BeforeAll {
    Import-Module PSSQLite
    Import-Module (Join-Path $PSScriptRoot '..\collector\IdentityCollector.psm1') -Force
    $script:Events = Join-Path $PSScriptRoot 'fixtures\events'

    # A fake EventLogRecord: only ToXml() and RecordId are used by the collector.
    function New-FakeEvent([string]$Id, [long]$RecordId) {
        $doc = [xml][IO.File]::ReadAllText((Join-Path $script:Events "$Id.xml"))
        $doc.Event['System']['EventRecordID'].InnerText = "$RecordId"
        $xml = $doc.OuterXml
        $o = [pscustomobject]@{ RecordId = $RecordId }
        $o | Add-Member -MemberType ScriptMethod -Name ToXml -Value ([scriptblock]::Create("@'`n$xml`n'@"))
        $o
    }

    # Leading comma: keep a one-row result as an array (PS 5.1 [pscustomobject] has no .Count).
    function Get-Rows([string]$Db, [string]$Query) { , @(Invoke-SqliteQuery -DataSource $Db -Query $Query) }
}

Describe 'Invoke-IdentityCollection' {
    BeforeEach {
        $script:Db = Join-Path $TestDrive "collect-$([guid]::NewGuid().ToString('N')).db"

        Mock -ModuleName IdentityCollector Get-LocalUser {
            [pscustomobject]@{ Name = 'jsmith'; SID = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
                Enabled = $true; LastLogon = [datetime]'2026-10-20T14:03:11Z'; PasswordLastSet = [datetime]'2026-01-01Z'
                PasswordExpires = $null; PasswordRequired = $true; Description = 'Analyst' }
            [pscustomobject]@{ Name = 'svc_backup'; SID = 'S-1-5-21-1111111111-2222222222-3333333333-1002'
                Enabled = $true; LastLogon = $null; PasswordLastSet = [datetime]'2024-03-01Z'
                PasswordExpires = $null; PasswordRequired = $false; Description = '' }
        }
        Mock -ModuleName IdentityCollector Get-UserFlags { if ($Name -eq 'svc_backup') { 0x10000 } else { 0x200 } }
        Mock -ModuleName IdentityCollector Get-LocalGroup {
            [pscustomobject]@{ Name = 'Administrators'; SID = 'S-1-5-32-544' }
            [pscustomobject]@{ Name = 'Users'; SID = 'S-1-5-32-545' }
        }
        Mock -ModuleName IdentityCollector Get-LocalGroupMember {
            [pscustomobject]@{ SID = 'S-1-5-18'; Name = 'NT AUTHORITY\SYSTEM'; PrincipalSource = 'Local' }
        }
        Mock -ModuleName IdentityCollector Get-EventLogRecordRange { [pscustomobject]@{ Oldest = 1; Newest = 90000 } }

        # The fake Security log; the mock honours -LastRecordId like the real XPath filter.
        $script:Log = @(
            New-FakeEvent 4624 101
            New-FakeEvent 4625 102
            New-FakeEvent 4740 103
            New-FakeEvent 4732 104
        )
        Mock -ModuleName IdentityCollector Get-SecurityEventSince {
            $script:Log | Where-Object { $_.RecordId -gt $LastRecordId }
        }
    }

    It 'loads snapshots and events and records a successful run' {
        $run = Invoke-IdentityCollection -Database $script:Db
        $run.status        | Should -Be 'success'
        $run.events_loaded | Should -Be 4
        $run.accounts      | Should -Be 2

        (Get-Rows $script:Db 'SELECT * FROM auth_event').Count     | Should -Be 2
        (Get-Rows $script:Db 'SELECT * FROM account_change').Count | Should -Be 2
        $svc = Get-Rows $script:Db "SELECT * FROM account_snapshot WHERE name = 'svc_backup'"
        $svc[0].pwd_never_expires | Should -Be 1
        $svc[0].pwd_required      | Should -Be 0
        $svc[0].description       | Should -BeNullOrEmpty
    }

    It 'loads only new events on the next run (incremental)' {
        Invoke-IdentityCollection -Database $script:Db | Out-Null
        $script:Log += New-FakeEvent 4625 105

        $run = Invoke-IdentityCollection -Database $script:Db
        $run.events_loaded      | Should -Be 1
        $run.last_record_before | Should -Be 104
        Should -Invoke -ModuleName IdentityCollector Get-SecurityEventSince -ParameterFilter { $LastRecordId -eq 104 }
        (Get-Rows $script:Db 'SELECT * FROM auth_event').Count | Should -Be 3
    }

    It 'does not duplicate rows when the same events are returned twice' {
        Invoke-IdentityCollection -Database $script:Db | Out-Null
        # Simulate an overlap: the source ignores the high-water mark and returns everything.
        Mock -ModuleName IdentityCollector Get-SecurityEventSince { $script:Log }

        $run = Invoke-IdentityCollection -Database $script:Db
        $run.events_loaded | Should -Be 0
        (Get-Rows $script:Db 'SELECT record_id FROM auth_event').Count     | Should -Be 2
        (Get-Rows $script:Db 'SELECT record_id FROM account_change').Count | Should -Be 2
        (Get-Rows $script:Db 'SELECT * FROM runs').Count                   | Should -Be 2
    }

    It 'keeps orphaned SIDs instead of crashing when Get-LocalGroupMember fails' {
        Mock -ModuleName IdentityCollector Get-LocalGroupMember {
            throw 'Failed to compare two elements in the array.'
        } -ParameterFilter { "$SID" -eq 'S-1-5-32-544' }
        Mock -ModuleName IdentityCollector Get-AdsiGroupMember {
            [pscustomobject]@{ Sid = 'S-1-5-18'; Name = 'SYSTEM'; Source = $null }
            [pscustomobject]@{ Sid = 'S-1-5-21-1111111111-2222222222-3333333333-1999'
                Name = 'S-1-5-21-1111111111-2222222222-3333333333-1999'; Source = $null }
        }

        $run = Invoke-IdentityCollection -Database $script:Db -WarningAction SilentlyContinue
        $run.status | Should -Be 'success'

        $orphan = Get-Rows $script:Db "SELECT * FROM group_membership WHERE member_source = 'Orphaned'"
        $orphan.Count           | Should -Be 1
        $orphan[0].group_name   | Should -Be 'Administrators'
        $orphan[0].member_name  | Should -BeNullOrEmpty
        (Get-Rows $script:Db "SELECT * FROM v_data_quality WHERE issue = 'orphaned_sid'").Count | Should -Be 1
    }

    It 'marks the run failed and drops its partial snapshot on error' {
        Mock -ModuleName IdentityCollector Get-SecurityEventSince { throw 'Access is denied' }

        { Invoke-IdentityCollection -Database $script:Db } | Should -Throw '*Access is denied*'
        $runs = Get-Rows $script:Db 'SELECT * FROM runs'
        $runs[0].status | Should -Be 'failed'
        $runs[0].error  | Should -BeLike '*Access is denied*'
        (Get-Rows $script:Db 'SELECT * FROM account_snapshot').Count | Should -Be 0
    }

    It 'flags a gap when the log rolled over between runs' {
        Invoke-IdentityCollection -Database $script:Db | Out-Null   # high-water 90000
        Mock -ModuleName IdentityCollector Get-EventLogRecordRange { [pscustomobject]@{ Oldest = 95000; Newest = 120000 } }

        $run = Invoke-IdentityCollection -Database $script:Db
        $run.status | Should -Be 'warning'
        $run.notes  | Should -BeLike '*rolled over*90001-94999*'
    }

    It 'reloads from the start of the log after a clear, without colliding with old record IDs' {
        Invoke-IdentityCollection -Database $script:Db | Out-Null   # records 101-104, high-water 90000
        Mock -ModuleName IdentityCollector Get-EventLogRecordRange { [pscustomobject]@{ Oldest = 1; Newest = 3 } }
        $script:Log = @(
            New-FakeEvent 1102 1
            New-FakeEvent 4624 2
            New-FakeEvent 4625 102   # same ID as a stored event from before the clear
        )

        $run = Invoke-IdentityCollection -Database $script:Db
        $run.status        | Should -Be 'warning'
        $run.notes         | Should -BeLike '*cleared*epoch 1*'
        $run.events_loaded | Should -Be 3
        $run.log_epoch     | Should -Be 1
        Should -Invoke -ModuleName IdentityCollector Get-SecurityEventSince -ParameterFilter { $LastRecordId -eq 0 }

        $r102 = Get-Rows $script:Db 'SELECT log_epoch FROM auth_event WHERE record_id = 102 ORDER BY log_epoch'
        $r102.log_epoch | Should -Be @(0, 1)
        # The 1102 "log cleared" event behind the red KRI is no longer skipped.
        (Get-Rows $script:Db 'SELECT * FROM account_change WHERE event_id = 1102').Count | Should -Be 1

        # The next run continues incrementally inside the new epoch.
        Mock -ModuleName IdentityCollector Get-EventLogRecordRange { [pscustomobject]@{ Oldest = 1; Newest = 4 } }
        $script:Log += New-FakeEvent 4624 103
        $next = Invoke-IdentityCollection -Database $script:Db
        $next.status             | Should -Be 'success'
        $next.events_loaded      | Should -Be 1
        $next.last_record_before | Should -Be 102
        $next.log_epoch          | Should -Be 1
    }

    It 'does not count the same clear twice when the run that detected it failed' {
        Invoke-IdentityCollection -Database $script:Db | Out-Null
        Mock -ModuleName IdentityCollector Get-EventLogRecordRange { [pscustomobject]@{ Oldest = 1; Newest = 3 } }
        $script:Log = @(New-FakeEvent 1102 1; New-FakeEvent 4624 2)
        Mock -ModuleName IdentityCollector Get-SecurityEventSince { throw 'Access is denied' }
        { Invoke-IdentityCollection -Database $script:Db } | Should -Throw

        Mock -ModuleName IdentityCollector Get-SecurityEventSince {
            $script:Log | Where-Object { $_.RecordId -gt $LastRecordId }
        }
        $run = Invoke-IdentityCollection -Database $script:Db
        $run.status        | Should -Be 'success'
        $run.log_epoch     | Should -Be 1
        $run.events_loaded | Should -Be 2
        Should -Invoke -ModuleName IdentityCollector Get-SecurityEventSince -ParameterFilter { $LastRecordId -eq 0 }
        (Get-Rows $script:Db 'SELECT DISTINCT log_epoch FROM auth_event ORDER BY log_epoch').log_epoch | Should -Be @(0, 1)
    }
}

Describe 'Initialize-IdentityDatabase migration' {
    It 'upgrades a database from before log_epoch without losing rows' {
        $db = Join-Path $TestDrive 'old-schema.db'
        Invoke-SqliteQuery -DataSource $db -Query @'
CREATE TABLE runs (run_id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, host TEXT,
  events_loaded INTEGER, accounts INTEGER, group_members INTEGER, last_record_before INTEGER,
  last_record_after INTEGER, status TEXT NOT NULL, notes TEXT, error TEXT);
CREATE TABLE auth_event (record_id INTEGER PRIMARY KEY, time_created TEXT NOT NULL, event_id INTEGER NOT NULL,
  target_user TEXT, target_sid TEXT, logon_type INTEGER, status_code TEXT, sub_status TEXT, source_ip TEXT,
  process_name TEXT, auth_package TEXT);
CREATE INDEX ix_auth_time ON auth_event(time_created);
CREATE TABLE account_change (record_id INTEGER PRIMARY KEY, time_created TEXT NOT NULL, event_id INTEGER NOT NULL,
  actor TEXT, target_user TEXT, target_sid TEXT, group_name TEXT, group_sid TEXT);
INSERT INTO runs (run_id, started_at, last_record_after, status) VALUES (1, '2026-10-24 02:00:00', 500, 'success');
INSERT INTO auth_event (record_id, time_created, event_id, target_user) VALUES
  (101, '2026-10-24 01:00:00', 4624, 'jsmith'), (102, '2026-10-24 01:05:00', 4625, 'jsmith');
INSERT INTO account_change (record_id, time_created, event_id, actor) VALUES (103, '2026-10-24 01:10:00', 4740, 'IDLAB-VM$');
'@

        $conn = New-SQLiteConnection -DataSource $db
        try { Initialize-IdentityDatabase -Connection $conn; Initialize-IdentityDatabase -Connection $conn }   # twice: idempotent
        finally { $conn.Close(); $conn.Dispose() }

        $auth = Get-Rows $db 'SELECT * FROM auth_event ORDER BY record_id'
        $auth.record_id   | Should -Be @(101, 102)
        $auth.log_epoch   | Should -Be @(0, 0)
        $auth[0].target_user | Should -Be 'jsmith'
        (Get-Rows $db 'SELECT * FROM account_change')[0].log_epoch | Should -Be 0
        (Get-Rows $db 'PRAGMA table_info(runs)').name | Should -Contain 'log_epoch'
        (Get-Rows $db "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'ix_auth_time'").Count | Should -Be 1
        (Get-Rows $db "SELECT name FROM sqlite_master WHERE name LIKE '%premigration%'").Count | Should -Be 0

        # The new key accepts the same record_id in a later epoch.
        Invoke-SqliteQuery -DataSource $db -Query "INSERT INTO auth_event (log_epoch, record_id, time_created, event_id) VALUES (1, 101, '2026-10-25 01:00:00', 4624)"
        (Get-Rows $db 'SELECT * FROM auth_event WHERE record_id = 101').Count | Should -Be 2
    }
}
