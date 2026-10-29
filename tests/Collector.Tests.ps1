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
}
