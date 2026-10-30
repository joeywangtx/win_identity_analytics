#Requires -Version 5.1
<#
    Functions behind collect.ps1. Kept in a module so Pester can test the parser and the
    load logic without admin rights or a real Security log (Windows calls are mocked).

    Works on Windows PowerShell 5.1 and PowerShell 7. Requires the PSSQLite module.
#>

Import-Module PSSQLite -ErrorAction Stop

$script:SqlDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'sql'

$script:AuthEventIds   = @(4624, 4625, 4648, 4672)
$script:ChangeEventIds = @(1102, 4720, 4722, 4723, 4724, 4725, 4726, 4732, 4733, 4738, 4740, 4767)

$script:AuthColumns   = 'log_epoch', 'record_id', 'time_created', 'event_id', 'target_user', 'target_sid',
                        'logon_type', 'status_code', 'sub_status', 'source_ip', 'process_name', 'auth_package'
$script:ChangeColumns = 'log_epoch', 'record_id', 'time_created', 'event_id', 'actor', 'target_user', 'target_sid',
                        'group_name', 'group_sid'
$script:AccountColumns = 'run_id', 'sid', 'name', 'enabled', 'last_logon', 'pwd_last_set',
                         'pwd_never_expires', 'pwd_required', 'description'
$script:MemberColumns  = 'run_id', 'group_name', 'group_sid', 'member_sid', 'member_name', 'member_source'

$ADS_UF_DONT_EXPIRE_PASSWD = 0x10000

# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------

function ConvertTo-NullableString {
    # Event fields use '-' (and sometimes the NULL SID) for "no value".
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq '-' -or $Value -eq 'S-1-0-0') { return $null }
    $Value.Trim()
}

function ConvertTo-NtStatus {
    # '0xc000006d' -> '0xC000006D', so codes match status_code_ref regardless of case.
    param([AllowNull()][string]$Value)
    $v = ConvertTo-NullableString $Value
    if ($null -eq $v) { return $null }
    if ($v -match '^0x([0-9a-fA-F]{1,8})$') { return '0x' + $Matches[1].ToUpperInvariant().PadLeft(8, '0') }
    $v
}

function ConvertTo-UtcText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        $Value = [datetime]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
    }
    $dt = [datetime]$Value
    if ($dt.Kind -ne [DateTimeKind]::Utc) { $dt = $dt.ToUniversalTime() }
    $dt.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-DbValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { [DBNull]::Value } else { $Value }
}

# ---------------------------------------------------------------------------
# Event parsing
# ---------------------------------------------------------------------------

function ConvertFrom-SecurityEventXml {
    <#
    .SYNOPSIS
        Parses one Security event (EventLogRecord.ToXml()) into a row for auth_event or
        account_change. Fields are read by their Name attribute, never by position, because
        the field order differs between Windows versions.
    .OUTPUTS
        PSCustomObject with a Table property ('auth_event' | 'account_change') plus the
        table's columns, or nothing for an event ID this collector doesn't store.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Xml)

    process {
        $doc = [xml]$Xml
        $sys = $doc.Event['System']
        $eventId  = [int]$sys['EventID'].InnerText
        $recordId = [long]$sys['EventRecordID'].InnerText
        $time     = ConvertTo-UtcText $sys['TimeCreated'].GetAttribute('SystemTime')

        $d = @{}
        $eventData = $doc.Event['EventData']
        if ($eventData) {
            foreach ($node in $eventData.ChildNodes) {
                if ($node.LocalName -eq 'Data') { $d[$node.GetAttribute('Name')] = $node.InnerText }
            }
        }
        # 1102 (log cleared) puts its fields under UserData/LogFileCleared instead.
        $userData = $doc.Event['UserData']
        if ($userData -and $userData.FirstChild) {
            foreach ($node in $userData.FirstChild.ChildNodes) { $d[$node.LocalName] = $node.InnerText }
        }
        $f = { param($name) ConvertTo-NullableString $d[$name] }

        if ($script:AuthEventIds -contains $eventId) {
            $row = [ordered]@{
                Table = 'auth_event'; record_id = $recordId; time_created = $time; event_id = $eventId
                target_user = $null; target_sid = $null; logon_type = $null; status_code = $null
                sub_status = $null; source_ip = $null; process_name = $null; auth_package = $null
            }
            if ($eventId -eq 4672) {
                # Special privileges: the account is the subject.
                $row.target_user = & $f 'SubjectUserName'
                $row.target_sid  = & $f 'SubjectUserSid'
            }
            else {
                $row.target_user  = & $f 'TargetUserName'
                $row.target_sid   = & $f 'TargetUserSid'
                $row.source_ip    = & $f 'IpAddress'
                $row.process_name = & $f 'ProcessName'
                $row.auth_package = & $f 'AuthenticationPackageName'
                $lt = & $f 'LogonType'
                if ($lt) { $row.logon_type = [int]$lt }
                if ($eventId -eq 4625) {
                    $row.status_code = ConvertTo-NtStatus $d['Status']
                    $row.sub_status  = ConvertTo-NtStatus $d['SubStatus']
                }
            }
            return [pscustomobject]$row
        }

        if ($script:ChangeEventIds -contains $eventId) {
            $row = [ordered]@{
                Table = 'account_change'; record_id = $recordId; time_created = $time; event_id = $eventId
                actor = & $f 'SubjectUserName'; target_user = $null; target_sid = $null
                group_name = $null; group_sid = $null
            }
            switch ($eventId) {
                { $_ -in 4732, 4733 } {
                    # Member added/removed: the group is the "target"; local members show MemberName '-'.
                    $row.target_user = & $f 'MemberName'
                    $row.target_sid  = & $f 'MemberSid'
                    $row.group_name  = & $f 'TargetUserName'
                    $row.group_sid   = & $f 'TargetSid'
                }
                1102 { }
                default {
                    $row.target_user = & $f 'TargetUserName'
                    $row.target_sid  = & $f 'TargetSid'
                }
            }
            return [pscustomobject]$row
        }

        Write-Verbose "Skipping event $eventId (record $recordId): not collected"
    }
}

# ---------------------------------------------------------------------------
# Windows data sources (wrapped so tests can mock them)
# ---------------------------------------------------------------------------

function Resolve-SidName {
    param([Parameter(Mandatory)][string]$Sid)
    try {
        (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate(
            [System.Security.Principal.NTAccount]).Value
    }
    catch { $null }
}

function Get-UserFlags {
    # ADSI userFlags is the authoritative source for "password never expires";
    # Get-LocalUser's PasswordExpires is also empty when the policy max age is unlimited.
    param([Parameter(Mandatory)][string]$Name)
    try { [int]([ADSI]"WinNT://$env:COMPUTERNAME/$Name,user").UserFlags.Value }
    catch { $null }
}

function Get-AdsiGroupMember {
    <#
        Fallback when Get-LocalGroupMember fails. It throws "Failed to compare two elements
        in the array" (5.1) or error 1789 when a group contains a SID that no longer resolves,
        which is exactly the case worth reporting. ADSI enumerates those members fine.
    #>
    param([Parameter(Mandatory)][string]$GroupName)
    $group = [ADSI]"WinNT://$env:COMPUTERNAME/$GroupName,group"
    foreach ($member in @($group.Invoke('Members'))) {
        $m = [ADSI]$member
        $sidBytes = $m.InvokeGet('objectSid')
        [pscustomobject]@{
            Sid    = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            Name   = $m.InvokeGet('Name')
            Source = $null
        }
    }
}

function Get-AccountSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][long]$RunId)

    foreach ($u in @(Get-LocalUser)) {
        $flags = Get-UserFlags -Name $u.Name
        $neverExpires = if ($null -ne $flags) { ($flags -band $ADS_UF_DONT_EXPIRE_PASSWD) -ne 0 }
                        else { $null -eq $u.PasswordExpires }
        [pscustomobject][ordered]@{
            run_id            = $RunId
            sid               = "$($u.SID)"
            name              = $u.Name
            enabled           = [int][bool]$u.Enabled
            last_logon        = ConvertTo-UtcText $u.LastLogon
            pwd_last_set      = ConvertTo-UtcText $u.PasswordLastSet
            pwd_never_expires = [int]$neverExpires
            pwd_required      = [int][bool]$u.PasswordRequired
            description       = ConvertTo-NullableString $u.Description
        }
    }
}

function Get-GroupSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][long]$RunId)

    foreach ($g in @(Get-LocalGroup)) {
        try {
            $members = @(Get-LocalGroupMember -SID $g.SID -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Sid = "$($_.SID)"; Name = $_.Name; Source = "$($_.PrincipalSource)" }
            })
        }
        catch {
            Write-Warning "Get-LocalGroupMember failed for '$($g.Name)' ($($_.Exception.Message)); using ADSI"
            $members = @(Get-AdsiGroupMember -GroupName $g.Name)
        }

        foreach ($m in $members) {
            # An unresolvable SID is a data-quality finding, not an error: keep the row.
            $name = Resolve-SidName -Sid $m.Sid
            if (-not $name -and $m.Name -and $m.Name -notmatch '^S-1-') { $name = $m.Name }
            $source = if (-not $name) { 'Orphaned' } elseif ($m.Source) { $m.Source } else { 'Unknown' }
            [pscustomobject][ordered]@{
                run_id        = $RunId
                group_name    = $g.Name
                group_sid     = "$($g.SID)"
                member_sid    = $m.Sid
                member_name   = $name
                member_source = $source
            }
        }
    }
}

function Get-SecurityEventSince {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][long]$LastRecordId,
        [string]$LogName = 'Security'
    )
    $ids = (@($script:AuthEventIds) + @($script:ChangeEventIds) | ForEach-Object { "EventID=$_" }) -join ' or '
    $xpath = "*[System[($ids) and EventRecordID > $LastRecordId]]"
    try {
        Get-WinEvent -LogName $LogName -FilterXPath $xpath -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return }
        throw
    }
}

function Get-EventLogRecordRange {
    # Oldest and newest EventRecordID currently in the log, for rollover/clear detection.
    param([string]$LogName = 'Security')
    $newest = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction SilentlyContinue
    $oldest = Get-WinEvent -LogName $LogName -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Oldest = if ($oldest) { [long]$oldest.RecordId } else { $null }
        Newest = if ($newest) { [long]$newest.RecordId } else { $null }
    }
}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

function New-RowTable {
    # Builds a DataTable with exactly the table's columns for Invoke-SQLiteBulkCopy.
    param(
        [Parameter(Mandatory)][string[]]$Columns,
        [AllowEmptyCollection()][object[]]$Rows = @()
    )
    $dt = New-Object System.Data.DataTable
    foreach ($c in $Columns) { [void]$dt.Columns.Add($c, [object]) }
    foreach ($r in $Rows) {
        $dr = $dt.NewRow()
        foreach ($c in $Columns) { $dr[$c] = ConvertTo-DbValue $r.$c }
        $dt.Rows.Add($dr)
    }
    , $dt
}

function Invoke-SqlFile {
    param(
        [Parameter(Mandatory)]$Connection,
        [Parameter(Mandatory)][string]$Path
    )
    $sql = [IO.File]::ReadAllText((Resolve-Path $Path))
    Invoke-SqliteQuery -SQLiteConnection $Connection -Query $sql | Out-Null
}

function Update-IdentitySchema {
    # Upgrades a database created before log_epoch existed: adds runs.log_epoch, and rebuilds
    # auth_event / account_change with the (log_epoch, record_id) key, keeping every row as
    # epoch 0. One transaction, so a failure leaves the old tables untouched. The data is
    # copied rather than renamed because RENAME rewrites view references on newer SQLite.
    param(
        [Parameter(Mandatory)]$Connection,
        [string]$SqlPath = $script:SqlDir
    )
    $columnsOf = {
        param([string]$Table)
        @(Invoke-SqliteQuery -SQLiteConnection $Connection -Query "PRAGMA table_info($Table)" | ForEach-Object name)
    }
    $addRunEpoch = (& $columnsOf 'runs') -notcontains 'log_epoch'
    $rebuild = @('auth_event', 'account_change' | Where-Object { (& $columnsOf $_) -notcontains 'log_epoch' })
    if (-not $addRunEpoch -and -not $rebuild.Count) { return }

    $sql = New-Object System.Text.StringBuilder
    [void]$sql.AppendLine('BEGIN;')
    if ($addRunEpoch) { [void]$sql.AppendLine('ALTER TABLE runs ADD COLUMN log_epoch INTEGER;') }
    $copies = @{}
    foreach ($t in $rebuild) {
        $copies[$t] = (& $columnsOf $t) -join ', '
        [void]$sql.AppendLine("CREATE TABLE ${t}_premigration AS SELECT * FROM $t; DROP TABLE $t;")
    }
    # Recreates the dropped tables and their indexes with the current definitions.
    [void]$sql.AppendLine([IO.File]::ReadAllText((Resolve-Path (Join-Path $SqlPath 'schema.sql'))))
    foreach ($t in $rebuild) {
        [void]$sql.AppendLine("INSERT INTO $t ($($copies[$t])) SELECT $($copies[$t]) FROM ${t}_premigration;")
        [void]$sql.AppendLine("DROP TABLE ${t}_premigration;")
    }
    [void]$sql.AppendLine('COMMIT;')

    try { Invoke-SqliteQuery -SQLiteConnection $Connection -Query $sql.ToString() | Out-Null }
    catch {
        try { Invoke-SqliteQuery -SQLiteConnection $Connection -Query 'ROLLBACK;' | Out-Null } catch { }
        throw
    }
}

function Initialize-IdentityDatabase {
    # Applies schema + views. All statements are idempotent, so this runs on every collection.
    param(
        [Parameter(Mandatory)]$Connection,
        [string]$SqlPath = $script:SqlDir
    )
    Invoke-SqlFile -Connection $Connection -Path (Join-Path $SqlPath 'schema.sql')
    Update-IdentitySchema -Connection $Connection -SqlPath $SqlPath
    foreach ($file in 'views_local.sql', 'kri_summary.sql') {
        Invoke-SqlFile -Connection $Connection -Path (Join-Path $SqlPath $file)
    }
}

function Get-ScalarValue {
    param($Connection, [string]$Query, [hashtable]$Parameters = @{})
    $v = Invoke-SqliteQuery -SQLiteConnection $Connection -Query $Query -SqlParameters $Parameters -As SingleValue
    if ($v -is [DBNull]) { $null } else { $v }
}

function Invoke-IdentityCollection {
    <#
    .SYNOPSIS
        One collector run: account + group snapshots and an incremental Security-log load.
    .DESCRIPTION
        Incremental load: only events with EventRecordID above the highest one already stored
        in the current log epoch are read. (log_epoch, record_id) is the primary key and rows
        are inserted with OR IGNORE, so a rerun (or an overlap) never duplicates rows. When the
        log is cleared or reset, IDs restart low: the epoch goes up and the log is read from
        the start. Every value goes in through parameters.
    .OUTPUTS
        The finished runs row.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Database,
        [string]$LogName = 'Security',
        [string]$SqlPath = $script:SqlDir
    )

    $dbDir = Split-Path -Parent ([IO.Path]::GetFullPath($Database))
    if (-not (Test-Path $dbDir)) { New-Item -ItemType Directory -Path $dbDir -Force | Out-Null }

    $conn = New-SQLiteConnection -DataSource $Database
    try {
        Initialize-IdentityDatabase -Connection $conn -SqlPath $SqlPath

        Invoke-SqliteQuery -SQLiteConnection $conn -Query @'
INSERT INTO runs (started_at, host, status) VALUES (@started, @host, 'running')
'@ -SqlParameters @{ started = (ConvertTo-UtcText (Get-Date)); host = $env:COMPUTERNAME }
        $runId = Get-ScalarValue $conn 'SELECT last_insert_rowid()'

        try {
            $notes = New-Object System.Collections.Generic.List[string]

            # Snapshots ---------------------------------------------------------
            $accounts = @(Get-AccountSnapshot -RunId $runId)
            Invoke-SQLiteBulkCopy -SQLiteConnection $conn -Table account_snapshot -Force `
                -DataTable (New-RowTable -Columns $script:AccountColumns -Rows $accounts)

            $members = @(Get-GroupSnapshot -RunId $runId)
            Invoke-SQLiteBulkCopy -SQLiteConnection $conn -Table group_membership -Force `
                -DataTable (New-RowTable -Columns $script:MemberColumns -Rows $members)

            # Incremental events ------------------------------------------------
            # Current log epoch: the highest seen on any earlier run (failed ones included,
            # since their events are kept) or on any stored event.
            $epoch = Get-ScalarValue $conn @'
SELECT MAX(e) FROM (SELECT MAX(COALESCE(log_epoch, 0)) AS e FROM runs WHERE run_id < @run
                    UNION ALL SELECT MAX(log_epoch) FROM auth_event
                    UNION ALL SELECT MAX(log_epoch) FROM account_change)
'@ @{ run = $runId }
            if ($null -eq $epoch) { $epoch = 0 }

            # High-water mark of the whole log at the previous good run in this epoch (not
            # only the events we keep), so a rollover gap or a reset can be detected precisely.
            $prevHigh = Get-ScalarValue $conn @'
SELECT last_record_after FROM runs
WHERE run_id < @run AND status IN ('success', 'warning') AND COALESCE(log_epoch, 0) = @epoch
ORDER BY run_id DESC LIMIT 1
'@ @{ run = $runId; epoch = $epoch }

            $range = Get-EventLogRecordRange -LogName $LogName
            $reset = $null -ne $prevHigh -and $null -ne $range.Newest -and $range.Newest -lt $prevHigh
            if ($reset) {
                # Record IDs restarted: read the new log from the start under a new epoch,
                # so new events neither get skipped nor collide with stored IDs.
                $epoch++
                $notes.Add("Log newest record $($range.Newest) < previous high-water $prevHigh; log was cleared or reset. Reloading from the start as log epoch $epoch")
            }
            elseif ($null -ne $prevHigh -and $null -ne $range.Oldest -and $range.Oldest -gt $prevHigh + 1) {
                $notes.Add("Log rolled over: records $($prevHigh + 1)-$($range.Oldest - 1) were lost before this run")
            }

            # Saved before loading, so a run that fails mid-load still pins the epoch of
            # the events it kept and the next run doesn't count the same reset twice.
            Invoke-SqliteQuery -SQLiteConnection $conn -Query 'UPDATE runs SET log_epoch = @epoch WHERE run_id = @run' `
                -SqlParameters @{ epoch = $epoch; run = $runId }

            $last = 0
            if (-not $reset) {
                $last = Get-ScalarValue $conn @'
SELECT MAX(r) FROM (SELECT MAX(record_id) AS r FROM auth_event WHERE log_epoch = @epoch
                    UNION ALL SELECT MAX(record_id) FROM account_change WHERE log_epoch = @epoch)
'@ @{ epoch = $epoch }
                if ($null -eq $last) { $last = 0 }
            }

            $parsed = @(Get-SecurityEventSince -LastRecordId $last -LogName $LogName |
                ForEach-Object { ConvertFrom-SecurityEventXml -Xml $_.ToXml() })
            foreach ($p in $parsed) { $p | Add-Member -NotePropertyName log_epoch -NotePropertyValue $epoch -Force }
            $auth   = @($parsed | Where-Object { $_.Table -eq 'auth_event' })
            $change = @($parsed | Where-Object { $_.Table -eq 'account_change' })

            $countSql = 'SELECT (SELECT COUNT(*) FROM auth_event) + (SELECT COUNT(*) FROM account_change)'
            $before = Get-ScalarValue $conn $countSql
            Invoke-SQLiteBulkCopy -SQLiteConnection $conn -Table auth_event -ConflictClause Ignore -Force `
                -DataTable (New-RowTable -Columns $script:AuthColumns -Rows $auth)
            Invoke-SQLiteBulkCopy -SQLiteConnection $conn -Table account_change -ConflictClause Ignore -Force `
                -DataTable (New-RowTable -Columns $script:ChangeColumns -Rows $change)
            $loaded = (Get-ScalarValue $conn $countSql) - $before

            $high = $range.Newest
            if ($null -eq $high -and $parsed.Count) { $high = ($parsed | Measure-Object record_id -Maximum).Maximum }
            if ($null -eq $high) { $high = $last }

            Invoke-SqliteQuery -SQLiteConnection $conn -Query @'
UPDATE runs
SET finished_at = @finished, events_loaded = @loaded, accounts = @accounts, group_members = @members,
    last_record_before = @before, last_record_after = @after, status = @status, notes = @notes
WHERE run_id = @run
'@ -SqlParameters @{
                finished = (ConvertTo-UtcText (Get-Date)); loaded = $loaded
                accounts = $accounts.Count; members = $members.Count
                before = $last; after = $high
                status = $(if ($notes.Count) { 'warning' } else { 'success' })
                notes = $(if ($notes.Count) { $notes -join '; ' } else { [DBNull]::Value })
                run = $runId
            }
        }
        catch {
            $err = $_
            # Snapshot rows from a failed run would be half-written; drop them. Events are
            # committed per table in one transaction and are safe to keep (and to re-load).
            Invoke-SqliteQuery -SQLiteConnection $conn -Query @'
DELETE FROM account_snapshot WHERE run_id = @run;
DELETE FROM group_membership WHERE run_id = @run;
UPDATE runs SET finished_at = @finished, status = 'failed', error = @error WHERE run_id = @run;
'@ -SqlParameters @{ run = $runId; finished = (ConvertTo-UtcText (Get-Date)); error = "$err" }
            throw $err
        }

        Invoke-SqliteQuery -SQLiteConnection $conn -Query 'SELECT * FROM runs WHERE run_id = @run' `
            -SqlParameters @{ run = $runId }
    }
    finally {
        $conn.Close()
        $conn.Dispose()
    }
}

Export-ModuleMember -Function ConvertFrom-SecurityEventXml, ConvertTo-NtStatus, ConvertTo-UtcText,
    Resolve-SidName, Get-UserFlags, Get-AdsiGroupMember, Get-AccountSnapshot, Get-GroupSnapshot,
    Get-SecurityEventSince, Get-EventLogRecordRange, New-RowTable, Invoke-SqlFile,
    Initialize-IdentityDatabase, Invoke-IdentityCollection
