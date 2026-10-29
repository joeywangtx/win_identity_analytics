#Requires -Version 5.1
<#
.SYNOPSIS
    Builds sample/sample.db: a fully synthetic database (no real VM or LANL data) so anyone
    can run the views, KRIs and dashboard without a lab or the LANL download.

.DESCRIPTION
    Local part: 21 daily collector runs (one failed, as happens in real life) for a lab with
    a dozen accounts, with the same staged story as Generate-Activity.ps1: daily logons,
    dormant accounts, a temporary admin, lockouts, a deleted account left as an orphaned SID.

    LANL part: a synthetic auth.txt.gz / redteam.txt.gz in the real LANL format, pushed
    through lanl/Import-LanlSlice.ps1 so the sample exercises the actual pipeline. It has
    300 users, a red team of 6 compromised users moving laterally from one host, and decoys
    (admins with naturally high fan-out, users starting on new servers) so the detection
    numbers show a real precision/recall trade-off.

    Deterministic: the same -Seed always produces the same database.
#>
[CmdletBinding()]
param(
    [string]$Database = (Join-Path $PSScriptRoot 'sample.db'),
    [int]$Seed = 42
)

$ErrorActionPreference = 'Stop'
Import-Module PSSQLite
Import-Module (Join-Path $PSScriptRoot '..\collector\IdentityCollector.psm1') -Force

$rng = New-Object System.Random($Seed)
function Rand([int]$Max) { $rng.Next($Max) }
function Pick([object[]]$Items) { $Items[$rng.Next($Items.Count)] }
function Fmt([datetime]$T) { $T.ToString('yyyy-MM-dd HH:mm:ss') }

if (Test-Path $Database) { Remove-Item $Database }

# ===========================================================================
# Part 1: local collector data
# ===========================================================================

$machine = 'S-1-5-21-4000000001-4000000002-4000000003'
$hostName = 'IDLAB-VM'
$day0 = [datetime]::SpecifyKind([datetime]'2026-10-01', 'Utc')
$days = 21

# name, rid, role, description, pwd_last_set, never_expires, pwd_required, enabled
$accounts = @(
    @{ n = 'Administrator';      rid = 500;  role = 'builtin';    d = 'Built-in account for administering the computer'; pls = '2026-06-01'; ne = 1; pr = 1; en = 0 }
    @{ n = 'Guest';              rid = 501;  role = 'builtin';    d = 'Built-in account for guest access';               pls = $null;        ne = 1; pr = 0; en = 0 }
    @{ n = 'DefaultAccount';     rid = 503;  role = 'builtin';    d = 'A user account managed by the system.';           pls = $null;        ne = 1; pr = 0; en = 0 }
    @{ n = 'labadmin';           rid = 1000; role = 'admin';      d = 'Lab owner';                                        pls = '2026-06-01'; ne = 0; pr = 1; en = 1 }
    @{ n = 'jsmith';             rid = 1001; role = 'regular';    d = 'Analyst';                                          pls = '2026-08-20'; ne = 0; pr = 1; en = 1 }
    @{ n = 'mjones';             rid = 1002; role = 'regular';    d = 'Analyst';                                          pls = '2026-07-02'; ne = 0; pr = 1; en = 1 }
    @{ n = 'akim';               rid = 1003; role = 'regular';    d = 'Engineer';                                         pls = '2026-09-15'; ne = 0; pr = 1; en = 1 }
    @{ n = 'helpdesk_tom';       rid = 1004; role = 'regular';    d = 'Help desk; temporary admin rights';                pls = '2026-09-01'; ne = 0; pr = 1; en = 1 }
    @{ n = 'svc_backup';         rid = 1005; role = 'service';    d = 'Backup service account';                           pls = '2025-11-10'; ne = 1; pr = 1; en = 1 }
    @{ n = 'svc_report';         rid = 1006; role = 'service';    d = $null;                                              pls = '2026-04-01'; ne = 0; pr = 1; en = 1 }
    @{ n = 'temp_contractor';    rid = 1007; role = 'occasional'; d = 'Contractor';                                       pls = '2026-09-25'; ne = 0; pr = 0; en = 1 }
    @{ n = 'old_pwd_carl';       rid = 1008; role = 'occasional'; d = 'Password never rotated';                           pls = '2025-03-01'; ne = 0; pr = 1; en = 1 }
    @{ n = 'dormant_alice';      rid = 1009; role = 'dormant';    d = 'Unused account';                                   pls = '2026-05-01'; ne = 0; pr = 1; en = 1 }
    @{ n = 'dormant_bob';        rid = 1010; role = 'dormant';    d = 'Unused account';                                   pls = '2026-05-01'; ne = 0; pr = 1; en = 1 }
)
foreach ($a in $accounts) { $a.sid = "$machine-$($a.rid)"; $a.last = $null }
$byName = @{}; foreach ($a in $accounts) { $byName[$a.n] = $a }

$groups = @{
    Administrators         = @{ sid = 'S-1-5-32-544'; members = [System.Collections.ArrayList]@('Administrator', 'labadmin', 'dormant_alice') }
    'Backup Operators'     = @{ sid = 'S-1-5-32-551'; members = [System.Collections.ArrayList]@('svc_backup', 'dormant_bob') }
    'Remote Desktop Users' = @{ sid = 'S-1-5-32-555'; members = [System.Collections.ArrayList]@('jsmith') }
    Users                  = @{ sid = 'S-1-5-32-545'; members = [System.Collections.ArrayList]@('labadmin', 'jsmith', 'mjones', 'akim', 'helpdesk_tom', 'svc_backup', 'svc_report', 'temp_contractor', 'old_pwd_carl', 'dormant_alice', 'dormant_bob') }
    Guests                 = @{ sid = 'S-1-5-32-546'; members = [System.Collections.ArrayList]@('Guest') }
}

$runs = New-Object System.Collections.Generic.List[object]
$snapshots = New-Object System.Collections.Generic.List[object]
$members = New-Object System.Collections.Generic.List[object]
$authRows = New-Object System.Collections.Generic.List[object]
$changeRows = New-Object System.Collections.Generic.List[object]
$script:rec = 50000
$deleted = @{}   # name -> sid of accounts deleted during the period

function Add-Auth($T, $EventId, $Acct, $LogonType, $Status = $null, $Sub = $null, $Ip = '127.0.0.1', $Pkg = 'Negotiate') {
    $script:rec += 1 + (Rand 40)   # other event IDs interleave in the real log
    $sid = if ($EventId -eq 4625) { $null } else { $Acct.sid }
    $authRows.Add([pscustomobject]@{ record_id = $script:rec; time_created = (Fmt $T); event_id = $EventId
        target_user = $Acct.n; target_sid = $sid; logon_type = $LogonType; status_code = $Status
        sub_status = $Sub; source_ip = $Ip; process_name = 'C:\Windows\System32\svchost.exe'; auth_package = $Pkg })
}
function Add-Change($T, $EventId, $Actor, $Acct, $Group = $null) {
    $script:rec += 1 + (Rand 40)
    $changeRows.Add([pscustomobject]@{ record_id = $script:rec; time_created = (Fmt $T); event_id = $EventId
        actor = $Actor; target_user = $(if ($Group) { $null } else { $Acct.n }); target_sid = $Acct.sid
        group_name = $(if ($Group) { $Group } else { $null }); group_sid = $(if ($Group) { $groups[$Group].sid } else { $null }) })
}

# Account created before the window, for lifecycle history.
Add-Change ($day0.AddHours(-30)) 4720 'labadmin' $byName['temp_contractor']

for ($d = 0; $d -lt $days; $d++) {
    $day = $day0.AddDays($d)

    # --- the day's activity (between runs) ------------------------------------
    foreach ($a in $accounts) {
        if ($deleted.ContainsKey($a.n) -or -not $a.en) { continue }
        $logons = switch ($a.role) {
            'admin'      { 1 + (Rand 2) }
            'regular'    { if ($day.DayOfWeek -in 'Saturday', 'Sunday') { Rand 2 } else { 1 + (Rand 3) } }
            'service'    { 6 }
            'occasional' { if ((Rand 5) -eq 0) { 1 } else { 0 } }
            default      { 0 }
        }
        for ($i = 0; $i -lt $logons; $i++) {
            $t = $day.AddHours(7 + (Rand 11)).AddMinutes((Rand 60))
            $type = if ($a.role -eq 'service') { 5 } elseif ($a.n -eq 'jsmith' -and (Rand 3) -eq 0) { 10 } else { 2 }
            Add-Auth $t 4624 $a $type
            if ($a.role -eq 'admin') { Add-Auth $t.AddSeconds(1) 4672 $a $null }
            $a.last = $t
        }
    }
    # Typos: a few failures for regular users.
    for ($i = 0; $i -lt (Rand 4); $i++) {
        $a = $byName[(Pick @('jsmith', 'mjones', 'akim', 'helpdesk_tom'))]
        Add-Auth ($day.AddHours(8 + (Rand 9)).AddMinutes((Rand 60))) 4625 $a 2 '0xC000006D' '0xC000006A'
    }
    # Background noise: password spraying for a name that doesn't exist.
    if ($d % 3 -eq 1) {
        for ($i = 0; $i -lt 4; $i++) {
            Add-Auth ($day.AddHours(3).AddMinutes($i)) 4625 @{ n = 'admin'; sid = $null } 3 '0xC000006D' '0xC0000064' '192.168.56.50' 'NTLM'
        }
    }

    # --- the staged story ---------------------------------------------------
    switch ($d) {
        4  { # temporary admin for the help desk
            Add-Change $day.AddHours(10) 4732 'labadmin' $byName['helpdesk_tom'] 'Administrators'
            [void]$groups.Administrators.members.Add('helpdesk_tom') }
        11 { Add-Change $day.AddHours(10) 4733 'labadmin' $byName['helpdesk_tom'] 'Administrators'
            $groups.Administrators.members.Remove('helpdesk_tom') }
        { $_ -in 6, 17 } { # lockouts: 5 bad passwords over the network, then 4740
            $t = $day.AddHours(14)
            for ($i = 0; $i -lt 5; $i++) { Add-Auth $t.AddSeconds(40 * $i) 4625 $byName['temp_contractor'] 3 '0xC000006D' '0xC000006A' '192.168.56.20' 'NTLM' }
            Add-Change $t.AddSeconds(165) 4740 "$hostName`$" $byName['temp_contractor']
            Add-Auth $t.AddSeconds(200) 4625 $byName['temp_contractor'] 3 '0xC0000234' '0x00000000' '192.168.56.20' 'NTLM'
            if ($d -eq 6) { Add-Change $t.AddMinutes(30) 4767 'labadmin' $byName['temp_contractor'] } }
        13 { Add-Change $day.AddHours(9) 4725 'labadmin' $byName['mjones']; $byName['mjones'].en = 0 }
        14 { # deleted while still in Backup Operators -> orphaned SID left behind there
            Add-Change $day.AddHours(9) 4726 'labadmin' $byName['dormant_bob']
            $groups.Users.members.Remove('dormant_bob')
            $deleted['dormant_bob'] = $byName['dormant_bob'].sid }
        19 { Add-Change $day.AddHours(16) 4738 'labadmin' $byName['svc_report'] }
    }

    # --- the run at 02:00 the next morning ---------------------------------------
    $runId = $d + 1
    $started = $day.AddDays(1).AddHours(2)
    if ($d -eq 8) {
        $runs.Add([pscustomobject]@{ run_id = $runId; started_at = (Fmt $started); finished_at = (Fmt $started.AddSeconds(2))
            host = $hostName; events_loaded = $null; accounts = $null; group_members = $null
            last_record_before = $null; last_record_after = $null; status = 'failed'; notes = $null
            error = 'Get-WinEvent : The RPC server is unavailable (VM suspended during the run)' })
        continue
    }
    $live = @($accounts | Where-Object { -not $deleted.ContainsKey($_.n) })
    foreach ($a in $live) {
        $snapshots.Add([pscustomobject]@{ run_id = $runId; sid = $a.sid; name = $a.n; enabled = $a.en
            last_logon = $(if ($a.last) { Fmt $a.last }); pwd_last_set = $(if ($a.pls) { "$($a.pls) 09:00:00" })
            pwd_never_expires = $a.ne; pwd_required = $a.pr; description = $a.d })
    }
    foreach ($g in $groups.Keys) {
        foreach ($m in $groups[$g].members) {
            $orphan = $deleted.ContainsKey($m)
            $members.Add([pscustomobject]@{ run_id = $runId; group_name = $g; group_sid = $groups[$g].sid
                member_sid = $byName[$m].sid; member_name = $(if (-not $orphan) { "$hostName\$m" })
                member_source = $(if ($orphan) { 'Orphaned' } else { 'Local' }) })
        }
    }
    $loadedToday = @($authRows | Where-Object { $_.time_created -lt (Fmt $started) }).Count +
                   @($changeRows | Where-Object { $_.time_created -lt (Fmt $started) }).Count
    $runs.Add([pscustomobject]@{ run_id = $runId; started_at = (Fmt $started); finished_at = (Fmt $started.AddSeconds(3 + (Rand 5)))
        host = $hostName; events_loaded = $loadedToday; accounts = $live.Count; group_members = 0
        last_record_before = $null; last_record_after = $script:rec; status = 'success'; notes = $null; error = $null })
}
# events_loaded above is cumulative; turn it into per-run deltas.
$prev = 0
foreach ($r in $runs) { if ($r.status -eq 'success') { $c = $r.events_loaded; $r.events_loaded = $c - $prev; $prev = $c
    $r.group_members = @($members | Where-Object run_id -eq $r.run_id).Count } }

$conn = New-SQLiteConnection -DataSource $Database
try {
    Initialize-IdentityDatabase -Connection $conn
    $load = @{
        runs             = 'run_id', 'started_at', 'finished_at', 'host', 'events_loaded', 'accounts', 'group_members',
                           'last_record_before', 'last_record_after', 'status', 'notes', 'error'
        account_snapshot = 'run_id', 'sid', 'name', 'enabled', 'last_logon', 'pwd_last_set', 'pwd_never_expires', 'pwd_required', 'description'
        group_membership = 'run_id', 'group_name', 'group_sid', 'member_sid', 'member_name', 'member_source'
        auth_event       = 'record_id', 'time_created', 'event_id', 'target_user', 'target_sid', 'logon_type', 'status_code',
                           'sub_status', 'source_ip', 'process_name', 'auth_package'
        account_change   = 'record_id', 'time_created', 'event_id', 'actor', 'target_user', 'target_sid', 'group_name', 'group_sid'
    }
    $data = @{ runs = $runs; account_snapshot = $snapshots; group_membership = $members; auth_event = $authRows; account_change = $changeRows }
    foreach ($t in $load.Keys) {
        Invoke-SQLiteBulkCopy -SQLiteConnection $conn -Table $t -Force -DataTable (New-RowTable -Columns $load[$t] -Rows $data[$t])
    }
}
finally { $conn.Close(); $conn.Dispose() }
Write-Host "Local: $($runs.Count) runs, $($authRows.Count) auth events, $($changeRows.Count) account changes"

# ===========================================================================
# Part 2: synthetic LANL slice (baseline = day 1, detection = day 2)
# ===========================================================================

$users = 1..300 | ForEach-Object { 'U{0}@DOM1' -f (100 + $_ * 7) }
$profiles = @{}
foreach ($u in $users) {
    $profiles[$u] = @{
        home    = 'C{0}' -f (1000 + (Rand 400))
        servers = @(1..(2 + (Rand 4)) | ForEach-Object { Pick @('C586', 'C625', 'C529', 'C467', 'C457', 'C1065', 'C2106', 'C612', 'C528', 'C1085') })
        ntlm    = (Rand 10) -eq 0      # ~10% of users still on NTLM
        perDay  = 10 + (Rand 40)
    }
}
$admins  = $users[0..7]        # high fan-out every day: a false-positive trap for fan_out
$movers  = $users[8..19]       # start on new servers in the detection window: benign new pairs
$service = $users[20..24]      # active around the clock
$stale   = $users[25..31]      # stale saved password: bursts of failures, a trap for failures
$redTeam = $users[40, 77, 102, 150, 201, 260]
$attackHost = 'C17693'

$events = New-Object System.Collections.Generic.List[object]
function Add-Lanl([long]$T, [string]$U, [string]$Src, [string]$Dst, [string]$Auth, [string]$Type, [string]$Orient = 'LogOn', [string]$Result = 'Success') {
    $events.Add([pscustomobject]@{ t = $T; line = "$T,$U,$U,$Src,$Dst,$Auth,$Type,$Orient,$Result" })
}

# A few day-0 lines so the importer's "skip before window" path is exercised.
for ($i = 0; $i -lt 50; $i++) { $u = Pick $users; Add-Lanl (80000 + $i) $u $profiles[$u].home (Pick $profiles[$u].servers) 'Kerberos' 'Network' }

foreach ($dayIdx in 1, 2) {
    $base = [long]$dayIdx * 86400
    foreach ($u in $users) {
        $p = $profiles[$u]
        $n = $p.perDay
        if ($service -contains $u) { $n = 48 }
        for ($i = 0; $i -lt $n; $i++) {
            $t = if ($service -contains $u) { $base + $i * 1800 + (Rand 600) } else { $base + 28800 + (Rand 36000) }
            $dst = if ((Rand 4) -eq 0) { $p.home } else { Pick $p.servers }
            $auth = if ($p.ntlm -and (Rand 3) -gt 0) { 'NTLM' } else { 'Kerberos' }
            $type = if ($dst -eq $p.home -and (Rand 3) -eq 0 -and $service -notcontains $u) { 'Interactive' } else { 'Network' }
            $result = if ((Rand 60) -eq 0) { 'Fail' } else { 'Success' }
            Add-Lanl $t $u $p.home $dst $auth $type 'LogOn' $result
            if ((Rand 2) -eq 0) { Add-Lanl ($t + 600) $u $p.home $dst $auth $type 'LogOff' }
            if ((Rand 3) -eq 0) { Add-Lanl $t $u $p.home 'C529' 'Kerberos' '?' 'TGS' }
        }
        if ($stale -contains $u) {   # a mapped drive or scheduled job with an old password
            $t0 = $base + 30000 + (Rand 30000)
            foreach ($k in 1..(8 + (Rand 20))) { Add-Lanl ($t0 + $k * 30) $u $p.home (Pick $p.servers) 'NTLM' 'Network' 'LogOn' 'Fail' }
        }
        if ($admins -contains $u) {
            foreach ($k in 1..(15 + (Rand 10))) { Add-Lanl ($base + 30000 + (Rand 30000)) $u $p.home ('C{0}' -f (3000 + $k)) 'Kerberos' 'Network' }
        }
        if ($dayIdx -eq 2 -and $movers -contains $u) {
            foreach ($k in 1..(2 + (Rand 5))) { Add-Lanl ($base + 30000 + (Rand 30000)) $u $p.home ('C{0}' -f (5000 + (Rand 50))) 'Kerberos' 'Network' }
        }
        # Service accounts sometimes log on interactively (the thing to flag).
        if ($dayIdx -eq 2 -and $u -eq $service[0]) { Add-Lanl ($base + 50000) $u $p.home $p.home 'Kerberos' 'Interactive' }
    }
    # Computer accounts and ANONYMOUS LOGON noise.
    for ($i = 0; $i -lt 400; $i++) {
        $c = 'C{0}' -f (1000 + (Rand 400))
        Add-Lanl ($base + (Rand 86400)) "$c`$@DOM1" $c (Pick @('C586', 'C625', 'C529')) 'Kerberos' 'Network'
    }
    for ($i = 0; $i -lt 120; $i++) {
        $src = 'C{0}' -f (1000 + (Rand 400))
        Add-Lanl ($base + (Rand 86400)) 'ANONYMOUS LOGON@C586' $src 'C586' 'NTLM' 'Network'
    }
}

# Red team, detection day: lateral movement from one host to many new computers.
$rtLines = New-Object System.Collections.Generic.List[object]
foreach ($u in $redTeam) {
    $targets = 1..(8 + (Rand 12)) | ForEach-Object { 'C{0}' -f (7000 + (Rand 300)) } | Select-Object -Unique
    foreach ($dst in $targets) {
        $t = 2 * 86400 + 40000 + (Rand 30000)
        $auth = Pick @('NTLM', 'Kerberos', 'NTLM')
        if ((Rand 8) -eq 0) { Add-Lanl ($t - 5) $u $attackHost $dst $auth 'Network' 'LogOn' 'Fail' }
        Add-Lanl $t $u $attackHost $dst $auth 'Network'
        $rtLines.Add([pscustomobject]@{ t = $t; line = "$t,$u,$attackHost,$dst" })
    }
}
# Data continues past the window, like the real file, so the importer stops early.
for ($i = 0; $i -lt 20; $i++) { $u = Pick $users; Add-Lanl (3 * 86400 + 100 + $i) $u $profiles[$u].home (Pick $profiles[$u].servers) 'Kerberos' 'Network' }

# One labelled event outside the detection window (should not count as a label).
$rtLines.Add([pscustomobject]@{ t = 400000; line = "400000,$($users[5]),$attackHost,C7999" })

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("lanl-sample-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $tmp | Out-Null
try {
    function Write-SortedGzip([string]$Path, $Items) {
        $fs = [IO.File]::Create($Path)
        $gz = New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Compress)
        $w = New-Object IO.StreamWriter($gz, (New-Object Text.UTF8Encoding($false)))
        try { foreach ($e in ($Items | Sort-Object t)) { $w.Write($e.line + "`n") } } finally { $w.Dispose() }
    }
    Write-SortedGzip (Join-Path $tmp 'auth.txt.gz') $events
    Write-SortedGzip (Join-Path $tmp 'redteam.txt.gz') $rtLines
    Write-Host "LANL synthetic: $($events.Count) auth lines, $($rtLines.Count) red-team lines"

    & (Join-Path $PSScriptRoot '..\lanl\Import-LanlSlice.ps1') -AuthPath (Join-Path $tmp 'auth.txt.gz') `
        -RedTeamPath (Join-Path $tmp 'redteam.txt.gz') -Database $Database -BaselineDays 1 -DetectionDays 2
}
finally { Remove-Item $tmp -Recurse -Force }

# The temp path holds the builder's Windows user name; the published database shouldn't.
Invoke-SqliteQuery -DataSource $Database -Query "UPDATE lanl_import_log SET source_file = 'synthetic/auth.txt.gz'"

Write-Host "`nKRI summary:"
Invoke-SqliteQuery -DataSource $Database -Query 'SELECT indicator, value, threshold, status FROM v_kri_summary' |
    Format-Table -AutoSize | Out-String | Write-Host
