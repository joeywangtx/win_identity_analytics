#Requires -Version 5.1
<#
.SYNOPSIS
    Streams a time slice of the LANL auth.txt.gz into SQLite and computes the indicators.

.DESCRIPTION
    1. Loads redteam.txt.gz into lanl_redteam (small; parameterized bulk insert).
    2. Streams auth.txt.gz with GZipStream + StreamReader (never Get-Content: the file has
       over a billion lines). The file is sorted by time, so reading stops at the first line
       past the end of the analysis window.
    3. Filters while streaming and writes kept lines unchanged to a CSV.
    4. Bulk-loads the CSV with the sqlite3 CLI (.import), far faster than row inserts.
    5. Runs sql/views_lanl.sql to fill the aggregate tables.
    Every step's row counts go into lanl_import_log.

    Filtering decision: only LogOn orientation is kept by default. LogOff duplicates each
    session, and TGS/TGT/AuthMap are Kerberos ticket bookkeeping that would inflate counts
    without describing a new logon. -KeepAllOrientations keeps everything (the SQL still
    analyses LogOn only). Computer accounts (user ending in '$') are dropped for user-focused
    analysis; how many is recorded.

.PARAMETER BaselineDays
    Dataset day indexes (day = time / 86400) used to learn "normal". Must be contiguous.

.PARAMETER DetectionDays
    Day indexes to score. Must be contiguous and after the baseline.

.PARAMETER RedTeamOnly
    Load redteam.txt.gz, print red-team events per day to help choose the slice, and stop.

.EXAMPLE
    .\Import-LanlSlice.ps1 -RedTeamPath D:\lanl\redteam.txt.gz -RedTeamOnly
    .\Import-LanlSlice.ps1 -AuthPath D:\lanl\auth.txt.gz -RedTeamPath D:\lanl\redteam.txt.gz -BaselineDays 7 -DetectionDays 8
#>
[CmdletBinding(DefaultParameterSetName = 'Import')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Import')]
    [string]$AuthPath,

    [Parameter(Mandatory)]
    [string]$RedTeamPath,

    [string]$Database = (Join-Path $PSScriptRoot '..\data\lanl.db'),

    [Parameter(ParameterSetName = 'Import')]
    [int[]]$BaselineDays = @(7),

    [Parameter(ParameterSetName = 'Import')]
    [int[]]$DetectionDays = @(8),

    [Parameter(ParameterSetName = 'Import')]
    [switch]$KeepAllOrientations,

    [Parameter(ParameterSetName = 'Import')]
    [switch]$KeepComputerAccounts,

    [Parameter(ParameterSetName = 'Import')]
    [switch]$KeepCsv,

    [Parameter(Mandatory, ParameterSetName = 'RedTeam')]
    [switch]$RedTeamOnly,

    [string]$Sqlite3 = 'sqlite3'
)

$ErrorActionPreference = 'Stop'
Import-Module PSSQLite
Import-Module (Join-Path $PSScriptRoot '..\collector\IdentityCollector.psm1') -Force
$SqlDir = Join-Path $PSScriptRoot '..\sql'
$SecondsPerDay = 86400

function Open-TextStream([string]$Path) {
    $fs = [IO.File]::OpenRead((Resolve-Path $Path))
    $stream = if ($Path -like '*.gz') {
        New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Decompress)
    } else { $fs }
    New-Object IO.StreamReader($stream, [Text.Encoding]::ASCII, $false, 1MB)
}

function Get-DayRange([int[]]$Days, [string]$Name) {
    $sorted = @($Days | Sort-Object -Unique)
    if ($sorted[-1] - $sorted[0] + 1 -ne $sorted.Count) { throw "$Name must be contiguous days; got $($Days -join ',')" }
    [pscustomobject]@{ Start = [long]$sorted[0] * $SecondsPerDay; End = ([long]$sorted[-1] + 1) * $SecondsPerDay }
}

function Invoke-Sqlite3([string]$Script) {
    # -bail: stop at the first error so a failed .import can't be mistaken for success.
    $out = $Script | & $Sqlite3 -bail $Database 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sqlite3 failed (exit $LASTEXITCODE): $out" }
    $out
}

function Get-Scalar($Conn, [string]$Query, [hashtable]$Parameters = @{}) {
    Invoke-SqliteQuery -SQLiteConnection $Conn -Query $Query -SqlParameters $Parameters -As SingleValue
}

if (-not (Get-Command $Sqlite3 -ErrorAction SilentlyContinue)) {
    throw "sqlite3 CLI not found ('$Sqlite3'). Install it and add it to PATH, or pass -Sqlite3 <path>."
}

$dbDir = Split-Path -Parent ([IO.Path]::GetFullPath($Database))
if (-not (Test-Path $dbDir)) { New-Item -ItemType Directory -Path $dbDir -Force | Out-Null }
$Database = [IO.Path]::GetFullPath($Database)

# --- Schema, red team -----------------------------------------------------------
$conn = New-SQLiteConnection -DataSource $Database
try {
    Initialize-IdentityDatabase -Connection $conn -SqlPath $SqlDir

    $reader = Open-TextStream $RedTeamPath
    $redteam = New-Object System.Collections.Generic.List[object]
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            if (-not $line) { continue }
            $p = $line.Split(',')
            $redteam.Add([pscustomobject]@{ time = [long]$p[0]; user = $p[1]; src_computer = $p[2]; dst_computer = $p[3] })
        }
    }
    finally { $reader.Dispose() }

    Invoke-SqliteQuery -SQLiteConnection $conn -Query 'DELETE FROM lanl_redteam'
    Invoke-SQLiteBulkCopy -SQLiteConnection $conn -Table lanl_redteam -Force `
        -DataTable (New-RowTable -Columns time, user, src_computer, dst_computer -Rows $redteam)
    Write-Host "Loaded $($redteam.Count) red-team events"

    if ($RedTeamOnly) {
        Invoke-SqliteQuery -SQLiteConnection $conn -Query @'
SELECT time / 86400 AS day, COUNT(*) AS events, COUNT(DISTINCT user) AS users,
       MIN(time) AS first_time, MAX(time) AS last_time
FROM lanl_redteam GROUP BY day ORDER BY day
'@ | Format-Table -AutoSize | Out-String | Write-Host
        return
    }

    # --- Windows ------------------------------------------------------------------
    $baseline  = Get-DayRange $BaselineDays 'BaselineDays'
    $detection = Get-DayRange $DetectionDays 'DetectionDays'
    if ($baseline.End -gt $detection.Start) { throw 'The baseline must end before the detection window starts' }
    $windowStart = $baseline.Start
    $windowEnd   = $detection.End

    Invoke-SqliteQuery -SQLiteConnection $conn -Query @'
INSERT INTO lanl_import_log (started_at, source_file, window_start, window_end, redteam_rows, status)
VALUES (@started, @file, @ws, @we, @rt, 'running')
'@ -SqlParameters @{ started = (ConvertTo-UtcText (Get-Date)); file = (Resolve-Path $AuthPath).Path
                     ws = $windowStart; we = $windowEnd; rt = $redteam.Count }
    $importId = Get-Scalar $conn 'SELECT last_insert_rowid()'
}
finally { $conn.Close(); $conn.Dispose() }

# --- Stream + filter ---------------------------------------------------------------
$csv = Join-Path $dbDir "lanl_slice_$importId.csv"
# Plain local counters: this loop runs once per line (100M+ times), so avoid property lookups.
$nRead = 0L; $nBefore = 0L; $nBetween = 0L; $nInWindow = 0L
$nOrientation = 0L; $nComputer = 0L; $nMalformed = 0L; $nWritten = 0L
$baselineEnd = $baseline.End; $detectionStart = $detection.Start
$filterOrientation = -not $KeepAllOrientations
$filterComputer = -not $KeepComputerAccounts
$stoppedEarly = $false
$sw = [Diagnostics.Stopwatch]::StartNew()

$reader = Open-TextStream $AuthPath
$writer = New-Object IO.StreamWriter($csv, $false, (New-Object Text.UTF8Encoding($false)), 1MB)
try {
    while ($null -ne ($line = $reader.ReadLine())) {
        $nRead++
        if ($nRead % 5000000 -eq 0) {
            Write-Host ("{0:N0} lines read ({1:N0}/s), {2:N0} kept" -f $nRead, ($nRead / $sw.Elapsed.TotalSeconds), $nWritten)
        }

        $comma = $line.IndexOf(',')
        $t = 0L
        if ($comma -lt 1 -or -not [long]::TryParse($line.Substring(0, $comma), [ref]$t)) { $nMalformed++; continue }
        if ($t -lt $windowStart) { $nBefore++; continue }
        if ($t -ge $windowEnd) { $stoppedEarly = $true; break }       # sorted by time: done
        if ($t -ge $baselineEnd -and $t -lt $detectionStart) { $nBetween++; continue }

        $nInWindow++
        $f = $line.Split(',')
        if ($f.Length -ne 9) { $nMalformed++; continue }
        if ($filterOrientation -and $f[7] -ne 'LogOn') { $nOrientation++; continue }
        if ($filterComputer -and $f[1].Split('@')[0].EndsWith('$')) { $nComputer++; continue }

        $writer.WriteLine($line)
        $nWritten++
    }
}
finally {
    $writer.Dispose()
    $reader.Dispose()
}
Write-Host ("Streamed {0:N0} lines in {1:N1} min; kept {2:N0}" -f $nRead, $sw.Elapsed.TotalMinutes, $nWritten)

# --- Load ---------------------------------------------------------------------------
# Indexes are dropped for the load and rebuilt after: one sort beats millions of index updates.
$csvForCli = $csv.Replace('\', '/')
Invoke-Sqlite3 @"
PRAGMA synchronous = OFF;
DELETE FROM lanl_auth;
DROP INDEX IF EXISTS ix_lanl_time;
DROP INDEX IF EXISTS ix_lanl_srcuser;
DROP INDEX IF EXISTS ix_lanl_dstcomp;
.import --csv "$csvForCli" lanl_auth
CREATE INDEX ix_lanl_time    ON lanl_auth(time);
CREATE INDEX ix_lanl_srcuser ON lanl_auth(src_user);
CREATE INDEX ix_lanl_dstcomp ON lanl_auth(dst_computer);
"@ | Out-Null

$conn = New-SQLiteConnection -DataSource $Database
try {
    Invoke-SqliteQuery -SQLiteConnection $conn -Query @'
DELETE FROM lanl_window;
INSERT INTO lanl_window VALUES ('baseline', @bs, @be), ('detection', @ds, @de);
'@ -SqlParameters @{ bs = $baseline.Start; be = $baseline.End; ds = $detection.Start; de = $detection.End }
    $loaded = Get-Scalar $conn 'SELECT COUNT(*) FROM lanl_auth'
}
finally { $conn.Close(); $conn.Dispose() }

$sw.Restart()
Invoke-Sqlite3 ([IO.File]::ReadAllText((Join-Path $SqlDir 'views_lanl.sql'))) | Out-Null
Write-Host ("Indicators computed in {0:N1} s" -f $sw.Elapsed.TotalSeconds)

# --- Validate + log -----------------------------------------------------------------
$notes = New-Object System.Collections.Generic.List[string]
if (-not $stoppedEarly) { $notes.Add('Reached end of file before the window ended (file truncated, or window past the data)') }
if ($loaded -ne $nWritten) { $notes.Add("Loaded $loaded rows but wrote $nWritten") }
if ($nMalformed) { $notes.Add("$nMalformed malformed lines skipped") }
if ($nBetween) { $notes.Add("$nBetween lines between baseline and detection skipped") }
$status = if ($loaded -ne $nWritten) { 'failed' } elseif ($notes.Count) { 'warning' } else { 'success' }

$conn = New-SQLiteConnection -DataSource $Database
try {
    Invoke-SqliteQuery -SQLiteConnection $conn -Query @'
UPDATE lanl_import_log
SET finished_at = @finished, rows_read = @read, rows_before_window = @before, rows_in_window = @inw,
    dropped_orientation = @orient, dropped_computer_acct = @comp, rows_written = @written,
    rows_loaded = @loaded, status = @status, notes = @notes
WHERE import_id = @id
'@ -SqlParameters @{
        finished = (ConvertTo-UtcText (Get-Date)); read = $nRead; before = $nBefore
        inw = $nInWindow; orient = $nOrientation; comp = $nComputer
        written = $nWritten; loaded = $loaded; status = $status
        notes = $(if ($notes.Count) { $notes -join '; ' } else { [DBNull]::Value }); id = $importId
    }

    Write-Host "`nImport log:"
    Invoke-SqliteQuery -SQLiteConnection $conn -Query 'SELECT * FROM lanl_import_log WHERE import_id = @id' `
        -SqlParameters @{ id = $importId } | Format-List | Out-String | Write-Host
    Write-Host 'Best cut-off per indicator (by F1):'
    Invoke-SqliteQuery -SQLiteConnection $conn -Query @'
SELECT e.indicator, e.top_n, e.flagged, e.true_pos, e.false_pos, e.precision, e.recall, e.f1
FROM lanl_detection_eval e
WHERE e.top_n = (SELECT x.top_n FROM lanl_detection_eval x WHERE x.indicator = e.indicator
                 ORDER BY x.f1 DESC, x.top_n LIMIT 1)
ORDER BY e.f1 DESC
'@ | Format-Table -AutoSize | Out-String | Write-Host
}
finally { $conn.Close(); $conn.Dispose() }

if (-not $KeepCsv) { Remove-Item $csv }
if ($status -eq 'failed') { throw "Import $importId failed validation: $($notes -join '; ')" }
