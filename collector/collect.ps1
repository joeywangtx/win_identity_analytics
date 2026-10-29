#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Collects local accounts, group membership and Security-log identity events into SQLite.

.DESCRIPTION
    One run = one row in `runs`, a fresh account/group snapshot, and every new Security event
    (4624, 4625, 4648, 4672, 4720-4767, 4732/4733, 1102) since the last run.
    Reading the Security log requires administrator rights (or SYSTEM, via Register-Task.ps1).

.PARAMETER Database
    SQLite file. Default: %ProgramData%\IdentityAnalytics\identity.db (readable by SYSTEM).

.PARAMETER LogFile
    Plain-text log of each run, useful when it runs unattended.

.EXAMPLE
    .\collect.ps1
    .\collect.ps1 -Database C:\Data\identity.db -Verbose
#>
[CmdletBinding()]
param(
    [string]$Database = (Join-Path $env:ProgramData 'IdentityAnalytics\identity.db'),
    [string]$LogFile  = (Join-Path $env:ProgramData 'IdentityAnalytics\collect.log')
)

$ErrorActionPreference = 'Stop'

function Write-Log([string]$Message) {
    $line = '{0:u}  {1}' -f (Get-Date).ToUniversalTime(), $Message
    Write-Verbose $line
    $dir = Split-Path -Parent $LogFile
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

try {
    if (-not (Get-Module -ListAvailable PSSQLite)) {
        throw 'PSSQLite not found. For the scheduled task (SYSTEM) install it machine-wide: Install-Module PSSQLite -Scope AllUsers'
    }
    Import-Module (Join-Path $PSScriptRoot 'IdentityCollector.psm1') -Force

    Write-Log "Run starting; database $Database"
    $run = Invoke-IdentityCollection -Database $Database
    Write-Log ("Run {0} {1}: {2} events, {3} accounts, {4} group members{5}" -f
        $run.run_id, $run.status, $run.events_loaded, $run.accounts, $run.group_members,
        $(if ($run.notes -and $run.notes -isnot [DBNull]) { "; notes: $($run.notes)" }))
    $run
}
catch {
    Write-Log "Run FAILED: $_"
    throw
}
