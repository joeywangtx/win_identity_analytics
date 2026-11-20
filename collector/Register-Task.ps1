#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registers a daily scheduled task, as SYSTEM: the collector (collect.ps1), or with
    -Activity, the staged daily activity (Generate-Activity.ps1 -Action Daily).

.DESCRIPTION
    SYSTEM can read the Security log without a stored password. Two consequences:
      * PSSQLite must be installed for all users (Install-Module PSSQLite -Scope AllUsers);
        a CurrentUser install lives in your profile, which SYSTEM never loads.
      * The database defaults to %ProgramData%\IdentityAnalytics, not your profile.
    Check it is running with:  SELECT * FROM v_run_history ORDER BY run_id DESC;

    The activity task can also run as SYSTEM because Generate-Activity.ps1 stores the
    test-account passwords with machine-scope DPAPI, readable by Administrators and SYSTEM.
    Check it is running with:  Import-Csv data\activity\staged_activity.csv | Select-Object -Last 5

    Each task runs through cmd.exe and appends everything it prints, errors included, to a
    task.log: next to the database for the collector, in data\activity for the activity task.
    That catches failures from before the script's own logging starts, such as a parameter
    that won't bind. The exit code still reaches Task Scheduler as LastTaskResult.

.EXAMPLE
    .\Register-Task.ps1 -At 02:00
    .\Register-Task.ps1 -Activity -At 12:00
    .\Register-Task.ps1 -Unregister
    .\Register-Task.ps1 -Activity -Unregister
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TaskName,
    [datetime]$At,
    [string]$Database = (Join-Path $env:ProgramData 'IdentityAnalytics\identity.db'),
    # Windows PowerShell 5.1, whichever shell registers the task: it's on every machine and
    # SYSTEM can always start it. A Microsoft Store PowerShell 7 can't be started by SYSTEM.
    [string]$PowerShellExe = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'),
    [switch]$Activity,
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'

if (-not $TaskName) { $TaskName = if ($Activity) { 'IdentityAnalytics-Activity' } else { 'IdentityAnalytics-Collect' } }
if (-not $PSBoundParameters.ContainsKey('At')) { $At = if ($Activity) { '12:00' } else { '02:00' } }

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed task $TaskName"
    return
}

if (-not (Test-Path $PowerShellExe)) { throw "PowerShell not found: $PowerShellExe" }
if ($PowerShellExe -like '*\WindowsApps\*') {
    throw "$PowerShellExe is a Microsoft Store app, which SYSTEM can't start. Use the MSI install (C:\Program Files\PowerShell\7\pwsh.exe) or leave -PowerShellExe out."
}

if ($Activity) {
    $script = (Resolve-Path (Join-Path $PSScriptRoot 'Generate-Activity.ps1')).Path
    $psArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action Daily' -f $script
    $taskLog = Join-Path (Split-Path $PSScriptRoot -Parent) 'data\activity\task.log'
    $description = 'Staged identity activity for the lab (Generate-Activity.ps1 -Action Daily)'
}
else {
    $allUsersModules = @("$env:ProgramFiles\WindowsPowerShell\Modules", "$env:ProgramFiles\PowerShell\Modules")
    $pssqlite = Get-Module -ListAvailable PSSQLite | Where-Object {
        $path = $_.ModuleBase; @($allUsersModules | Where-Object { $path -like "$_*" }).Count -gt 0 }
    if (-not $pssqlite) {
        Write-Warning 'PSSQLite is not installed for all users; the SYSTEM task will fail. Run: Install-Module PSSQLite -Scope AllUsers'
    }
    $script = (Resolve-Path (Join-Path $PSScriptRoot 'collect.ps1')).Path
    $psArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Database "{1}"' -f $script, $Database
    $taskLog = Join-Path (Split-Path $Database -Parent) 'task.log'
    $description = 'Collects local identity data and Security events into SQLite'
}

New-Item -ItemType Directory -Path (Split-Path $taskLog -Parent) -Force | Out-Null
# cmd /c ""exe" args >> "log" 2>&1": the outer quotes keep cmd from mangling the inner ones.
$arguments = '/c "echo ==== %DATE% %TIME% >> "{2}" & "{0}" {1} >> "{2}" 2>&1"' -f $PowerShellExe, $psArgs, $taskLog
$action    = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\cmd.exe') -Argument $arguments -WorkingDirectory $PSScriptRoot
$trigger   = New-ScheduledTaskTrigger -Daily -At $At
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# StartWhenAvailable: a VM that was off at the scheduled time runs the task when it next boots.
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
                -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

if ($PSCmdlet.ShouldProcess($TaskName, "register daily at $($At.ToString('HH:mm')) as SYSTEM")) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description $description -Force | Out-Null
    Write-Host "Registered $TaskName (daily $($At.ToString('HH:mm')), SYSTEM)$(if (-not $Activity) { " -> $Database" })"
    Write-Host "Run it now with: Start-ScheduledTask -TaskName $TaskName"
    Write-Host "Output of each run: $taskLog"
}
