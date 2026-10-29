#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registers a daily scheduled task that runs collect.ps1 as SYSTEM.

.DESCRIPTION
    SYSTEM can read the Security log without a stored password. Two consequences:
      * PSSQLite must be installed for all users (Install-Module PSSQLite -Scope AllUsers);
        a CurrentUser install lives in your profile, which SYSTEM never loads.
      * The database defaults to %ProgramData%\IdentityAnalytics, not your profile.
    Check it is running with:  SELECT * FROM v_run_history ORDER BY run_id DESC;

.EXAMPLE
    .\Register-Task.ps1 -At 02:00
    .\Register-Task.ps1 -Unregister
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TaskName = 'IdentityAnalytics-Collect',
    [datetime]$At = '02:00',
    [string]$Database = (Join-Path $env:ProgramData 'IdentityAnalytics\identity.db'),
    [string]$PowerShellExe = (Join-Path $PSHOME 'powershell.exe'),
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed task $TaskName"
    return
}

if (-not (Test-Path $PowerShellExe)) { $PowerShellExe = (Get-Command pwsh, powershell -ErrorAction SilentlyContinue | Select-Object -First 1).Source }

$allUsersModules = @("$env:ProgramFiles\WindowsPowerShell\Modules", "$env:ProgramFiles\PowerShell\Modules")
$pssqlite = Get-Module -ListAvailable PSSQLite | Where-Object {
    $path = $_.ModuleBase; @($allUsersModules | Where-Object { $path -like "$_*" }).Count -gt 0 }
if (-not $pssqlite) {
    Write-Warning 'PSSQLite is not installed for all users; the SYSTEM task will fail. Run: Install-Module PSSQLite -Scope AllUsers'
}

$script = (Resolve-Path (Join-Path $PSScriptRoot 'collect.ps1')).Path
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Database "{1}"' -f $script, $Database

$action    = New-ScheduledTaskAction -Execute $PowerShellExe -Argument $arguments -WorkingDirectory $PSScriptRoot
$trigger   = New-ScheduledTaskTrigger -Daily -At $At
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# StartWhenAvailable: a VM that was off at 02:00 runs the collection when it next boots.
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
                -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

if ($PSCmdlet.ShouldProcess($TaskName, "register daily at $($At.ToString('HH:mm')) as SYSTEM")) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description 'Collects local identity data and Security events into SQLite' -Force | Out-Null
    Write-Host "Registered $TaskName (daily $($At.ToString('HH:mm')), SYSTEM) -> $Database"
    Write-Host "Run it now with: Start-ScheduledTask -TaskName $TaskName"
}
