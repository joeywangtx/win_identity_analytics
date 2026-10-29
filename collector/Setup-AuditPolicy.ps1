#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enables the audit subcategories the collector depends on. VM ONLY.

.DESCRIPTION
    - Enables Logon, Special Logon, Account Lockout, User Account Management and
      Security Group Management auditing (by GUID: subcategory names are localized).
    - Grows the Security log to 1 GB so events don't roll over between daily runs.
    - Optionally sets a lockout policy so lockouts can actually happen (-SetLockoutPolicy).
    - Saves `auditpol /get /category:*` before and after, as evidence for ENGINEERING.md.

    Refuses to run on a machine that doesn't look like a VM unless -Force is given.

.EXAMPLE
    .\Setup-AuditPolicy.ps1 -SetLockoutPolicy
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SetLockoutPolicy,
    [int]$LogSizeBytes = 1073741824,
    [string]$EvidenceDir = (Join-Path $PSScriptRoot '..\data\audit-evidence'),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$model = (Get-CimInstance Win32_ComputerSystem).Model
if ($model -notmatch 'Virtual|VMware|VirtualBox|KVM|QEMU|HVM' -and -not $Force) {
    throw "This doesn't look like a VM (model '$model'). This script changes security policy; run it in your lab VM, or pass -Force."
}

# Subcategory GUIDs are the same on every Windows language.
$subcategories = @(
    @{ Name = 'Logon';                     Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true }   # 4624 4625 4648
    @{ Name = 'Special Logon';             Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false }  # 4672
    @{ Name = 'Account Lockout';           Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Success = $false; Failure = $true }   # 4625 0xC0000234
    @{ Name = 'User Account Management';   Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $true }   # 4720-4767
    @{ Name = 'Security Group Management'; Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Success = $true;  Failure = $false }  # 4732 4733
)

New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
auditpol /get /category:* | Out-File (Join-Path $EvidenceDir "auditpol-before-$stamp.txt") -Encoding utf8

foreach ($s in $subcategories) {
    $succ = if ($s.Success) { 'enable' } else { 'disable' }
    $fail = if ($s.Failure) { 'enable' } else { 'disable' }
    if ($PSCmdlet.ShouldProcess($s.Name, "auditpol success:$succ failure:$fail")) {
        auditpol /set /subcategory:"$($s.Guid)" /success:$succ /failure:$fail | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $($s.Name)" }
        Write-Host "Audit $($s.Name): success=$succ failure=$fail"
    }
}

# Subcategory settings are ignored if legacy category-level policy overrides them.
if ($PSCmdlet.ShouldProcess('SCENoApplyLegacyAuditPolicy', 'set to 1')) {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord
}

if ($PSCmdlet.ShouldProcess('Security log', "max size $LogSizeBytes bytes")) {
    wevtutil sl Security /ms:$LogSizeBytes
    Write-Host "Security log max size: $([math]::Round($LogSizeBytes / 1MB)) MB"
}

if ($SetLockoutPolicy -and $PSCmdlet.ShouldProcess('Account policy', 'lockout after 5 failures for 15 minutes')) {
    net accounts /lockoutthreshold:5 /lockoutwindow:15 /lockoutduration:15 | Out-Null
    Write-Host 'Lockout policy: 5 attempts / 15 min window / 15 min duration'
}

$after = Join-Path $EvidenceDir "auditpol-after-$stamp.txt"
auditpol /get /category:* | Out-File $after -Encoding utf8
Write-Host "Evidence saved: $after"
