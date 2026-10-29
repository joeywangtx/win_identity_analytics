#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stages identity activity on the lab VM and logs every action. VM ONLY.

.DESCRIPTION
    Creates test accounts, signs them in, produces failed logons and lockouts, and changes
    group membership, so the collector and views have something real to find.

    Every action is appended to data\activity\staged_activity.csv (UTC time, action, account,
    detail). That log is how staged activity is told apart from organic activity later.

    Passwords for the test accounts are random and stored with DPAPI (Export-Clixml), so only
    the same Windows user on the same machine can read them back.

    Logons go through the Win32 LogonUser API: an interactive (type 2) or network (type 3)
    logon that writes 4624/4625 exactly like a real sign-in, without opening a desktop.

.EXAMPLE
    .\Generate-Activity.ps1 -Action Setup            # once: create the accounts
    .\Generate-Activity.ps1 -Action Daily            # each day: normal use + a few failures
    .\Generate-Activity.ps1 -Action Lockout -Account temp_contractor
    .\Generate-Activity.ps1 -Action GrantAdmin  -Account helpdesk_tom
    .\Generate-Activity.ps1 -Action RevokeAdmin -Account helpdesk_tom   # a week later
    .\Generate-Activity.ps1 -Action Disable -Account mjones
    .\Generate-Activity.ps1 -Action Delete  -Account dormant_bob
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Setup', 'Daily', 'Logon', 'FailedLogons', 'Lockout', 'GrantAdmin', 'RevokeAdmin',
                 'NeverExpires', 'Disable', 'Delete')]
    [string]$Action,

    [string]$Account,

    [int]$Count = 3,

    [string]$DataDir = (Join-Path $PSScriptRoot '..\data\activity'),

    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$model = (Get-CimInstance Win32_ComputerSystem).Model
if ($model -notmatch 'Virtual|VMware|VirtualBox|KVM|QEMU|HVM' -and -not $Force) {
    throw "This doesn't look like a VM (model '$model'). This script creates accounts and causes lockouts; run it in your lab VM, or pass -Force."
}

# Role decides how Daily treats the account.
$Accounts = @(
    @{ Name = 'jsmith';          Role = 'regular';    Description = 'Analyst' }
    @{ Name = 'mjones';          Role = 'regular';    Description = 'Analyst' }
    @{ Name = 'akim';            Role = 'regular';    Description = 'Engineer' }
    @{ Name = 'helpdesk_tom';    Role = 'regular';    Description = 'Help desk; temporary admin rights' }
    @{ Name = 'svc_backup';      Role = 'service';    Description = 'Backup service account' }
    @{ Name = 'svc_report';      Role = 'service';    Description = '' }      # missing description on purpose
    @{ Name = 'temp_contractor'; Role = 'occasional'; Description = 'Contractor' }
    @{ Name = 'old_pwd_carl';    Role = 'occasional'; Description = 'Password never rotated' }
    @{ Name = 'dormant_alice';   Role = 'dormant';    Description = 'Unused account' }
    @{ Name = 'dormant_bob';     Role = 'dormant';    Description = 'Unused account' }
)

New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
$CredFile = Join-Path $DataDir 'credentials.clixml'
$LogFile  = Join-Path $DataDir 'staged_activity.csv'

Add-Type -Namespace IdLab -Name Native -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool LogonUser(string user, string domain, string password,
                                    int logonType, int provider, out IntPtr token);
[DllImport("kernel32.dll")]
public static extern bool CloseHandle(IntPtr handle);
'@ -ErrorAction SilentlyContinue

function Write-Staged([string]$What, [string]$Who, [string]$Detail = '') {
    [pscustomobject]@{
        time_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        action   = $What
        account  = $Who
        detail   = $Detail
    } | Export-Csv -Path $LogFile -Append -NoTypeInformation -Encoding UTF8
    Write-Host "$What $Who $Detail"
}

function New-RandomPassword {
    # Guarantees each complexity class, then fills to 20 characters.
    $sets = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!#%+=?@'
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 20
    $rng.GetBytes($bytes)
    $chars = for ($i = 0; $i -lt 20; $i++) { $set = $sets[$i % 4]; $set[$bytes[$i] % $set.Length] }
    -join ($chars | Sort-Object { Get-Random })
}

function Get-Credentials {
    if (-not (Test-Path $CredFile)) { throw "No credentials file; run -Action Setup first" }
    Import-Clixml $CredFile
}

function Invoke-Logon([string]$User, [string]$Password, [int]$Type = 2) {
    # 2 = interactive, 3 = network. Returns $true on success.
    $token = [IntPtr]::Zero
    $ok = [IdLab.Native]::LogonUser($User, '.', $Password, $Type, 0, [ref]$token)
    if ($ok) { [void][IdLab.Native]::CloseHandle($token) }
    $ok
}

function Get-PlainPassword([pscredential]$Credential) { $Credential.GetNetworkCredential().Password }

switch ($Action) {
    'Setup' {
        $creds = @{}
        if (Test-Path $CredFile) { $creds = Import-Clixml $CredFile }
        foreach ($a in $Accounts) {
            if (Get-LocalUser -Name $a.Name -ErrorAction SilentlyContinue) { continue }
            if (-not $PSCmdlet.ShouldProcess($a.Name, 'create local user')) { continue }
            $secret = ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force
            $params = @{ Name = $a.Name; Password = $secret; Description = $a.Description }
            if (-not $a.Description) { $params.Remove('Description') }
            New-LocalUser @params | Out-Null
            Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $a.Name   # Users: allows local logon
            $creds[$a.Name] = New-Object pscredential($a.Name, $secret)
            Write-Staged 'create' $a.Name "role=$($a.Role)"
        }
        $creds | Export-Clixml $CredFile
        Set-LocalUser -Name svc_backup -PasswordNeverExpires $true
        Write-Staged 'password_never_expires' 'svc_backup'
    }

    'Daily' {
        $creds = Get-Credentials
        foreach ($a in $Accounts) {
            if (-not $creds.ContainsKey($a.Name)) { continue }
            if (-not (Get-LocalUser -Name $a.Name -ErrorAction SilentlyContinue)) { continue }
            $pw = Get-PlainPassword $creds[$a.Name]
            switch ($a.Role) {
                'regular'    { if (Invoke-Logon $a.Name $pw 2) { Write-Staged 'logon' $a.Name 'interactive' } }
                'service'    { if (Invoke-Logon $a.Name $pw 3) { Write-Staged 'logon' $a.Name 'network' } }
                'occasional' { if ((Get-Random -Maximum 4) -eq 0 -and (Invoke-Logon $a.Name $pw 2)) { Write-Staged 'logon' $a.Name 'interactive' } }
                'dormant'    { }   # never used, on purpose
            }
        }
        # A little background noise: 0-2 typos for a random regular user (stays under lockout).
        $typo = ($Accounts | Where-Object Role -eq 'regular' | Get-Random).Name
        $n = Get-Random -Maximum 3
        for ($i = 0; $i -lt $n; $i++) { [void](Invoke-Logon $typo 'Wrong-Passw0rd!' 2) }
        if ($n) { Write-Staged 'failed_logon' $typo "count=$n" }
    }

    'Logon' {
        if (-not $Account) { throw '-Account is required' }
        $creds = Get-Credentials
        $ok = Invoke-Logon $Account (Get-PlainPassword $creds[$Account]) 2
        Write-Staged 'logon' $Account "interactive success=$ok"
    }

    'FailedLogons' {
        if (-not $Account) { throw '-Account is required' }
        for ($i = 0; $i -lt $Count; $i++) { [void](Invoke-Logon $Account 'Wrong-Passw0rd!' 3) }
        Write-Staged 'failed_logon' $Account "count=$Count network"
    }

    'Lockout' {
        if (-not $Account) { throw '-Account is required' }
        $threshold = [int]((net accounts | Select-String 'Lockout threshold') -replace '\D', '')
        if (-not $threshold) { throw 'No lockout threshold set; run Setup-AuditPolicy.ps1 -SetLockoutPolicy' }
        for ($i = 0; $i -le $threshold; $i++) { [void](Invoke-Logon $Account 'Wrong-Passw0rd!' 3) }
        $locked = (Get-CimInstance Win32_UserAccount -Filter "LocalAccount = True AND Name = '$Account'").Lockout
        Write-Staged 'lockout' $Account "attempts=$($threshold + 1) locked=$locked"
    }

    'GrantAdmin' {
        if (-not $Account) { throw '-Account is required' }
        if ($PSCmdlet.ShouldProcess($Account, 'add to Administrators')) {
            Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $Account
            Write-Staged 'add_admin' $Account
        }
    }

    'RevokeAdmin' {
        if (-not $Account) { throw '-Account is required' }
        if ($PSCmdlet.ShouldProcess($Account, 'remove from Administrators')) {
            Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $Account
            Write-Staged 'remove_admin' $Account
        }
    }

    'NeverExpires' {
        if (-not $Account) { throw '-Account is required' }
        Set-LocalUser -Name $Account -PasswordNeverExpires $true
        Write-Staged 'password_never_expires' $Account
    }

    'Disable' {
        if (-not $Account) { throw '-Account is required' }
        Disable-LocalUser -Name $Account
        Write-Staged 'disable' $Account
    }

    'Delete' {
        if (-not $Account) { throw '-Account is required' }
        if ($PSCmdlet.ShouldProcess($Account, 'delete local user')) {
            $groups = @(Get-LocalGroup | Where-Object {
                @(Get-LocalGroupMember -SID $_.SID -ErrorAction SilentlyContinue).Name -like "*\$Account" })
            Remove-LocalUser -Name $Account
            Write-Staged 'delete' $Account ("was in: " + (($groups.Name) -join ', '))
        }
    }
}
