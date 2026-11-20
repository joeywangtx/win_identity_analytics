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

    Passwords for the test accounts are random and stored in data\activity\credentials.dat,
    encrypted with machine-scope DPAPI and readable only by Administrators and SYSTEM. So any
    admin on this VM (and the SYSTEM scheduled task) can use them, but not another machine.
    If the stored passwords can't be read (e.g. the older per-user credentials.clixml made
    by another user), Setup resets the test accounts to new random passwords and logs it.

    Logons go through the Win32 LogonUser API: an interactive (type 2) or network (type 3)
    logon that writes 4624/4625 exactly like a real sign-in, without opening a desktop.

    Setup is safe to re-run: it creates missing accounts, then brings every account to its
    intended starting state (password flags, dormant_alice in Administrators, dormant_bob in
    Backup Operators), changing and logging only what differs.

    Daily is meant to run every day; Register-Task.ps1 -Activity schedules it.

.EXAMPLE
    .\Generate-Activity.ps1 -Action Setup            # once (or again, to repair the starting state)
    .\Generate-Activity.ps1 -Action Daily            # each day: normal use + a few failures
    .\Generate-Activity.ps1 -Action AddToGroup -Account jsmith -Group RemoteDesktopUsers
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
                 'AddToGroup', 'NeverExpires', 'Disable', 'Delete')]
    [string]$Action,

    [string]$Account,

    [ValidateSet('Administrators', 'BackupOperators', 'RemoteDesktopUsers', 'Users')]
    [string]$Group,

    [int]$Count = 3,

    [string]$DataDir,   # default: ..\data\activity

    [switch]$Force
)

$ErrorActionPreference = 'Stop'
# Not a param() default: Windows PowerShell leaves $PSScriptRoot empty there under
# powershell.exe -File, which is how the scheduled task starts this script.
if (-not $DataDir) { $DataDir = Join-Path $PSScriptRoot '..\data\activity' }

$model = (Get-CimInstance Win32_ComputerSystem).Model
if ($model -notmatch 'Virtual|VMware|VirtualBox|KVM|QEMU|HVM' -and -not $Force) {
    throw "This doesn't look like a VM (model '$model'). This script creates accounts and causes lockouts; run it in your lab VM, or pass -Force."
}

# Role decides how Daily treats the account. The other keys are the starting state Setup
# enforces: NoPasswordRequired / NeverExpires flags, and privileged Groups (by SID).
$Accounts = @(
    @{ Name = 'jsmith';          Role = 'regular';    Description = 'Analyst' }
    @{ Name = 'mjones';          Role = 'regular';    Description = 'Analyst' }
    @{ Name = 'akim';            Role = 'regular';    Description = 'Engineer' }
    @{ Name = 'helpdesk_tom';    Role = 'regular';    Description = 'Help desk; temporary admin rights' }
    @{ Name = 'svc_backup';      Role = 'service';    Description = 'Backup service account'; NeverExpires = $true }
    @{ Name = 'svc_report';      Role = 'service';    Description = '' }      # missing description on purpose
    @{ Name = 'temp_contractor'; Role = 'occasional'; Description = 'Contractor'; NoPasswordRequired = $true }
    @{ Name = 'old_pwd_carl';    Role = 'occasional'; Description = 'Password never rotated' }
    @{ Name = 'dormant_alice';   Role = 'dormant';    Description = 'Unused account'; Groups = @('S-1-5-32-544') }  # Administrators
    @{ Name = 'dormant_bob';     Role = 'dormant';    Description = 'Unused account'; Groups = @('S-1-5-32-551') }  # Backup Operators
)

$GroupSids = @{
    Administrators = 'S-1-5-32-544'; BackupOperators = 'S-1-5-32-551'
    RemoteDesktopUsers = 'S-1-5-32-555'; Users = 'S-1-5-32-545'
}

New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
$CredFile       = Join-Path $DataDir 'credentials.dat'
$LegacyCredFile = Join-Path $DataDir 'credentials.clixml'   # per-user DPAPI, older versions
$LogFile        = Join-Path $DataDir 'staged_activity.csv'

Add-Type -AssemblyName System.Security

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

function Read-StoredPasswords {
    # Account name -> plain-text password. Empty when nothing readable is stored.
    $map = @{}
    if (Test-Path $CredFile) {
        $bytes = [Security.Cryptography.ProtectedData]::Unprotect(
            [IO.File]::ReadAllBytes($CredFile), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
        $json = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        foreach ($p in $json.PSObject.Properties) { $map[$p.Name] = $p.Value }
    }
    elseif (Test-Path $LegacyCredFile) {
        try {
            $legacy = Import-Clixml $LegacyCredFile
            foreach ($k in $legacy.Keys) { $map[$k] = $legacy[$k].GetNetworkCredential().Password }
        }
        catch [Security.Cryptography.CryptographicException] {
            Write-Warning "Can't read $LegacyCredFile; it was encrypted for another Windows user. Setup will reset the test accounts' passwords."
        }
    }
    $map
}

function Save-StoredPasswords([hashtable]$Passwords) {
    $bytes = [Text.Encoding]::UTF8.GetBytes(([pscustomobject]$Passwords | ConvertTo-Json -Compress))
    [IO.File]::WriteAllBytes($CredFile, [Security.Cryptography.ProtectedData]::Protect(
        $bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine))
    # Machine-scope DPAPI lets any local process decrypt, so the file ACL is the real lock.
    icacls $CredFile /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $CredFile" }
    if (Test-Path $LegacyCredFile) { Remove-Item $LegacyCredFile -Force }
}

function Get-Credentials {
    $map = Read-StoredPasswords
    if (-not $map.Count) { throw 'No readable stored passwords; run -Action Setup first' }
    $map
}

function Invoke-Logon([string]$User, [string]$Password, [int]$Type = 2) {
    # 2 = interactive, 3 = network. Returns $true on success.
    $token = [IntPtr]::Zero
    $ok = [IdLab.Native]::LogonUser($User, '.', $Password, $Type, 0, [ref]$token)
    if ($ok) { [void][IdLab.Native]::CloseHandle($token) }
    $ok
}

function Test-NeverExpires([string]$Name) {
    # ADSI userFlags, as the collector reads it; Get-LocalUser has no direct property.
    ([int]([ADSI]"WinNT://$env:COMPUTERNAME/$Name,user").UserFlags.Value -band 0x10000) -ne 0
}

function Set-PasswordRequired([string]$Name, [bool]$Required) {
    # Set-LocalUser can't change this flag; net user can.
    $value = if ($Required) { 'yes' } else { 'no' }
    net user $Name /passwordreq:$value | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "net user $Name /passwordreq:$value failed" }
    Write-Staged $(if ($Required) { 'password_required' } else { 'password_not_required' }) $Name
}

function Add-ToGroup([string]$Name, [string]$GroupSid) {
    # Returns $true if added, $false if already a member. Adding and catching "already a
    # member" avoids Get-LocalGroupMember, which throws on groups holding orphaned SIDs.
    try { Add-LocalGroupMember -SID $GroupSid -Member $Name; $true }
    catch [Microsoft.PowerShell.Commands.MemberExistsException] { $false }
}

switch ($Action) {
    'Setup' {
        $creds = Read-StoredPasswords
        # finally: a password that was just set is saved even if a later account fails.
        try { foreach ($a in $Accounts) {
            $exists = [bool](Get-LocalUser -Name $a.Name -ErrorAction SilentlyContinue)
            if ($exists -and $creds.ContainsKey($a.Name)) { continue }
            $plain = New-RandomPassword
            $secret = ConvertTo-SecureString $plain -AsPlainText -Force
            if ($exists) {
                # The account exists but its password isn't readable: give it a new one.
                if (-not $PSCmdlet.ShouldProcess($a.Name, 'reset password')) { continue }
                Set-LocalUser -Name $a.Name -Password $secret
                Write-Staged 'reset_password' $a.Name 'stored password unreadable'
            }
            else {
                if (-not $PSCmdlet.ShouldProcess($a.Name, 'create local user')) { continue }
                $params = @{ Name = $a.Name; Password = $secret; Description = $a.Description }
                if (-not $a.Description) { $params.Remove('Description') }
                New-LocalUser @params | Out-Null
                Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $a.Name   # Users: allows local logon
                Write-Staged 'create' $a.Name "role=$($a.Role)"
            }
            $creds[$a.Name] = $plain
        } }
        finally { if ($creds.Count) { Save-StoredPasswords $creds } }

        # Starting state. Each step checks first, so a re-run only changes what differs.
        foreach ($a in $Accounts) {
            $u = Get-LocalUser -Name $a.Name -ErrorAction SilentlyContinue
            if (-not $u) { continue }   # e.g. dormant_bob after the Delete step
            # New-LocalUser sets "password not required" on every account it creates; only
            # temp_contractor is meant to have it.
            $wantRequired = -not $a.NoPasswordRequired
            if ($u.PasswordRequired -ne $wantRequired -and $PSCmdlet.ShouldProcess($a.Name, "password required = $wantRequired")) {
                Set-PasswordRequired $a.Name $wantRequired
            }
            if ($a.NeverExpires -and -not (Test-NeverExpires $a.Name)) {
                Set-LocalUser -Name $a.Name -PasswordNeverExpires $true
                Write-Staged 'password_never_expires' $a.Name
            }
            foreach ($sid in @($a.Groups | Where-Object { $_ })) {
                if ($PSCmdlet.ShouldProcess($a.Name, "add to group $sid") -and (Add-ToGroup $a.Name $sid)) {
                    Write-Staged 'add_group' $a.Name "group_sid=$sid"
                }
            }
        }
    }

    'Daily' {
        $creds = Get-Credentials
        foreach ($a in $Accounts) {
            if (-not $creds.ContainsKey($a.Name)) { continue }
            if (-not (Get-LocalUser -Name $a.Name -ErrorAction SilentlyContinue)) { continue }
            $pw = $creds[$a.Name]
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
        $ok = Invoke-Logon $Account $creds[$Account] 2
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

    'AddToGroup' {
        if (-not $Account -or -not $Group) { throw '-Account and -Group are required' }
        if ($PSCmdlet.ShouldProcess($Account, "add to $Group")) {
            if (Add-ToGroup $Account $GroupSids[$Group]) { Write-Staged 'add_group' $Account "group=$Group" }
            else { Write-Host "$Account is already in $Group" }
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
