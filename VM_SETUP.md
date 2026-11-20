# Creating the lab VM (Hyper-V)

This guide builds the Windows 11 VM that the collector runs in (`IDLAB-VM`). It takes about an hour, most of it
waiting for Windows to install. Commands marked **host** run on the laptop in an **Administrator** PowerShell.
Commands marked **VM** run inside the VM.

Checked on this laptop: Windows 11 Pro, 16 GB RAM, 125 GB free on C:, virtualization enabled. Hyper-V is **not**
enabled yet (step 1).

| VM setting | Value | Why |
|---|---|---|
| Generation | 2 | Required for Secure Boot + TPM |
| CPU | 2 virtual processors | Windows 11 minimum |
| Memory | 4 GB fixed | Windows 11 minimum. Leaves the laptop about 12 GB |
| Disk | 64 GB dynamic VHDX | Windows 11 minimum. Uses ~25 GB at first and grows |
| Network | Default Switch | NAT to the internet, no setup |
| Security | Secure Boot (Windows template) + virtual TPM | Windows 11 setup refuses to install without them |

---

## 1. Turn on Hyper-V (host, once)

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

Restart when it asks. Then check that it's running:

```powershell
Get-Service vmms          # Status should be Running
Get-VMSwitch              # should list "Default Switch"
```

If it fails with a virtualization error, enable **Intel VT-x / AMD-V** in the BIOS/UEFI settings.

## 2. Download Windows 11

Use the **Windows 11 Enterprise evaluation** ISO. It's free for 90 days, which is longer than this project, and it
needs no product key:

1. Go to <https://www.microsoft.com/evalcenter/evaluate-windows-11-enterprise>
2. Choose **ISO – Enterprise**, 64-bit, your language. It needs a short registration form.
3. Save it as `C:\HyperV\ISO\Win11_Eval.iso`. It's about 5–6 GB.

Enterprise also lets you skip the Microsoft account and create a **local account** during setup. This lab used a
Microsoft account and added a local admin afterwards (step 4); either works.

> Alternative: the normal Windows 11 ISO from <https://www.microsoft.com/software-download/windows11>. Choose
> "I don't have a product key" and pick Pro. It works unactivated (watermark, limited personalisation), but recent
> builds push hard for a Microsoft account during setup.

> Hyper-V Manager's **Quick Create** used to offer a ready-made "Windows 11 dev environment". Microsoft has
> stopped publishing that image, so this guide builds the VM from the ISO. (Quick Create with "Local installation
> source" also works, but the script below gives you a VM with exactly the settings in the table.)

## 3. Create the VM (host)

Save as `C:\HyperV\New-LabVM.ps1` and run it in an Administrator PowerShell:

```powershell
$Name   = 'IDLAB-VM'
$Root   = 'C:\HyperV'
$Iso    = "$Root\ISO\Win11_Eval.iso"

if (-not (Test-Path $Iso)) { throw "ISO not found: $Iso" }

New-VM -Name $Name -Generation 2 -MemoryStartupBytes 4GB -Path $Root `
       -NewVHDPath "$Root\$Name\$Name.vhdx" -NewVHDSizeBytes 64GB -SwitchName 'Default Switch'

Set-VMProcessor -VMName $Name -Count 2
Set-VMMemory    -VMName $Name -DynamicMemoryEnabled $false

# Windows 11 requirements: Secure Boot with the Microsoft Windows template, and a TPM.
Set-VMKeyProtector -VMName $Name -NewLocalKeyProtector
Enable-VMTPM       -VMName $Name

# Boot from the ISO first.
$dvd = Add-VMDvdDrive -VMName $Name -Path $Iso -Passthru
Set-VMFirmware -VMName $Name -FirstBootDevice $dvd -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows

# Standard checkpoints only when you take them (step 6), not automatically.
Set-VM -VMName $Name -CheckpointType Standard -AutomaticCheckpointsEnabled $false

# Lets the host copy files in and run commands inside (steps 7-8).
Enable-VMIntegrationService -VMName $Name -Name 'Guest Service Interface'

Get-VM $Name | Format-List Name, State, Generation, ProcessorCount, MemoryStartup
```

## 4. Install Windows

```powershell
Start-VM IDLAB-VM
vmconnect localhost IDLAB-VM
```

1. **Press any key** as soon as "Press any key to boot from CD or DVD…" appears. You only get a few seconds. If you
   see a PXE / "No operating system" screen instead, close the window, run `Stop-VM IDLAB-VM -TurnOff`, then
   `Start-VM` and try again.
2. Setup: language → **Install Windows 11** → accept the licence → **Custom: Install Windows only** → select the
   empty disk → Next. It reboots a few times.
3. Out-of-box setup (OOBE):
   - Region and keyboard: your choice.
   - Sign in with your **Microsoft account**. Setup makes it the first administrator.
   - Privacy settings: turn everything off.
4. After you reach the desktop, create **`labadmin`**, a local admin account. PowerShell Direct (step 7) and the
   export need a local `IDLAB-VM\labadmin` credential; a Microsoft account doesn't work well there. Then **rename the
   computer** so it matches the sample data and docs (VM, admin PowerShell):

   ```powershell
   $pw = Read-Host 'Password for labadmin' -AsSecureString
   New-LocalUser -Name labadmin -Password $pw
   Add-LocalGroupMember -SID 'S-1-5-32-544' -Member labadmin   # Administrators
   Rename-Computer -NewName IDLAB-VM -Restart
   ```

   `New-LocalUser` silently sets **"password not required"** on the account, which lets its password be made blank.
   This lab left the flag in place, and the collector reports it as a real finding
   ([findings, item 2](report/findings.md#2-the-labs-own-admin-account-allows-an-empty-password)). On any machine you
   care about, clear it straight away with `net user labadmin /passwordreq:yes`.
   - **The Microsoft account's password never expires locally.** It's managed online, so the "password never expires"
     KRI counts it. Treat it as an accepted exception.

## 5. Prepare Windows (VM, admin PowerShell)

```powershell
# Updates first. They're noisy in the Security log; better done before you start collecting.
#   Settings → Windows Update → Check for updates; repeat until clean, reboot.

# Keep the VM awake so the 02:00 task isn't skipped while the VM runs.
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0

# Allow local scripts.
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

# PSSQLite for ALL users: the scheduled task runs as SYSTEM.
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module PSSQLite -Scope AllUsers -Force
```

Pester and sqlite3 aren't needed in the VM. Tests and the LANL import run on the laptop.

## 6. Take a checkpoint (host)

```powershell
Checkpoint-VM -Name IDLAB-VM -SnapshotName 'clean-install'
```

This is your undo button. If an experiment goes wrong: `Restore-VMCheckpoint -VMName IDLAB-VM -Name clean-install -Confirm:$false`.
A restore throws away everything after the checkpoint, including collected data, so copy the database out first (step 8).

## 7. Copy the project into the VM (host)

PowerShell Direct opens a session from the host into the VM over the VM bus. No network or file sharing is needed.

```powershell
$cred = Get-Credential IDLAB-VM\labadmin
$s = New-PSSession -VMName IDLAB-VM -Credential $cred

# Code only: data/, *.db and *.gz stay on the laptop.
$src = 'C:\Work\Internship\win_identity_analytics'
Invoke-Command -Session $s { New-Item -ItemType Directory C:\Lab\identity-analytics -Force | Out-Null }
foreach ($dir in 'collector', 'sql') {
    Copy-Item "$src\$dir" -Destination 'C:\Lab\identity-analytics\' -ToSession $s -Recurse -Force
}
Remove-PSSession $s
```

Run this again whenever you change the scripts on the laptop.

## 8. Run the lab (VM, admin PowerShell)

Follow [ENGINEERING.md, Part 1](ENGINEERING.md#part-1-collector-in-the-vm) from inside the VM:

```powershell
cd C:\Lab\identity-analytics
.\collector\Setup-AuditPolicy.ps1 -SetLockoutPolicy
.\collector\collect.ps1 -Verbose
.\collector\Register-Task.ps1 -At 02:00                # collector, daily as SYSTEM
.\collector\Generate-Activity.ps1 -Action Setup        # test accounts and their starting state
.\collector\Register-Task.ps1 -Activity -At 12:00      # staged daily activity, as SYSTEM
Start-ScheduledTask -TaskName IdentityAnalytics-Activity; Start-Sleep 30
Get-ScheduledTaskInfo -TaskName IdentityAnalytics-Activity | Format-Table LastRunTime, LastTaskResult   # want 0
Import-Csv .\data\activity\staged_activity.csv | Select-Object -Last 8 | Format-Table   # want today's logon rows
```

Keep the `Format-Table` on each line. Without it, PowerShell prints the CSV rows under the first command's columns, and
they show as blank lines. If `LastTaskResult` isn't 0 or there are no new `logon` rows, see
[ENGINEERING.md, Is the staged activity running?](ENGINEERING.md#is-the-staged-activity-running).

The test-account passwords are kept in `data\activity\credentials.dat`, encrypted for this machine and readable only
by Administrators and SYSTEM, so any admin can run the scripts and the activity task needs no stored password.
Without this task, the test accounts log on once and never again, and the lockout, failure and dormancy checks have
nothing to find.

Then take a second checkpoint: `Checkpoint-VM -Name IDLAB-VM -SnapshotName 'collector-ready'` (host).

### Staged scenario

The daily task covers normal use. These one-off steps are run by hand, on top of it (VM, admin PowerShell, in
`C:\Lab\identity-analytics`). Every step is logged to `data\activity\staged_activity.csv`.

| Day | Command | What it should trigger |
|---|---|---|
| 0 | `Generate-Activity.ps1 -Action Setup` | Dormant `dormant_alice` in Administrators (red), `dormant_bob` in Backup Operators, `temp_contractor` with no password required (red), `svc_backup` password never expires (amber) |
| 1 | `Generate-Activity.ps1 -Action GrantAdmin -Account helpdesk_tom` | A privileged group change |
| 1 | `Generate-Activity.ps1 -Action Lockout -Account temp_contractor` | A lockout after 5 quick failures |
| 2 | `Generate-Activity.ps1 -Action Disable -Account mjones` | Account lifecycle |
| 3 | `Generate-Activity.ps1 -Action Delete -Account dormant_bob` | Account deleted (4726), and removed from Backup Operators (4733), a privileged group change. No orphaned SID: deleting a *local* account also removes it from every local group. Orphans come from domain or cloud accounts deleted elsewhere, so on the VM that KRI stays green and only the sample database shows it |
| 4+ | `Generate-Activity.ps1 -Action Lockout -Account temp_contractor` | A second lockout |
| 7 | `Generate-Activity.ps1 -Action RevokeAdmin -Account helpdesk_tom` | The temporary admin removed a week later |

Export the day after the last step, once the next collector run has loaded it. The 7-day KRIs count back 7 days from
the latest run, so every extra day drops the earliest steps out of them. The event views (`v_lockouts`,
`v_privileged_group_changes`, `v_account_lifecycle`) keep the whole history either way.

Count days by your local date. `staged_activity.csv` is in UTC, so an evening step can show the next day's date.
Each step prints what it did (e.g. `lockout temp_contractor attempts=6 locked=True`) and adds a row to the log. If
Lockout says `No lockout threshold set`, run `Setup-AuditPolicy.ps1 -SetLockoutPolicy` first. `locked=False` means
the lockout didn't happen; check `net accounts`.

**Already collecting with an older version of the scripts?** Copy the project in again (step 7), then re-run
`Generate-Activity.ps1 -Action Setup`. It creates nothing new, but fixes the starting state. If the old
`credentials.clixml` was made by a different Windows user and can't be read ("Key not valid for use in specified
state"), it gives the test accounts new random passwords and logs a `reset_password` row for each. It also clears the "password
not required" flag that `New-LocalUser` sets on every account it creates (except on `temp_contractor`, where it's
intended), and adds `dormant_alice` and `dormant_bob` to their groups. Then register the activity task and start the
scenario from day 1.

A fresh VM can't produce the "password older than 365 days" KRI: Windows doesn't let you backdate a password, so
`old_pwd_carl`'s password is always new. That KRI is only shown by the sample database.

**The VM only collects while it's running.** A paused or stopped VM generates no events, and the task runs late on
the next start (`StartWhenAvailable`). Two options:

- Leave the VM running whenever the laptop is on, and register the task at a time the laptop is usually awake
  (e.g. `-At 12:00`).
- Have it start with the laptop: `Set-VM IDLAB-VM -AutomaticStartAction Start -AutomaticStopAction Save` (host).

Both tasks follow the same rule: if the VM was off at the scheduled time, the task runs when it next starts.

### Get the database out (host)

```powershell
$s = New-PSSession -VMName IDLAB-VM -Credential $cred
New-Item -ItemType Directory C:\Work\Internship\win_identity_analytics\data -Force | Out-Null
Copy-Item 'C:\ProgramData\IdentityAnalytics\identity.db' -FromSession $s `
          -Destination 'C:\Work\Internship\win_identity_analytics\data\identity.db'
Copy-Item 'C:\Lab\identity-analytics\data\activity\staged_activity.csv' -FromSession $s `
          -Destination 'C:\Work\Internship\win_identity_analytics\data\'
Remove-PSSession $s
```

Don't copy while the 02:00 task is running. `data/` is git-ignored.

## 9. When the project is done (host)

```powershell
Stop-VM IDLAB-VM -TurnOff
Remove-VM IDLAB-VM -Force
Remove-Item C:\HyperV\IDLAB-VM -Recurse -Force    # the VHDX and checkpoints (~25-40 GB)
```

Remove Hyper-V too, if you won't use it again: `Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| "This PC can't run Windows 11" during setup | Check TPM is on (`Get-VMSecurity IDLAB-VM`), Secure Boot template is `MicrosoftWindows`, 2+ CPUs, 4 GB RAM (not dynamic) |
| You'd rather not use a Microsoft account | Take the VM offline during OOBE: `Disconnect-VMNetworkAdapter -VMName IDLAB-VM` (host), go back one screen and continue. A local account is offered offline. Reconnect afterwards: `Connect-VMNetworkAdapter -VMName IDLAB-VM -SwitchName 'Default Switch'` |
| Boots to PXE / "No operating system was loaded" | You missed "Press any key". Turn off, start, press a key straight away |
| `New-PSSession -VMName` fails | The VM must be running and signed in at least once. Use `IDLAB-VM\labadmin`, and check the Guest Service Interface is on |
| No internet in the VM | `Get-VMNetworkAdapter IDLAB-VM`. It should be on `Default Switch`. Restarting the host's Hyper-V service usually fixes Default Switch NAT |
| Laptop sluggish | Lower the VM to 4 GB if you raised it, and close the vmconnect window (the VM keeps running) |
| VirtualBox/VMware stop working | They need to run on top of Hyper-V (recent versions do). Otherwise disable Hyper-V while using them |
