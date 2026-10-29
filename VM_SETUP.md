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

Enterprise also makes a **local account** easy during setup (step 4), and this project is about local accounts.

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
   - Enterprise: **Sign-in options → Domain join instead**. That creates a local account.
   - User name: **`labadmin`**. Give it a password you'll remember, and answer the three security questions with junk.
   - Privacy settings: turn everything off.
4. After you reach the desktop, **rename the computer** so it matches the sample data and docs (VM, admin PowerShell):

   ```powershell
   Rename-Computer -NewName IDLAB-VM -Restart
   ```

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
.\collector\Register-Task.ps1 -At 02:00
.\collector\Generate-Activity.ps1 -Action Setup
```

Then take a second checkpoint: `Checkpoint-VM -Name IDLAB-VM -SnapshotName 'collector-ready'` (host).

**The VM only collects while it's running.** A paused or stopped VM generates no events, and the task runs late on
the next start (`StartWhenAvailable`). Two options:

- Leave the VM running whenever the laptop is on, and register the task at a time the laptop is usually awake
  (e.g. `-At 12:00`).
- Have it start with the laptop: `Set-VM IDLAB-VM -AutomaticStartAction Start -AutomaticStopAction Save` (host).

Daily routine: `.\collector\Generate-Activity.ps1 -Action Daily` inside the VM, plus the staged events in the plan
(admin add/remove a week apart, lockouts, disable/delete).

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
| Setup insists on a Microsoft account | Take the VM offline during OOBE: `Disconnect-VMNetworkAdapter -VMName IDLAB-VM` (host), go back one screen and continue. A local account is offered offline. Reconnect afterwards: `Connect-VMNetworkAdapter -VMName IDLAB-VM -SwitchName 'Default Switch'` |
| Boots to PXE / "No operating system was loaded" | You missed "Press any key". Turn off, start, press a key straight away |
| `New-PSSession -VMName` fails | The VM must be running and signed in at least once. Use `IDLAB-VM\labadmin`, and check the Guest Service Interface is on |
| No internet in the VM | `Get-VMNetworkAdapter IDLAB-VM`. It should be on `Default Switch`. Restarting the host's Hyper-V service usually fixes Default Switch NAT |
| Laptop sluggish | Lower the VM to 4 GB if you raised it, and close the vmconnect window (the VM keeps running) |
| VirtualBox/VMware stop working | They need to run on top of Hyper-V (recent versions do). Otherwise disable Hyper-V while using them |
