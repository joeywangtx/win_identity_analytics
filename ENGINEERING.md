# Engineering guide

How to install, configure, run, test and debug the Windows Identity Analytics Pipeline. For what the project is for
and how to read its results, see [README.md](README.md).

## Contents

1. [Architecture](#architecture)
2. [Requirements and installation](#requirements-and-installation): [installing PowerShell 7](#installing-powershell-7)
3. [Configuration](#configuration)
4. [Running](#running): [sample](#sample-database), [collector](#part-1-collector-in-the-vm), [LANL](#part-2-lanl-import), [Power BI](#part-3-power-bi)
5. [Schema reference](#schema-reference)
6. [Data reference](#data-reference): [KRI thresholds](#kri-thresholds), [sample contents](#sample-database-contents), [LANL slice](#lanl-slice), [lab VM run log](#lab-vm-run-log)
7. [Testing with Pester](#testing-with-pester)
8. [Debugging and troubleshooting](#debugging-and-troubleshooting)
9. [Repository layout](#repository-layout)

Detailed guides that this page links to rather than repeats:

| Guide | Covers |
|---|---|
| [VM_SETUP.md](VM_SETUP.md) | Building the Hyper-V VM, copying the project in, getting the database out |
| [lanl/README.md](lanl/README.md) | LANL download, terms of use, slice choice, filtering decisions |
| [powerbi/README.md](powerbi/README.md) | ODBC connection, tables to import, dashboard pages |

---

## Architecture

```
 Windows VM                              LANL auth.txt.gz (1B+ lines)
 ├ Get-LocalUser / LocalGroupMember       │ GZipStream, stop at window end
 ├ Security log (Get-WinEvent, XPath)     │ filter → CSV → sqlite3 .import
 ▼                                        ▼
 collect.ps1 (daily, SYSTEM)  ──►  SQLite  ◄──  Import-LanlSlice.ps1
                                    │  views_local.sql   (dormant, privileged, hygiene, lockouts…)
                                    │  views_lanl.sql    (fan-out, new pairs, NTLM… → precision/recall)
                                    │  kri_summary.sql   (red / amber / green)
                                    ▼
                               Power BI (ODBC)
```

| Component | Runs where | Does |
|---|---|---|
| `collector/IdentityCollector.psm1` | VM | All collector logic: snapshots, event parsing, incremental load, gap detection. Windows calls go through small wrappers so tests can mock them |
| `collector/collect.ps1` | VM, daily as SYSTEM | Thin entry point: imports the module, runs one collection, writes `collect.log`, and rethrows on failure so the task result is non-zero |
| `collector/Setup-AuditPolicy.ps1` | VM, once | Audit subcategories by GUID, 1 GB Security log, optional lockout policy, `auditpol` evidence |
| `collector/Generate-Activity.ps1` | VM, setup + daily | Test accounts and staged activity, logged to `staged_activity.csv` |
| `collector/Register-Task.ps1` | VM, once | Registers the `IdentityAnalytics-Collect` daily task (SYSTEM), and with `-Activity` the `IdentityAnalytics-Activity` daily task (also SYSTEM) |
| `lanl/Import-LanlSlice.ps1` | Host | Streams the gzip, filters the window, bulk-loads with `sqlite3 .import`, then runs `views_lanl.sql` |
| `sql/schema.sql` | Both | Tables, indexes, lookup tables |
| `sql/views_local.sql`, `sql/kri_summary.sql` | Both | Local views and KRI rows (persistent views, SQLite 3.8.8-compatible) |
| `sql/views_lanl.sql` | Host, `sqlite3` CLI | LANL indicators and evaluation, materialised into plain tables |
| `sample/New-SampleDatabase.ps1` | Host | Builds the synthetic `sample.db` through the real importer |

### Design notes

- **Incremental and idempotent loading.** Each run reads only events with an `EventRecordID` higher than the highest
  one stored in the current **log epoch**. `(log_epoch, record_id)` is the primary key and rows are inserted with
  `OR IGNORE`, so an overlap or a rerun can't duplicate data. Every value goes in through query parameters, never
  string concatenation.
- **Gap detection.** Each run stores the log's newest record ID as a high-water mark. If the oldest record still in
  the log is later than the previous mark, events were lost to rollover. If the newest record is earlier, the log was
  cleared or the VM was restored to a checkpoint. Either case marks the run `warning` with a note.
- **Log epochs.** Clearing the Security log (or restoring a checkpoint) restarts `EventRecordID` from a low number.
  Without epochs, the collector would skip every new event, including the 1102 "log cleared" event, until the IDs
  passed the old maximum, and new events reusing an old ID would be dropped as duplicates. So when a reset is
  detected, the run raises `log_epoch` by one and reads the log from the start. The epoch is saved on the `runs` row
  before events load, so a run that fails mid-load doesn't make the next run count the same reset twice. Databases
  created before epochs existed are upgraded in place on the next run (existing rows become epoch 0).
- **Orphaned SIDs.** `Get-LocalGroupMember` throws when a group contains a SID that no longer resolves. The collector
  falls back to ADSI and keeps the member as `Orphaned`, because that's a finding, not a crash.
- **SQLite 3.8.8 compatibility.** PSSQLite bundles SQLite 3.8.8 (2015), and SQLite parses the whole schema whenever a
  connection opens. A single view using window functions, `IIF` or UPSERT would break the collector. So every
  persistent view uses 3.8.8-compatible SQL. The LANL analysis, which needs window functions, runs in the modern
  `sqlite3` CLI and writes its results to plain tables.
- **Script paths resolved in the body.** Windows PowerShell 5.1 leaves `$PSScriptRoot` empty in an advanced script's
  `param()` defaults when it's started with `powershell.exe -File`, which is how scheduled tasks start it. So path
  defaults such as `-DataDir` and `-Database` are left empty in `param()` and filled in on the first lines of the
  script.
- **Reproducible "now".** Views measure time from the latest successful run (`v_reference_run`), not the wall clock.
  Reopening an old database gives the same answers.
- **UTC everywhere.** All timestamps are stored as UTC text.
- **Locale-safe.** Groups are matched by well-known SID and audit subcategories by GUID, so this works on
  non-English Windows.
- **Aggregate before Power BI.** Power BI imports thousands of aggregate rows instead of millions of events.

## Requirements and installation

| Tool | Where | Why | Install |
|---|---|---|---|
| Windows PowerShell 5.1 or PowerShell 7 | Host and VM | Everything. Scheduled tasks always use 5.1 | Built in (5.1). PowerShell 7: [below](#installing-powershell-7) |
| PSSQLite 1.1.0 | Host: CurrentUser. VM: **AllUsers** | SQLite access from PowerShell | `Install-Module PSSQLite -Scope CurrentUser` (host) / `-Scope AllUsers` (VM) |
| Pester 5.5+ | Host | Tests | `Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -SkipPublisherCheck` |
| sqlite3 CLI 3.25+ | Host | LANL bulk import and window functions, quick inspection | Download from <https://sqlite.org/download.html> and add to PATH |
| Hyper-V | Host | The lab VM | See [VM_SETUP.md](VM_SETUP.md) |
| Power BI Desktop + 64-bit SQLite ODBC driver | Host | Part 3 | See [powerbi/README.md](powerbi/README.md) |

Pester and sqlite3 aren't needed in the VM. Tests and the LANL import run on the host.

### Installing PowerShell 7

PowerShell 7 doesn't upgrade Windows PowerShell 5.1. It installs **next to it**. 5.1 (`powershell.exe`) is part of
Windows and stays; 7 is a separate program (`pwsh.exe`) with its own folder, profile and settings. You can use either
for this project: all 51 tests pass on both, and CI runs both.

**Install** (host, any PowerShell). Prefer the MSI-based install over the Microsoft Store:

```powershell
winget install --id Microsoft.PowerShell --source winget
```

This installs to `C:\Program Files\PowerShell\7\` and updates through winget (`winget upgrade Microsoft.PowerShell`).
The Microsoft Store version works for interactive use, but it lives in a protected `WindowsApps` folder that the
SYSTEM account can't start programs from. To see which one you have:

```powershell
(Get-Command pwsh).Source   # ...\PowerShell\7\pwsh.exe = MSI; ...\WindowsApps\pwsh.exe = Store
```

**Open it:** Start menu → *PowerShell 7*, or type `pwsh`. In Windows Terminal, set it as the default profile under
Settings → Startup. VS Code picks it up automatically for `.ps1` files once it's installed.

**Modules.** PowerShell 7 also loads modules from the Windows PowerShell folders, so modules you installed under 5.1
(PSSQLite, Pester) normally work without reinstalling. Check, and install any that are missing, from `pwsh`:

```powershell
Get-Module -ListAvailable Pester, PSSQLite | Format-Table Name, Version, ModuleBase
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -Force -SkipPublisherCheck   # if missing
Install-Module PSSQLite -Scope CurrentUser -Force                                          # if missing
```

**Run the tests in 7:**

```powershell
pwsh
cd C:\Work\Internship\win_identity_analytics
Invoke-Pester .\tests
```

**What stays on 5.1, and why:**

- **The scheduled tasks.** `Register-Task.ps1` always points the tasks at Windows PowerShell 5.1
  (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`), even when you run it from 7. 5.1 is on every
  machine, SYSTEM can always start it, and it's what the collector was run on for the lab results. To run the tasks
  on 7 instead, pass the MSI path: `Register-Task.ps1 -PowerShellExe 'C:\Program Files\PowerShell\7\pwsh.exe'`.
  A Store path is refused.
- **The VM.** Nothing in the VM needs 7, so it isn't installed there. If you do install it, the tasks still use 5.1
  unless you pass `-PowerShellExe`.

**Differences that matter here:**

- **Default file encoding.** 7 writes UTF-8 without a BOM; 5.1's `Set-Content` writes the system code page and
  `Out-File` writes UTF-16. The scripts ask for UTF-8 explicitly, so their files (`collect.log`,
  `staged_activity.csv`) read the same on both; the only difference is that 5.1 adds a byte-order mark.
- **`&&` and `||`** work in 7 but are parse errors in 5.1. Avoid them in scripts that must run on both.
- **Pester 3.4** is built into 5.1 only, so the old-Pester conflict described under
  [Useful commands](#useful-commands) doesn't happen in 7.

## Configuration

| Setting | Default | Where to change it |
|---|---|---|
| Audit subcategories | Logon, Special Logon, Account Lockout, User Account Management, Security Group Management | `Setup-AuditPolicy.ps1` |
| Security log size | 1 GB | `Setup-AuditPolicy.ps1` |
| Lockout policy | 5 attempts, 15-minute window, 15-minute duration | `Setup-AuditPolicy.ps1 -SetLockoutPolicy` |
| Collector database | `%ProgramData%\IdentityAnalytics\identity.db` | `collect.ps1 -Database`, `Register-Task.ps1 -Database` |
| Collector log | `%ProgramData%\IdentityAnalytics\collect.log` | `collect.ps1 -LogFile` |
| Task output logs | Collector: `task.log` next to the database. Activity: `data\activity\task.log` | Set by `Register-Task.ps1` |
| Task schedule | Collector: daily at 02:00 local, as SYSTEM. Activity: daily at 12:00, as SYSTEM. Both: 1-hour limit, run late if missed | `Register-Task.ps1 -At` (add `-Activity` for the activity task) |
| Dormancy threshold | 30 days | `sql/views_local.sql` |
| KRI thresholds and severities | See [KRI thresholds](#kri-thresholds) | `sql/kri_summary.sql` |
| LANL windows | Baseline day 7, detection day 8 | `Import-LanlSlice.ps1 -BaselineDays -DetectionDays` |
| LANL orientation filter | `LogOn` only | `Import-LanlSlice.ps1 -KeepAllOrientations` (the SQL still analyses `LogOn` only) |
| Top-N cut-offs | 5, 10, 20, 50, 100, 250 | `sql/views_lanl.sql` |

The audit events collected:

| Audit subcategory | Events |
|---|---|
| Logon (success + failure) | 4624, 4625, 4648 |
| Special Logon (success) | 4672 |
| Account Lockout (failure) | 4625 with lockout status |
| User Account Management (success + failure) | 4720, 4722–4726, 4738, 4740, 4767 |
| Security Group Management (success) | 4732, 4733 |
| (always on) | 1102 Security log cleared |

**Audit configuration evidence:** `Setup-AuditPolicy.ps1` saves `auditpol /get /category:*` to
`data/audit-evidence/`. Paste it here once captured:

```
(paste auditpol output)
```

## Running

### Sample database

```powershell
sqlite3 -header -column sample\sample.db "SELECT indicator, value, threshold, status FROM v_kri_summary;"
.\sample\New-SampleDatabase.ps1          # rebuild; deterministic (-Seed 42), runs the real LANL importer
```

### Part 1: collector in the VM

Build the VM with [VM_SETUP.md](VM_SETUP.md) (Hyper-V, about an hour). Run these as Administrator, **in the VM
only**. `Setup-AuditPolicy.ps1` and `Generate-Activity.ps1` refuse to run on a non-VM unless you pass `-Force`.

```powershell
Install-Module PSSQLite -Scope AllUsers            # AllUsers: the task runs as SYSTEM
.\collector\Setup-AuditPolicy.ps1 -SetLockoutPolicy # audit subcategories, 1 GB Security log, lockout policy
.\collector\collect.ps1 -Verbose                   # first run → %ProgramData%\IdentityAnalytics\identity.db
.\collector\Register-Task.ps1 -At 02:00            # collector, daily as SYSTEM
.\collector\Generate-Activity.ps1 -Action Setup    # test accounts and their starting state (safe to re-run)
.\collector\Register-Task.ps1 -Activity -At 12:00  # Generate-Activity -Action Daily, daily as SYSTEM
```

Then run the one-off steps in the [staged scenario](VM_SETUP.md#staged-scenario) (admin add and remove, lockouts,
disable, delete). The day after the last step (once the collector has loaded it), copy `identity.db` and `staged_activity.csv` to
`data/` on the host ([VM_SETUP.md](VM_SETUP.md) step 8).

### Part 2: LANL import

Download `auth.txt.gz` and `redteam.txt.gz` per [lanl/README.md](lanl/README.md), then on the host:

```powershell
.\lanl\Import-LanlSlice.ps1 -RedTeamPath D:\lanl\redteam.txt.gz -RedTeamOnly     # red-team events per day, to pick a slice
.\lanl\Import-LanlSlice.ps1 -AuthPath D:\lanl\auth.txt.gz -RedTeamPath D:\lanl\redteam.txt.gz -Database data\lanl.db
```

The defaults are baseline = day 7 and detection = day 8. Reaching the end of day 8 means streaming about 152M lines.
The real run took about 13 minutes on the project laptop. The importer prints its read rate every 5M lines, and runs
`views_lanl.sql` automatically after loading. Try `-BaselineDays 0 -DetectionDays 1` first: that window is at the start
of the file, so it finishes quickly.

### Part 3: Power BI

See [powerbi/README.md](powerbi/README.md). In short: create a 64-bit SQLite ODBC DSN pointing at the database, then
**Get Data → ODBC** and import the views and aggregate tables, never `auth_event` or `lanl_auth`.

## Schema reference

All tables are defined in `sql/schema.sql`. The same schema is used by the VM database, `data/lanl.db` and
`sample/sample.db`.

**Collector tables**

| Table | Grain | Source |
|---|---|---|
| `runs` | One row per collector run: start/finish, status, events loaded, high-water marks, log epoch, notes, error | The collector |
| `account_snapshot` | Account × run | `Get-LocalUser` (+ ADSI user flags) |
| `group_membership` | Group member × run, including orphaned SIDs | `Get-LocalGroupMember`, with ADSI fallback |
| `auth_event` | One row per 4624 / 4625 / 4648 / 4672, keyed on `(log_epoch, record_id)` | Security log |
| `account_change` | One row per 4720 / 4722–4726 / 4738 / 4740 / 4767 / 4732 / 4733 / 1102, keyed on `(log_epoch, record_id)` | Security log |
| `event_ref`, `logon_type_ref`, `status_code_ref`, `privileged_group` | Lookup tables | `schema.sql` |

**LANL tables**

| Table | Grain |
|---|---|
| `lanl_import_log` | One row per import: rows read / before window / in window / dropped / written / loaded, status |
| `lanl_window` | Baseline and detection time ranges |
| `lanl_auth` | Filtered logon events (millions of rows; don't import into Power BI) |
| `lanl_redteam` | All red-team events |
| `lanl_new_pairs` | User→computer pairs first seen in the detection window |
| `lanl_user_daily` | User × day aggregates |
| `lanl_computer_daily` | Destination computer × day: NTLM share, ANONYMOUS LOGON volume |
| `lanl_service_like` | Accounts that behave like services |
| `lanl_indicator_score` | Indicator × user: score, rank, red-team flag |
| `lanl_detection_eval` | Indicator × top-N: flagged, true/false positives, precision, recall, F1 |

**Views** (`views_local.sql`, `kri_summary.sql`)

| View | Logic |
|---|---|
| `v_reference_run` | The latest successful run; every view measures "now" from it |
| `v_account_latest` | Each account as of the reference run |
| `v_dormant_accounts` | Enabled, with no logon in more than 30 days (or never). Uses the newer of `LastLogon` and the last 4624 event |
| `v_privileged_accounts` | Members of admin-level groups (by well-known SID), with dormant and orphaned members flagged |
| `v_password_hygiene` | Never-expires, not-required, and age buckets 0–90 / 90–365 / 365+ |
| `v_auth_failures_daily` | 4625 by day, account, logon type and reason. Uses SubStatus when Status is the generic 0xC000006D |
| `v_lockouts` | One row per 4740, with the failures and minutes since the previous lockout or unlock |
| `v_privileged_group_changes` | 4732/4733 on admin groups, with the actor. Members are resolved by SID |
| `v_account_lifecycle` | Created / enabled / disabled / deleted / changed / locked / unlocked |
| `v_data_quality` | Orphaned SIDs, accounts with no description, events for accounts missing from the snapshot |
| `v_run_history` | Collector health |
| `v_kri_summary` | One row per KRI: value, threshold, status |

## Data reference

### KRI thresholds

| KRI | Status rule |
|---|---|
| Dormant privileged accounts, password not required, Security log cleared (30 days) | > 0 → red |
| Password never expires, passwords older than 365 days, orphaned SIDs, failed collector runs (14 days), privileged group changes (7 days) | > 0 → amber |
| Lockouts in last 7 days | > 3 → amber |
| LANL users with 5+ new computer pairs | > 10 → amber |
| LANL NTLM share of logons | > 5% → amber |
| Failed logons (7 days), LANL best F1 | Context only (`info`) |

Thresholds are defined in [sql/kri_summary.sql](sql/kri_summary.sql). The 7-day KRIs count back from the latest
successful run, so a scenario longer than 7 days never appears in one window; the event views keep the full history.

### Sample database contents

Built by [sample/New-SampleDatabase.ps1](sample/New-SampleDatabase.ps1). Fully synthetic and deterministic: the same
`-Seed` always produces the same database. The LANL half is written in the real LANL file format and loaded through
the real importer, so the sample exercises the production code path.

**Local half:** 21 daily runs (2–22 October 2026) for host `IDLAB-VM`, with 14 accounts, 515 authentication events
and 9 account changes:

| Account | Scenario | Expected finding |
|---|---|---|
| `labadmin` | Lab owner, daily admin logons | None (the normal case) |
| `jsmith`, `mjones`, `akim` | Regular users, weekday logons, occasional typos | Background failed-logon noise. `mjones` is disabled on day 13 |
| `helpdesk_tom` | Added to Administrators on day 4, removed on day 11 | Two privileged group changes by `labadmin` |
| `svc_backup` | Service logons around the clock, password never expires, password set 2025-11 | Password never expires |
| `svc_report` | Service account with no description | Data-quality issue |
| `temp_contractor` | Password not required; locked out twice (days 6 and 17) | Password not required (red), 2 lockouts |
| `old_pwd_carl` | Password last set 2025-03 | Password older than 365 days |
| `dormant_alice` | In Administrators, never logs on | **Dormant privileged account** (red) |
| `dormant_bob` | Never logs on; deleted on day 14 but left in Backup Operators, as a deleted domain account would be | Orphaned SID in a privileged group |
| *(nonexistent `admin`)* | Password-spray noise from 192.168.56.50 every third day | Failures for an unknown user |

Run 9 is recorded as **failed** (the VM was suspended), so the collector-health KRI has a real case to catch.

**LANL half:** 300 users across two days, 33,665 lines read and 18,349 kept. A red team of **6 users** moves laterally
to 8–20 never-seen computers each. Decoy groups make detection non-trivial:

| Decoy group | Behaviour | Indicator it fools |
|---|---|---|
| 8 admins | High fan-out every day, including the baseline | `fan_out` (not `new_pairs`, because the pairs aren't new) |
| 12 "movers" | Start using a few new servers on the detection day | `new_pairs` at larger N |
| 7 stale-password users | Bursts of failed NTLM logons | `failures`, `failure_burst` |
| 5 service accounts | Active all day; one logs on interactively | `service_interactive` |
| ~10% of users | Still on NTLM | `ntlm_logons` |

**Sample KRIs:**

| KRI | Value | Status | Cause |
|---|---|---|---|
| Dormant privileged accounts | 1 | 🔴 red | `dormant_alice` in Administrators, never logged on |
| Password not required | 1 | 🔴 red | `temp_contractor` |
| Password never expires | 1 | 🟠 amber | `svc_backup` |
| Passwords older than 365 days | 1 | 🟠 amber | `old_pwd_carl` (set 2025-03) |
| Orphaned SIDs in groups | 1 | 🟠 amber | Deleted `dormant_bob` still in Backup Operators |
| Failed collector runs (14 days) | 1 | 🟠 amber | Run 9 (VM suspended) |
| Lockouts in last 7 days | 1 | 🟢 green | `temp_contractor` on 18 Oct (below the threshold of 3) |
| Privileged group changes (7 days) | 0 | 🟢 green | `helpdesk_tom`'s changes on days 4 and 11 fall outside the window |
| Security log cleared (30 days) | 0 | 🟢 green | None |
| Failed logons in last 7 days | 23 | info | Typos, spraying and the lockout |
| LANL users with 5+ new pairs | 12 | 🟠 amber | 6 red team + 6 movers |
| LANL NTLM share | 10.37% | 🟠 amber | ~10% of synthetic users on NTLM |
| LANL best indicator F1 | 0.909 | info | `new_pairs` / `combined_risk` at N = 5 |

On the sample, `new_pairs` and `combined_risk` reach precision 1.0 and recall 0.83 at N = 5, and recall 1.0 at
N = 10. That's expected, because the synthetic red team is built to be findable.

### LANL slice

Baseline day 7, detection day 8 (why: [README → The data](README.md#the-data); per-day red-team counts:
[lanl/README.md](lanl/README.md#choosing-the-slice)). Each import records these counts in `lanl_import_log`:

| Step | Rows |
|---|---|
| Lines read (stopped at the end of day 8) | 152,468,275 |
| Before the window (days 0–6, skipped) | 113,699,303 |
| In the window (days 7–8) | 38,768,971 |
| Removed: not a logon (logoffs, Kerberos ticket requests) | 22,494,657 |
| Removed: computer accounts | 10,053,920 |
| **Kept for analysis** | **6,220,394** (3.12M baseline, 3.10M detection) |

### Lab VM run log

24 collector runs, 24 October – 17 November 2026, all `success`, at up to about 640 events per day. There was no 02:00
run on 1 November or 11 November (VM off or rebooting); the next run loaded the missed events both times.

The first 12 days showed that the staged daily activity only ran when started by hand, so the test accounts logged on
once and the scenario steps never happened. The activity was then made a scheduled task
([VM_SETUP.md](VM_SETUP.md#staged-scenario)), and the scenario was re-run on the same VM. Dates are local (UTC−8):

| Date (2026) | Step |
|---|---|
| 6 November | Day 0: starting state re-applied (new test-account passwords, password flags, dormant group members) |
| 6–7 November | No staged activity: the new SYSTEM task failed on start-up (`$PSScriptRoot` empty under `-File`; see [Is the staged activity running?](#is-the-staged-activity-running)) |
| 8 November | Daily activity running as a scheduled task. Day 1: `helpdesk_tom` added to Administrators, `temp_contractor` locked out |
| 9 November | Day 2: `mjones` disabled |
| 10–11 November | VM rebooted overnight for patching. Neither task ran on 11 November until started by hand that evening. No events were lost |
| 11 November | Day 3, a day late: `dormant_bob` deleted. Windows also removed it from Backup Operators (4733), so no orphaned SID was left |
| 15 November | Day 4, second lockout of `temp_contractor` (planned for 12 November). Day 7: temporary admin removed by a one-time SYSTEM task |
| 17 November | Last collector run; database exported |

## Testing with Pester

```powershell
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -SkipPublisherCheck
Invoke-Pester .\tests -Output Detailed
```

All 51 tests should pass in about 15 seconds, with no admin rights, VM or LANL download needed.

[Pester](https://pester.dev) is the standard test framework for PowerShell, much like pytest for Python or JUnit for
Java. A test file is an ordinary PowerShell script named `*.Tests.ps1`. `Invoke-Pester` finds and runs those files,
then reports each test as passed, failed or skipped.

### Why test this project

An identity KRI is only useful if people trust it. If `v_dormant_accounts` silently misses an account, or a rerun of
the collector double-counts failed logons, the dashboard looks fine but is wrong. Tests prove that each step gives
the right answer on inputs where the right answer is already known.

There's a practical reason too. The collector's real inputs (the Security log, local accounts) need admin rights and
a VM, and change all the time. The tests replace those inputs with fixed, hand-written ones. The logic can then be
checked on the laptop, in about 15 seconds, as often as you like.

### How a Pester test reads

```powershell
Describe 'Invoke-IdentityCollection' {          # a group of related tests
    BeforeEach {                                 # runs before every test in the group
        Mock -ModuleName IdentityCollector Get-LocalUser { <# fake accounts #> }
    }
    It 'loads only new events on the next run (incremental)' {   # one test
        $run = Invoke-IdentityCollection -Database $script:Db
        $run.events_loaded | Should -Be 1        # an assertion: the test fails if this is false
    }
}
```

| Pester feature | What it does | Where this project uses it |
|---|---|---|
| `Describe` / `Context` / `It` | Groups tests and names each one, so a failure says exactly what broke | One `Describe` per function or SQL view |
| `Should -Be`, `-BeNullOrEmpty`, `-Throw` … | Assertions: compare an actual value with the expected one | Row counts, field values, KRI statuses |
| `BeforeAll` / `BeforeEach` | Setup that runs once per group, or before each test | Load the module, build a fresh database |
| `Mock` | Replaces a real command with a fake that returns fixed data | `Get-LocalUser`, `Get-LocalGroupMember`, the Security-log reader |
| `Should -Invoke` | Checks that a mocked command was called, and with which parameters | Proves the second run asks only for events after record 104 |
| `$TestDrive` | A temporary folder that Pester deletes after the tests | Every collector test writes its own throwaway `.db` |
| `-Skip` | Skips a test when a condition isn't met, and reports it as skipped rather than failed | The LANL tests skip if the `sqlite3` CLI isn't installed |

**Mocking is what makes this testable.** The collector's logic lives in `IdentityCollector.psm1`, and every call to
Windows goes through a small wrapper (`Get-SecurityEventSince`, `Get-EventLogRecordRange`, `Get-UserFlags`). The tests
mock those wrappers to return saved event XML from `tests/fixtures/events/`. So the real parsing, loading and SQL all
run, but the Windows side is fake and predictable. For example, one test makes the log reader throw
`Access is denied` to check that the failed run is recorded properly. Another makes the oldest record in the log newer
than the last one stored, to check that rollover is detected.

### What the 51 tests cover

| File | Tests | What it proves | Input |
|---|---|---|---|
| `Parser.Tests.ps1` | 9 | Event XML for 4624 / 4625 / 4740 / 4732 / 1102 is parsed into the right fields, read by name not position. Placeholder values (`-`, empty, the null SID `S-1-0-0`) become NULL. NTSTATUS codes are upper-cased and padded (`0x0` → `0x00000000`). | Saved event XML in `tests/fixtures/events/` |
| `Collector.Tests.ps1` | 9 | A first run loads everything. A rerun loads only new events and never duplicates rows. An orphaned SID falls back to ADSI instead of crashing. A failed run is recorded as `failed`. Log rollover gets a `warning`. After a log clear, the log is reloaded from the start under a new epoch, including the 1102 event and an ID that collides with an old one, and a failed run doesn't make the same clear count twice. An old database is upgraded without losing rows. | Mocked Windows commands + fake event log |
| `ViewsLocal.Tests.ps1` | 23 | Every local view and the KRI summary return exactly the expected rows: who is dormant, who is privileged, failure reasons, lockout timing, data-quality issues, red/amber/green statuses | `tests/fixtures/local_fixture.sql`, a hand-built database with known answers |
| `Lanl.Tests.ps1` | 10 | End-to-end LANL import of a tiny gzip slice. Exact row counts at each step (read / in window / dropped / loaded), new user→computer pairs, and precision/recall against hand-calculated values | A generated mini `auth.txt.gz` / `redteam.txt.gz` |

The view tests run through PSSQLite, the same SQLite 3.8.8 engine the collector uses. A view that uses newer SQL
would pass in a modern `sqlite3` but break the collector, and these tests catch that.

### Useful commands

```powershell
Invoke-Pester .\tests -Output Detailed                            # every test, with names
Invoke-Pester .\tests\ViewsLocal.Tests.ps1                         # one file
Invoke-Pester .\tests -FullNameFilter '*incremental*'              # tests whose name matches
Import-Module Pester -MinimumVersion 5.5; Invoke-Pester .\tests   # if an old Pester 3.x is also installed
```

**CI.** [.github/workflows/ci.yml](.github/workflows/ci.yml) runs every test on `windows-latest` under both Windows
PowerShell 5.1 and PowerShell 7, on each push to `main` and each pull request. It installs Pester, PSSQLite and the
`sqlite3` CLI, so the LANL tests run instead of skipping. It then runs the README's quick-start query against
`sample.db` and uploads the test results.

Windows ships with Pester 3.4, which uses older syntax and can't run these tests. That's why the install command asks
for 5.5 or later, and `-SkipPublisherCheck` is needed to install it next to the built-in copy.

## Debugging and troubleshooting

### Is the collector running every day?

Check in this order, from the outside in:

```powershell
# Host (admin, or a member of Hyper-V Administrators): is the VM up?
Get-VM IDLAB-VM | Select-Object Name, State, Uptime

# VM: when did the task last run, and did it exit cleanly?
Get-ScheduledTaskInfo -TaskName IdentityAnalytics-Collect | Select-Object LastRunTime, LastTaskResult, NextRunTime

# VM: what did each run record? (sqlite3 isn't installed in the VM, so use PSSQLite)
Invoke-SqliteQuery -DataSource C:\ProgramData\IdentityAnalytics\identity.db `
  -Query 'SELECT run_id, started_at, status, events_loaded, notes, error FROM runs ORDER BY run_id' | Format-Table -AutoSize

# VM: the plain-text log
Get-Content C:\ProgramData\IdentityAnalytics\collect.log -Tail 20
```

**How to read them:**

- **`LastTaskResult` 0** means `collect.ps1` didn't throw. It does **not** rule out a `warning` run, which completes
  normally. Always check the `runs` table too.
- **`LastTaskResult` non-zero** means the run threw. The reason is in `collect.log` and in `runs.error`.
- **`started_at` is in UTC.** A 02:00 local task shows as 09:00 on a UTC-7 clock. After a daylight-saving change it
  shifts by an hour, and one gap between runs is 23 or 25 hours. That's harmless.
- **A missing day** usually means the VM was off or paused at 02:00. The task has `StartWhenAvailable`, so it runs
  when the VM next starts, and that run loads the missed events.
- **`Get-VM` says "You do not have the required permission"**: run it in an Administrator PowerShell, or add your
  account to the local *Hyper-V Administrators* group.

### Is the staged activity running?

The activity task writes nothing to a database. Its record is `data\activity\staged_activity.csv`, one row per action.
Check it in three layers: the log (the task ran and the logons succeeded), the Security log (Windows recorded them),
and `identity.db` (the collector loaded them).

```powershell
# VM: did the task run, and exit cleanly?
Get-ScheduledTaskInfo -TaskName IdentityAnalytics-Activity | Format-Table LastRunTime, LastTaskResult, NextRunTime

# VM: one row per day (UTC) of the staged log
Import-Csv C:\Lab\identity-analytics\data\activity\staged_activity.csv |
  Group-Object { $_.time_utc.Substring(0,10) } | Sort-Object Name | ForEach-Object {
    $logons = $_.Group | Where-Object action -eq 'logon'
    [pscustomobject]@{
      DayUtc   = $_.Name
      Logons   = @($logons).Count
      Accounts = ($logons.account | Sort-Object -Unique) -join ', '
      Other    = (($_.Group | Where-Object action -ne 'logon') | ForEach-Object { "$($_.action):$($_.account)" }) -join ', '
    } } | Format-Table -AutoSize -Wrap

# VM: the same accounts in the database, per day and event
Invoke-SqliteQuery -DataSource C:\ProgramData\IdentityAnalytics\identity.db -Query @"
SELECT substr(time_created,1,10) AS day, target_user, event_id, logon_type, COUNT(*) AS n
FROM auth_event
WHERE target_user IN ('jsmith','mjones','akim','helpdesk_tom','svc_backup','svc_report',
                      'temp_contractor','old_pwd_carl','dormant_alice','dormant_bob')
GROUP BY 1,2,3,4 ORDER BY 1,2
"@ | Format-Table -AutoSize
```

**How to read them:**

- **A normal day** has `logon` rows for jsmith, akim, helpdesk_tom, svc_backup and svc_report, and mjones until it's
  disabled. temp_contractor and old_pwd_carl sign in on about one day in four. dormant_alice and dormant_bob never
  do. Most days also have a `failed_logon` row.
- **A missing account on one day** means its logon failed. `Daily` only logs successful logons, so the usual causes
  are a lockout in progress or a stored password that no longer matches (re-run `-Action Setup`).
- **No rows at all for a day**, not even `failed_logon`, means the task didn't run or threw before signing anyone in.
  Check `LastTaskResult`, then run `Generate-Activity.ps1 -Action Daily` by hand.
- **Every `logon` row** should match at least one 4624 in `auth_event` (type 2 interactive, type 3 network) once the
  next collector run has loaded it. Typos show as 4625.

**It works by hand but the task returns 1.** Look at the end of the task's output log first:

```powershell
Get-Content C:\Lab\identity-analytics\data\activity\task.log -Tail 30          # activity task
Get-Content C:\ProgramData\IdentityAnalytics\task.log -Tail 30                  # collector task
```

`Register-Task.ps1` starts both tasks through `cmd.exe` and appends everything they print, errors included, to
`task.log`, with a `====` timestamp line per run. That also catches errors from before the script's own logging
starts, such as a parameter that won't bind. A task registered with an older `Register-Task.ps1` has no log: register
it again. Without a log, capture the output once with a throwaway SYSTEM task:

```powershell
$root = 'C:\Lab\identity-analytics'; $log = "$root\data\activity\task_debug.log"
$cmd  = '/c powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}\collector\Generate-Activity.ps1" -Action Daily > "{1}" 2>&1' -f $root, $log
Register-ScheduledTask -TaskName IA-Debug -Force `
  -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument $cmd -WorkingDirectory "$root\collector") `
  -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) | Out-Null
Start-ScheduledTask IA-Debug; Start-Sleep 30; Get-Content $log
Unregister-ScheduledTask IA-Debug -Confirm:$false; Remove-Item $log
```

This also runs `Daily` once more. That's harmless, because the extra activity is logged like any other.

### Run statuses

| `runs.status` | Meaning | What to do |
|---|---|---|
| `success` | Completed with no gaps detected | Nothing |
| `warning` | Completed, but `notes` reports a gap: events lost to log rollover (the oldest record is newer than the last stored mark), or the log was cleared or the VM restored to a checkpoint (the newest record is older than the mark) | Rollover: enlarge the Security log or run more often. Cleared: nothing is lost; the run starts a new `log_epoch` and reloads the log from the start. Check for event 1102, which is a finding in itself |
| `failed` | Threw an error, recorded in `runs.error`. Its partial snapshot is deleted | Fix the cause (below). The next run picks up from the last good high-water mark, so no events are lost |
| `running` (on an old row) | The process was killed before it finished: the 1-hour task limit, or the VM stopped mid-run | Usually nothing. The next run compares only against earlier `success` / `warning` runs |

### Common collector failures

| Symptom | Cause | Fix |
|---|---|---|
| `PSSQLite not found` in `collect.log`, but it works when you run it by hand | PSSQLite installed for CurrentUser; SYSTEM can't see your profile | `Install-Module PSSQLite -Scope AllUsers`. `Register-Task.ps1` warns about this |
| Task returns 1 with `Join-Path : Cannot bind argument to parameter 'Path' because it is an empty string`, but the script works by hand | An older copy of a script with a `$PSScriptRoot` path default in `param()`, which is empty under `powershell.exe -File` | Copy the current scripts into the VM (path defaults are now set in the script body) |
| `Access is denied` reading the Security log | Not running elevated | Run as Administrator, or let the SYSTEM task run it |
| Database won't open; errors about a missing function or bad syntax in a view | A view uses SQL newer than SQLite 3.8.8 (window functions, `IIF`, UPSERT). SQLite parses every view when a connection opens | Rewrite the view in 3.8.8 SQL. `ViewsLocal.Tests.ps1` runs through PSSQLite and catches this |
| Expected events missing (e.g. no 4740 lockouts) | Audit subcategory not enabled, or lockout policy not set | Rerun `Setup-AuditPolicy.ps1 -SetLockoutPolicy` and compare with `data/audit-evidence/` |
| Orphaned SID shows as a member with no name | Expected: the account was deleted while still in a group | Nothing; it's reported in `v_data_quality` |
| A KRI is unexpectedly green or `no data` | Views measure from the latest **successful** run. With no successful run, the source is empty | Check `v_reference_run` and `v_run_history` |

### LANL import

| Symptom | Cause | Fix |
|---|---|---|
| `lanl_import_log.status = 'failed'` | `rows_loaded` ≠ `rows_written`: the bulk load didn't load every CSV row | Check the `sqlite3` output and disk space, then rerun |
| `status = 'warning'` | The file ended before the window did: a truncated download, or a multi-member gzip that .NET Framework's `GZipStream` stops reading early | Re-download and check the file size, or decompress and recompress as a single member |
| `sqlite3` not found | The CLI isn't on PATH. The importer and `Lanl.Tests.ps1` both need it | Install it and add it to PATH. Existing shells need PATH reloaded |
| Very slow before any rows load | Expected: reaching day 7 means reading about 114M lines first | Watch the read rate printed every 5M lines. Test with `-BaselineDays 0 -DetectionDays 1` |

### Power BI

| Symptom | Cause | Fix |
|---|---|---|
| F1 shows as 1 instead of 0.909 | Power BI types each column from the first rows the driver reports | `v_kri_summary` casts `value` and `threshold` to REAL. Keep that cast in any new KRI |
| Import is slow or huge | Raw event tables imported | Import views and aggregate tables only, never `auth_event` or `lanl_auth` |

### Tests

| Symptom | Cause | Fix |
|---|---|---|
| Errors like `Should -Be` not recognised, or `-Output` not a parameter | Windows' built-in Pester 3.4 loaded instead of 5.x | `Import-Module Pester -MinimumVersion 5.5` before `Invoke-Pester` |
| `Lanl.Tests.ps1` reports tests skipped | `sqlite3` isn't on PATH | Install it; skipped is not failed |

## Repository layout

```
collector/  IdentityCollector.psm1 (logic), collect.ps1, Setup-AuditPolicy.ps1, Generate-Activity.ps1, Register-Task.ps1
lanl/       Import-LanlSlice.ps1, README.md
sql/        schema.sql, views_local.sql, views_lanl.sql, kri_summary.sql
tests/      Pester tests + fixtures (sample event XML, fixture database)
sample/     New-SampleDatabase.ps1, sample.db (synthetic)
powerbi/    dashboard notes (+ .pbix, screenshots)
report/     findings.md
data/       (git-ignored) VM database, LANL slice, staged-activity log, audit evidence
```

**Never committed:** the real VM database, `.evtx` exports, LANL data, or `data/`. Aggregate results such as the
detection table in the README are published, but no LANL records are.
