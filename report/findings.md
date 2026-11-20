# Identity Risk Findings

**Period:** 2026-10-24 – 2026-11-17 · **Sources:** lab VM `IDLAB-VM` (24 daily collector runs) · LANL auth slice
(baseline day 7, detection day 8)

Dates are local time on the VM (UTC−8). The database stores UTC, so an evening event has the next day's date in a
query. KRI values are as of the last collector run, 17 November 2026 at 01:00.

## Summary

1. **One dormant account has admin rights.** `dormant_alice` is in Administrators and has never signed in.
2. **The lab's own admin account allows an empty password.** `labadmin` was created by hand with the "password not
   required" flag, which nothing in the build checked. It is one of 2 accounts with the flag and 3 with a password
   that never expires.
3. **A disabled account kept being tried.** After `mjones` was disabled, it got 8 failed sign-ins over 7 days, all
   with reason "account disabled". Something still held its password.
4. **The temporary admin was removed on time, but by the machine itself.** The removal is attributed to `IDLAB-VM$`
   (a scheduled task running as SYSTEM), not a person. The 7-day KRI never showed the grant and the removal together.
5. **Deleting a local account cleans up its groups.** Deleting `dormant_bob` removed it from Backup Operators in the
   same second, so the expected orphaned SID never appeared. The deleted account is still visible through its
   events.
6. **The collector was reliable.** 24 of 24 runs succeeded and no events were lost. The two days without a 02:00 run
   were both caught up later.
7. **On LANL, lateral-movement indicators work and the rest are close to noise.** `fan_out` catches 19 of 45 red-team
   users in a list of 50 (F1 0.40). `combined_lateral` is 60% precise in a list of 20.

## Method

- **Local data:** Windows Security log (audit subcategories listed in ENGINEERING.md, evidence in
  `data/audit-evidence/`), plus `Get-LocalUser` / `Get-LocalGroupMember` snapshots. Collected daily by `collect.ps1`
  as SYSTEM: 24 runs, 10,548 authentication events and 134 account and group changes.
- **Staged vs organic:** all staged activity is listed in `data/activity/staged_activity.csv` (119 actions: 10
  account creations, 72 sign-ins, 9 typo batches, the scenario steps and the start-state fixes). Anything not in that
  file is organic (Windows itself, updates, and my own use of the VM).
- **Scenario** (staged, after a re-run of the start state on 6 November):

  | Date | Step | Events |
  |---|---|---|
  | 6 Nov | Start state: new test-account passwords, `dormant_alice` → Administrators, `dormant_bob` → Backup Operators | 4724, 4738, 4732 |
  | 8 Nov | `helpdesk_tom` → Administrators; `temp_contractor` locked out | 4732, 4740 |
  | 9 Nov | `mjones` disabled | 4725 |
  | 11 Nov | `dormant_bob` deleted (a day late) | 4726, 4733 × 2 |
  | 15 Nov | `helpdesk_tom` removed from Administrators; `temp_contractor` locked out again (3 days late) | 4733, 4740 |

  Daily sign-ins and typos ran every day from 8 November. On 11 November they ran in the evening, after a patch
  reboot.
- **LANL slice:** baseline day 7, detection day 8, LogOn orientation only, computer accounts dropped.
  Import log: 152,468,275 rows read / 38,768,971 in the window / 6,220,394 kept.
- **Detection measurement:** each indicator ranks users in the detection window. The top N (score > 0) are compared
  with the red-team users for that window.

## Lab VM KRIs

| KRI | Value | Status | Accounts | Staged or organic |
|---|---|---|---|---|
| Dormant privileged accounts | 1 | 🔴 red | `dormant_alice` | Staged |
| Password not required | 2 | 🔴 red | `temp_contractor`, `labadmin` | Staged, **organic** |
| Password never expires | 3 | 🟠 amber | `svc_backup`, `labadmin`, the owner's Microsoft account | Staged, **organic**, **organic** |
| Privileged group changes (7 days) | 2 | 🟠 amber | `dormant_bob` removed from Backup Operators, `helpdesk_tom` removed from Administrators | Staged |
| Lockouts (7 days) | 1 | 🟢 green | `temp_contractor` on 15 Nov (the 8 Nov lockout is outside the window) | Staged |
| Passwords older than 365 days | 0 | 🟢 green | — | Can't be staged on a new VM |
| Orphaned SIDs in groups | 0 | 🟢 green | — | See finding 5 |
| Security log cleared (30 days) | 0 | 🟢 green | — | — |
| Failed collector runs (14 days) | 0 | 🟢 green | — | — |
| Failed logons (7 days) | 22 | info | Typos, lockout attempts, the disabled account | 33 of 36 all-time failures are staged |

Every red and amber row traces back to a known account. Three of the six flagged accounts are organic: the staged
scenario surfaced real configuration problems on the VM itself.

## Findings

### 1. Dormant account with admin rights

- **Evidence:** `SELECT * FROM v_dormant_accounts` → `dormant_alice`, "never logged on". `v_privileged_accounts` shows
  it as an enabled member of Administrators with `is_dormant = 1`, next to two active admins (`labadmin` and the
  owner's account) and the disabled built-in Administrator.
- **Risk:** an unused admin account is a working credential that nobody watches. Its sign-ins wouldn't look out of
  place, because there is no normal behaviour to compare them with.
- **Recommendation:** disable `dormant_alice` and remove it from Administrators. Review admin-group membership monthly,
  and flag any member with no sign-in in 30 days.

### 2. The lab's own admin account allows an empty password

- **Evidence:** `SELECT name, pwd_required, pwd_never_expires FROM v_password_hygiene WHERE enabled = 1 AND
  (pwd_required = 0 OR pwd_never_expires = 1)` returns `labadmin` with both flags. Windows was set up with
  the owner's Microsoft account, and `labadmin` was added 25 minutes later with `New-LocalUser`
  ([VM_SETUP.md, step 4](../VM_SETUP.md#4-install-windows)): 4720 on 24 October, by the owner's account.
  It already had both flags at the first collector run, and nothing changed them afterwards. `New-LocalUser` sets
  "password not required" on every account it creates, which is also why the staged accounts needed a fix on
  6 November.
- **Risk:** the flag lets the password be set to blank, bypassing the password policy, on an account in
  Administrators. It's invisible in the Settings app and in `Get-LocalUser`'s default output.
- **Recommendation:** run `net user labadmin /passwordreq:yes`. Add a post-provisioning check for this flag to every
  account-creation script, because the default tooling sets it silently. `temp_contractor` (staged) needs the same fix.

### 3. Passwords that never expire

- **Evidence:** `v_password_hygiene`: `svc_backup` (staged), `labadmin` and the owner's Microsoft account (organic).
- **Risk:** a password that never changes stays valid after it leaks. This matters most for service accounts, whose
  passwords end up in scripts and configuration.
- **Recommendation:** move `svc_backup` to a managed service account with automatic rotation. Set an expiry on
  `labadmin`. The Microsoft account's password is managed online, so the local flag is expected. Record it as an
  accepted exception rather than a finding, so it doesn't keep the KRI amber.

### 4. A disabled account was still being used

- **Evidence:** `SELECT status_code, sub_status, COUNT(*) FROM auth_event WHERE event_id = 4625 AND target_user =
  'mjones' GROUP BY 1, 2` returns 8 failures with sub-status `0xC0000072` (account disabled), one per daily run from
  10 to 16 November, plus 2 wrong-password typos. The source is the daily activity task, which still signs `mjones` in.
- **Risk:** on a real system, this pattern means a script, service, mapped drive or person still holds the leaver's
  password. If the account is ever re-enabled, that access returns. The failures look like ordinary noise in the
  7-day failed-logon count.
- **Recommendation:** alert on any 4625 with sub-status `0xC0000072`. It's rare and specific, unlike general failure
  counts. Find the source (process, logon type, source address) and remove the stored credential.

### 5. The temporary admin: removed on time, but by the machine

- **Evidence:** `SELECT * FROM v_privileged_group_changes`: `helpdesk_tom` added to Administrators on 8 November by
  `labadmin` and removed on 15 November by `IDLAB-VM$`. Its successful sign-ins confirm both changes independently:
  one 4624 per sign-in before and after, and two while it was an admin (Windows gives an admin a full-rights and a
  limited session).
- **Risk:** a change attributed to the computer account has no accountable person. On 17 November the 7-day KRI shows
  the removal but not the grant, so nobody looking only at the KRI would see a full week of admin rights.
- **Recommendation:** alert on each privileged group change when it happens, and match it to a ticket. Have automated
  changes run under a named service identity, and log which task made them.

### 6. Deleted accounts don't leave orphaned SIDs locally

- **Evidence:** `account_change` has the 4726 (deleted) for `dormant_bob` and, in the same second, 4733 removals from
  Backup Operators and Users. `v_data_quality` reports `dormant_bob` and the Windows Setup account `defaultuser0`
  (created, disabled and deleted on 24 October) as `event_user_not_in_snapshot`: accounts with events but no longer
  present.
- **Risk:** low on a standalone machine. Windows removes a local account from local groups when it's deleted. The
  orphaned-SID case in the sample database comes from domain or cloud accounts deleted elsewhere, which this VM
  doesn't have.
- **Recommendation:** keep the orphaned-SID KRI for domain-joined machines. Locally, use the 4726 + 4733 trail and
  `event_user_not_in_snapshot` to audit deletions.

### 7. Lockouts: fast, below the threshold

- **Evidence:** `SELECT * FROM v_lockouts`: two lockouts of `temp_contractor`, each after 6 network failures (logon
  type 3) in under a minute. Each burst also produced one `0xC0000234` (account locked) failure.
- **Risk:** six failures in seconds looks like a script or brute force, not a person mistyping. Two lockouts in a
  week stay green under the "more than 3" threshold, so speed tells more than count.
- **Recommendation:** add `minutes_to_lockout` to the lockout alert, and treat sub-minute lockouts as suspected
  guessing.

### 8. Collector health and organic noise

- **Evidence:** `SELECT * FROM v_run_history`: 24 runs, all `success`, no gap notes, no 1102 (log cleared). There was
  no 02:00 run on 1 November or on 11 November. The VM was off or rebooting, and the next run loaded the missed events
  each time. Of 5,251 successful sign-ins, 5,070 (97%) are Windows service sign-ins (logon type 5) and 74 (1.4%) are
  staged. My own remote sessions into the VM appear as remote-desktop sign-ins (type 10).
- **Risk:** a KRI is only as good as the run behind it. Most of the log is routine Windows activity, so raw volumes
  say little.
- **Recommendation:** alert on a missed run on the same day. Set the VM to start with the host. Filter service
  sign-ins out before any per-user analysis.

### LANL detection results

Best N per indicator, by F1. 45 red-team users among about 16,000 active users (base rate 0.28%):

| Indicator | Best top-N | Precision | Recall | F1 |
|---|---|---|---|---|
| `fan_out` | 50 | 0.38 | 0.42 | 0.40 |
| `combined_lateral` | 20 | 0.60 | 0.27 | 0.37 |
| `new_pairs` | 20 | 0.50 | 0.22 | 0.31 |
| `combined_risk` | 20 | 0.40 | 0.18 | 0.25 |
| `service_interactive` | 50 | 0.10 | 0.11 | 0.11 |
| `failure_burst` | 100 | 0.07 | 0.16 | 0.10 |
| `failures` | 250 | 0.05 | 0.29 | 0.09 |
| `rare_logon_types` | 250 | 0.04 | 0.20 | 0.06 |
| `ntlm_logons` | 10 | 0.10 | 0.02 | 0.04 |

**Threshold for an IAM team:** `combined_lateral` at N = 20 as the daily queue. Twelve of 20 alerts are real, which a
small team can review in a day. Add `fan_out` at N = 50 as a weekly sweep to reach 42% recall. Larger lists add
alerts much faster than they add attackers, and the failure and NTLM indicators shouldn't drive alerts on their own.

## Limitations

- **Single VM, mostly staged activity.** One standalone machine, with a scripted scenario and one regular user. Real
  environments have far more noise.
- **The scenario ran late and long.** It took 8 days (8–15 November), so no single 7-day KRI window holds all of it;
  the event views do. The first attempt (24 October – 6 November) produced only one day of sign-ins, because the
  daily activity wasn't scheduled. 6 and 7 November have no staged activity, because the new SYSTEM task failed on
  start-up.
- **Thin occasional-user data.** `temp_contractor` and `old_pwd_carl` signed in once each, against about three
  expected each by chance.
- **Untestable KRIs.** A new VM can't produce a password older than 365 days or a local orphaned SID. Those KRIs
  are only exercised by the sample database.
- **LANL labels are incomplete,** so some "false positives" may be real anomalies that weren't labelled.
- **Narrow LANL window.** Results depend on the chosen window. One detection day isn't a long-term evaluation.
- **No domain or cloud identity.** No Active Directory or Entra ID: domain events (4768/4769/4771) and cloud sign-ins
  are out of scope.
