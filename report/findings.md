# Identity Risk Findings

> **Template.** Fill this in from your own VM and LANL runs. Every number must come from a query you can show,
> and every finding needs evidence and a recommendation. Delete this note when done. Export to `findings.pdf`.

**Period:** _YYYY-MM-DD – YYYY-MM-DD_ · **Sources:** lab VM `IDLAB-VM` (N daily collector runs) · LANL auth slice (days 7–8)

## Summary

1. _Finding in one plain sentence, with its number._
2. …
3. …

## Method

- **Local data:** Windows Security log (audit subcategories listed in ENGINEERING.md, evidence in `data/audit-evidence/`),
  `Get-LocalUser` / `Get-LocalGroupMember` snapshots, collected daily by `collect.ps1` as SYSTEM.
- **Staged vs organic:** all staged activity is listed in `data/activity/staged_activity.csv` (N actions). Anything
  not in that file is organic (Windows itself, updates, my own use of the VM).
- **LANL slice:** baseline day 7, detection day 8, LogOn orientation only, computer accounts dropped.
  Import log: N rows read / N in window / N loaded.
- **Detection measurement:** each indicator ranks users in the detection window. The top N (score > 0) are compared
  with the red-team users for that window.

## Findings

### 1. _Title_ (e.g. Dormant account with admin rights)

- **Evidence:** _query + number, or chart reference_ (`SELECT * FROM v_privileged_accounts WHERE is_dormant = 1`)
- **Risk:** _why it matters_
- **Recommendation:** _specific action, e.g. "disable dormant_alice and remove it from Administrators"_

### 2. …

### LANL detection results

| Indicator | Best top-N | Precision | Recall | F1 |
|---|---|---|---|---|
| | | | | |

_Which threshold you would choose for an IAM team, and why (alert volume vs missed compromises)._

## Limitations

- Single VM with mostly staged activity. Real environments have far more noise.
- Red-team labels are incomplete, so some "false positives" may be real anomalies that weren't labelled.
- Results depend on the chosen window. One detection day isn't a long-term evaluation.
- No Active Directory or Entra ID: domain events (4768/4769/4771) and cloud sign-ins are out of scope.
