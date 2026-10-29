# LANL data

This part uses the **Comprehensive, Multi-Source Cyber-Security Events** dataset from Los Alamos National Laboratory:
<https://csr.lanl.gov/data/cyber1/>

> A. D. Kent, "Comprehensive, Multi-Source Cyber-Security Events," Los Alamos National Laboratory, 2015. http://dx.doi.org/10.17021/1179829

LANL has released the dataset under CC0 (public domain), but **none of it is committed to this repo**: `auth.txt.gz`
alone is 7.2 GB, and anyone can download it from LANL. `.gitignore` excludes `*.gz`, `*.csv` and `data/`.

## Files needed

| File | Size | Format |
|---|---|---|
| `auth.txt.gz` | several GB compressed, 1B+ lines | `time,src user@domain,dst user@domain,src computer,dst computer,auth type,logon type,auth orientation,success/failure` |
| `redteam.txt.gz` | ~5 KB, 749 lines | `time,user@domain,src computer,dst computer` |

- `time` is seconds from the start of the dataset, not a date. Day index = `time / 86400`.
- Computer accounts end in `$` (`C625$@DOM1`). `?` means unknown.
- The file is sorted by time, which is why the importer can stop reading at the end of the window.

## Choosing the slice

```powershell
.\Import-LanlSlice.ps1 -RedTeamPath D:\lanl\redteam.txt.gz -RedTeamOnly
```

Red-team events per day in `redteam.txt.gz`:

| Day | Events | Users |
|---|---|---|
| 1, 2, 5, 6 | 10, 15, 21, 3 | 4, 2, 4, 2 |
| 7 | 1 | 1 |
| **8** | **273** | **45** |
| 9 | 15 | 1 |
| 12 | 209 | 39 |
| 13–15 | 81, 35, 26 | 22, 13, 14 |
| 20–29 | 60 in total | |

**Chosen:** baseline = day 7 (1 red-team event, close to clean), detection = day 8 (the busiest red-team day,
45 labeled users). These are the script defaults. An alternative pair is baseline 11, detection 12–13.

## Import

```powershell
.\Import-LanlSlice.ps1 -AuthPath D:\lanl\auth.txt.gz -RedTeamPath D:\lanl\redteam.txt.gz `
    -BaselineDays 7 -DetectionDays 8 -Database ..\data\lanl.db
```

You need the `sqlite3` CLI on PATH for the `.import` bulk load. Reaching day 7 means reading every line before it
(roughly 100M+ lines). The importer prints its read rate every 5M lines, so you can estimate how long the run will take.
Test with `-BaselineDays 0 -DetectionDays 1` first, since that window is at the start of the file.

**Filtering decisions** (recorded per import in `lanl_import_log`):

- Only the `LogOn` orientation is kept. `LogOff` repeats each session, and `TGS`/`TGT`/`AuthMap` are Kerberos
  ticket operations, not new logons. Keeping them would inflate every count. `-KeepAllOrientations` keeps them,
  but the SQL still analyses `LogOn` only.
- Computer accounts (`$`) are dropped for user-focused analysis. The count of dropped rows is recorded.
- `ANONYMOUS LOGON` is kept. It gets its own per-computer view and is excluded from user scoring.

If `rows_loaded` ≠ `rows_written`, the import is marked `failed`. If the file ends before the window does, the import is
marked `warning`. That can happen with a truncated download, or with a multi-member gzip that .NET Framework's
GZipStream stops reading early.
