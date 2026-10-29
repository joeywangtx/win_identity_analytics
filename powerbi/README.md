# Power BI dashboard

`identity-dashboard.pbix` is built by hand in Power BI Desktop. This file lists what goes on each page and where the
data comes from, so the dashboard can be rebuilt. Add screenshots of each page to `powerbi/screenshots/` and link them
from the main README, because the `.pbix` can't be viewed without Power BI.

## Connect

1. Install Power BI Desktop and the **64-bit** SQLite ODBC driver (http://www.ch-werner.de/sqliteodbc/).
2. In *ODBC Data Sources (64-bit)*, add a System DSN with the SQLite3 driver, named `identity`, that points to the
   database. Start with `sample/sample.db`, then switch to your VM database.
3. Power BI: **Get Data → ODBC → identity**. Import only the views and aggregate tables below, never `auth_event`
   or `lanl_auth`.

## Tables to import

| Source | Used on |
|---|---|
| `v_kri_summary`, `v_run_history` | 1 Overview |
| `v_auth_failures_daily`, `v_lockouts` | 2 Authentication |
| `v_privileged_accounts`, `v_dormant_accounts`, `v_privileged_group_changes`, `v_password_hygiene`, `v_account_lifecycle`, `v_data_quality` | 3 Privileged access & hygiene |
| `lanl_user_daily`, `lanl_new_pairs`, `lanl_computer_daily`, `lanl_indicator_score` | 4 Enterprise (LANL) |
| `lanl_detection_eval` | 5 Detection results |

## Pages

| Page | Visuals |
|---|---|
| **1. Overview** | KRI cards from `v_kri_summary` with conditional formatting on `status` (red / amber / green, grey for info and no data). Account totals. Failure trend from `v_auth_failures_daily`. Collector health from `v_run_history`. |
| **2. Authentication (VM)** | Failures by day (stacked by `reason`), by `logon_type_name`, lockout timeline from `v_lockouts` with `minutes_to_lockout` in the tooltip |
| **3. Privileged access & hygiene (VM)** | Admin-group members table (highlight `is_dormant`, `is_orphaned`), group changes with actor, password `age_bucket` distribution, data-quality issue list |
| **4. Enterprise authentication (LANL)** | Fan-out histogram, top users by new pairs, NTLM share by computer, top-risk users from `lanl_indicator_score` (`indicator = 'combined_risk'`) with an `is_redteam` overlay |
| **5. Detection results (LANL)** | Precision/recall table per indicator, and a line chart of precision and recall vs `top_n` (slicer on indicator) showing the trade-off |

Use the same color meaning on every page: red = risk, amber = review, green = OK, grey = context. Add slicers for date
and account on pages 2–3.

## Gotcha

Power BI types each column from the driver's metadata. `v_kri_summary` casts `value` and `threshold` to REAL for this
reason. Without the cast, a column whose first row is an integer count can round later ratios such as F1 = 0.909 to 1.
