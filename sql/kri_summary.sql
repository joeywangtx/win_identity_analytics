-- One row per key risk indicator for the Power BI Overview page.
-- status: red | amber | green, 'info' for context metrics, 'no data' when the source is empty.
-- Thresholds live here, in one place, so they are easy to review and change.
-- SQLite 3.8.8 compatible.
--
-- value/threshold are CAST to REAL: ADO.NET and ODBC clients type a computed column from its
-- first row, so without the cast a leading integer count makes later ratios round to 0 or 1.

DROP VIEW IF EXISTS v_kri_summary;
CREATE VIEW v_kri_summary AS
SELECT k.indicator, k.part,
       CAST(k.value AS REAL) AS value,
       CAST(k.threshold AS REAL) AS threshold,
       CASE
         WHEN k.value IS NULL THEN 'no data'
         WHEN k.severity = 'info' THEN 'info'
         WHEN k.value > k.threshold THEN k.severity
         ELSE 'green'
       END AS status,
       k.description
FROM (
  SELECT 'Dormant privileged accounts' AS indicator, 'local' AS part,
         (SELECT COUNT(DISTINCT member_sid) FROM v_privileged_accounts WHERE is_dormant = 1) AS value,
         0 AS threshold, 'red' AS severity,
         'Enabled admin-level members with no logon in 30+ days' AS description
  UNION ALL
  SELECT 'Lockouts in last 7 days', 'local',
         (SELECT COUNT(*) FROM v_lockouts, v_reference_run r
           WHERE lockout_time > datetime(r.ref_time, '-7 days')),
         3, 'amber', 'Account lockouts (4740) in the 7 days before the latest run'
  UNION ALL
  SELECT 'Password never expires', 'local',
         (SELECT COUNT(*) FROM v_password_hygiene WHERE enabled = 1 AND pwd_never_expires = 1),
         0, 'amber', 'Enabled accounts with password-never-expires set'
  UNION ALL
  SELECT 'Password not required', 'local',
         (SELECT COUNT(*) FROM v_password_hygiene WHERE enabled = 1 AND pwd_required = 0),
         0, 'red', 'Enabled accounts allowed to have an empty password'
  UNION ALL
  SELECT 'Passwords older than 365 days', 'local',
         (SELECT COUNT(*) FROM v_password_hygiene WHERE enabled = 1 AND age_bucket = '365+'),
         0, 'amber', 'Enabled accounts whose password is a year old or more'
  UNION ALL
  SELECT 'Privileged group changes in last 7 days', 'local',
         (SELECT COUNT(*) FROM v_privileged_group_changes, v_reference_run r
           WHERE time_created > datetime(r.ref_time, '-7 days')),
         0, 'amber', 'Additions/removals to admin-level groups; each should match a change ticket'
  UNION ALL
  SELECT 'Orphaned SIDs in groups', 'local',
         (SELECT COUNT(*) FROM v_data_quality WHERE issue = 'orphaned_sid'),
         0, 'amber', 'Group members whose SID no longer resolves'
  UNION ALL
  SELECT 'Security log cleared (30 days)', 'local',
         (SELECT COUNT(*) FROM account_change, v_reference_run r
           WHERE event_id = 1102 AND time_created > datetime(r.ref_time, '-30 days')),
         0, 'red', 'Event 1102: someone cleared the audit trail'
  UNION ALL
  SELECT 'Failed collector runs (14 days)', 'local',
         (SELECT COUNT(*) FROM runs, v_reference_run r
           WHERE runs.status = 'failed' AND runs.started_at > datetime(r.ref_time, '-14 days')),
         0, 'amber', 'Collector runs that did not complete; data may be missing'
  UNION ALL
  SELECT 'Failed logons in last 7 days', 'local',
         (SELECT COUNT(*) FROM auth_event, v_reference_run r
           WHERE event_id = 4625 AND time_created > datetime(r.ref_time, '-7 days')),
         NULL, 'info', 'Context: total 4625 events'
  UNION ALL
  SELECT 'LANL users with new computer pairs (>= 5)', 'lanl',
         (SELECT CASE WHEN COUNT(*) = 0 THEN NULL ELSE SUM(CASE WHEN d.new_pairs >= 5 THEN 1 ELSE 0 END) END
            FROM lanl_user_daily d WHERE d.window_name = 'detection'),
         10, 'amber', 'Users reaching 5+ computers in the detection window never seen in the baseline'
  UNION ALL
  SELECT 'LANL NTLM share of logons (%)', 'lanl',
         (SELECT ROUND(100.0 * SUM(ntlm_logons) / SUM(logons), 2)
            FROM lanl_user_daily WHERE window_name = 'detection'),
         5, 'amber', 'NTLM instead of Kerberos, detection window'
  UNION ALL
  SELECT 'LANL best indicator F1', 'lanl',
         (SELECT ROUND(MAX(f1), 3) FROM lanl_detection_eval),
         NULL, 'info', 'Best F1 against red-team labels across indicators and top-N cutoffs'
) k;
