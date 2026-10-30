-- Part 1 identity views over the local collector tables.
-- Must stay SQLite 3.8.8 compatible (no window functions, IIF, FILTER, UPSERT).
--
-- "Now" is the start time of the latest completed run, not the wall clock. That keeps
-- results reproducible: re-opening an old database or sample.db gives the same answers.

DROP VIEW IF EXISTS v_reference_run;
CREATE VIEW v_reference_run AS
SELECT run_id, started_at AS ref_time
FROM runs
WHERE status IN ('success', 'warning')
ORDER BY run_id DESC
LIMIT 1;

-- Latest account snapshot, plus the most recent successful logon seen in the event log.
-- Get-LocalUser's LastLogon can lag or be empty, so both sources are combined.
DROP VIEW IF EXISTS v_account_latest;
CREATE VIEW v_account_latest AS
SELECT a.sid, a.name, a.enabled, a.description,
       a.pwd_last_set, a.pwd_never_expires, a.pwd_required,
       a.last_logon,
       e.last_event_logon,
       CASE
         WHEN a.last_logon IS NULL THEN e.last_event_logon
         WHEN e.last_event_logon IS NULL THEN a.last_logon
         WHEN a.last_logon > e.last_event_logon THEN a.last_logon
         ELSE e.last_event_logon
       END AS last_activity,
       r.ref_time
FROM account_snapshot a
JOIN v_reference_run r ON r.run_id = a.run_id
LEFT JOIN (
  SELECT target_sid, MAX(time_created) AS last_event_logon
  FROM auth_event
  WHERE event_id = 4624
  GROUP BY target_sid
) e ON e.target_sid = a.sid;

DROP VIEW IF EXISTS v_dormant_accounts;
CREATE VIEW v_dormant_accounts AS
SELECT sid, name, last_logon, last_event_logon, last_activity,
       CAST(julianday(ref_time) - julianday(last_activity) AS INTEGER) AS days_inactive,
       CASE WHEN last_activity IS NULL THEN 'never logged on' ELSE 'inactive > 30 days' END AS reason
FROM v_account_latest
WHERE enabled = 1
  AND (last_activity IS NULL OR julianday(ref_time) - julianday(last_activity) > 30);

DROP VIEW IF EXISTS v_privileged_accounts;
CREATE VIEW v_privileged_accounts AS
SELECT pg.label AS privileged_group,
       gm.group_name,
       gm.member_sid,
       COALESCE(gm.member_name, gm.member_sid) AS member_name,
       gm.member_source,
       a.enabled,
       a.last_activity,
       CASE WHEN d.sid IS NOT NULL THEN 1 ELSE 0 END AS is_dormant,
       CASE WHEN gm.member_source = 'Orphaned' THEN 1 ELSE 0 END AS is_orphaned,
       CASE WHEN a.sid IS NOT NULL THEN 1 ELSE 0 END AS is_local_account
FROM group_membership gm
JOIN v_reference_run r ON r.run_id = gm.run_id
JOIN privileged_group pg ON pg.group_sid = gm.group_sid
LEFT JOIN v_account_latest a ON a.sid = gm.member_sid
LEFT JOIN v_dormant_accounts d ON d.sid = gm.member_sid;

DROP VIEW IF EXISTS v_password_hygiene;
CREATE VIEW v_password_hygiene AS
SELECT sid, name, enabled, pwd_last_set, pwd_never_expires, pwd_required,
       CAST(julianday(ref_time) - julianday(pwd_last_set) AS INTEGER) AS pwd_age_days,
       CASE
         WHEN pwd_last_set IS NULL THEN 'never set'
         WHEN julianday(ref_time) - julianday(pwd_last_set) < 90 THEN '0-90'
         WHEN julianday(ref_time) - julianday(pwd_last_set) < 365 THEN '90-365'
         ELSE '365+'
       END AS age_bucket,
       CASE WHEN pwd_never_expires = 1 OR pwd_required = 0
                 OR pwd_last_set IS NULL
                 OR julianday(ref_time) - julianday(pwd_last_set) >= 365
            THEN 1 ELSE 0 END AS has_issue
FROM v_account_latest;

-- 4625 Status is often the generic 0xC000006D; the SubStatus carries the real reason.
DROP VIEW IF EXISTS v_auth_failures_daily;
CREATE VIEW v_auth_failures_daily AS
SELECT x.day, x.target_user, x.logon_type, x.logon_type_name, x.reason_code,
       COALESCE(sc.label, 'Other') AS reason,
       COUNT(*) AS failures
FROM (
  SELECT date(f.time_created) AS day,
         f.target_user,
         f.logon_type,
         COALESCE(lt.label, 'Unknown') AS logon_type_name,
         CASE WHEN f.status_code = '0xC000006D' AND f.sub_status IS NOT NULL
                   AND f.sub_status <> '0x00000000'
              THEN f.sub_status ELSE f.status_code END AS reason_code
  FROM auth_event f
  LEFT JOIN logon_type_ref lt ON lt.logon_type = f.logon_type
  WHERE f.event_id = 4625
) x
LEFT JOIN status_code_ref sc ON sc.status_code = x.reason_code
GROUP BY x.day, x.target_user, x.logon_type, x.logon_type_name, x.reason_code, sc.label;

-- One row per lockout (4740). Failures are counted back to the previous lockout/unlock
-- of the same account, capped at 24 hours.
DROP VIEW IF EXISTS v_lockouts;
CREATE VIEW v_lockouts AS
SELECT log_epoch, record_id, lockout_time, date(lockout_time) AS day, account, actor,
       first_failure, failures_before_lockout,
       ROUND((julianday(lockout_time) - julianday(first_failure)) * 1440, 1) AS minutes_to_lockout
FROM (
  SELECT l.log_epoch, l.record_id, l.time_created AS lockout_time, l.target_user AS account, l.actor,
         (SELECT MIN(f.time_created) FROM auth_event f
           WHERE f.event_id = 4625 AND lower(f.target_user) = lower(l.target_user)
             AND f.time_created <= l.time_created
             AND f.time_created > COALESCE(
                   (SELECT MAX(p.time_created) FROM account_change p
                     WHERE p.event_id IN (4740, 4767) AND lower(p.target_user) = lower(l.target_user)
                       AND p.time_created < l.time_created
                       AND p.time_created > datetime(l.time_created, '-1 day')),
                   datetime(l.time_created, '-1 day'))) AS first_failure,
         (SELECT COUNT(*) FROM auth_event f
           WHERE f.event_id = 4625 AND lower(f.target_user) = lower(l.target_user)
             AND f.time_created <= l.time_created
             AND f.time_created > COALESCE(
                   (SELECT MAX(p.time_created) FROM account_change p
                     WHERE p.event_id IN (4740, 4767) AND lower(p.target_user) = lower(l.target_user)
                       AND p.time_created < l.time_created
                       AND p.time_created > datetime(l.time_created, '-1 day')),
                   datetime(l.time_created, '-1 day'))) AS failures_before_lockout
  FROM account_change l
  WHERE l.event_id = 4740
);

-- 4732/4733 log local members as '-' in MemberName, so fall back to the snapshot by SID.
DROP VIEW IF EXISTS v_privileged_group_changes;
CREATE VIEW v_privileged_group_changes AS
SELECT c.log_epoch, c.record_id, c.time_created, date(c.time_created) AS day,
       CASE c.event_id WHEN 4732 THEN 'added' ELSE 'removed' END AS action,
       pg.label AS privileged_group,
       c.group_name,
       COALESCE(c.target_user,
                (SELECT s.name FROM account_snapshot s WHERE s.sid = c.target_sid
                  ORDER BY s.run_id DESC LIMIT 1),
                c.target_sid) AS member,
       c.target_sid AS member_sid,
       c.actor
FROM account_change c
JOIN privileged_group pg ON pg.group_sid = c.group_sid
WHERE c.event_id IN (4732, 4733);

DROP VIEW IF EXISTS v_account_lifecycle;
CREATE VIEW v_account_lifecycle AS
SELECT c.log_epoch, c.record_id, c.time_created, date(c.time_created) AS day, c.event_id,
       er.label AS action,
       COALESCE(c.target_user, c.target_sid) AS account,
       c.target_sid,
       c.actor
FROM account_change c
JOIN event_ref er ON er.event_id = c.event_id
WHERE er.category IN ('lifecycle', 'lockout');

DROP VIEW IF EXISTS v_data_quality;
CREATE VIEW v_data_quality AS
SELECT 'orphaned_sid' AS issue, gm.member_sid AS object,
       'Unresolvable SID in group ' || gm.group_name AS detail
FROM group_membership gm
JOIN v_reference_run r ON r.run_id = gm.run_id
WHERE gm.member_source = 'Orphaned'
UNION ALL
SELECT 'missing_description', name, 'Enabled account has no description'
FROM v_account_latest
WHERE enabled = 1 AND (description IS NULL OR trim(description) = '')
UNION ALL
-- Domain-style SIDs (S-1-5-21-*) with events but absent from the latest snapshot:
-- deleted accounts that still had activity, or accounts from another source.
SELECT 'event_user_not_in_snapshot', ev.sid,
       ev.events || ' events, last ' || ev.last_seen || COALESCE(' as ' || ev.last_name, '')
FROM (
  SELECT sid, COUNT(*) AS events, MAX(time_created) AS last_seen, MAX(name) AS last_name
  FROM (
    SELECT target_sid AS sid, time_created, target_user AS name FROM auth_event
    UNION ALL
    SELECT target_sid, time_created, target_user FROM account_change
    WHERE event_id NOT IN (4732, 4733)
  )
  WHERE sid LIKE 'S-1-5-21-%'
  GROUP BY sid
) ev
WHERE ev.sid NOT IN (SELECT sid FROM v_account_latest);

-- Collector health, for the Overview page.
DROP VIEW IF EXISTS v_run_history;
CREATE VIEW v_run_history AS
SELECT run_id, started_at, date(started_at) AS day, finished_at, host,
       events_loaded, accounts, group_members, status, notes, error, COALESCE(log_epoch, 0) AS log_epoch,
       ROUND((julianday(finished_at) - julianday(started_at)) * 86400, 1) AS duration_sec
FROM runs;
