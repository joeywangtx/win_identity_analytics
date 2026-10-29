-- Part 2 indicators over the LANL slice. Run with the sqlite3 CLI (3.25+, window functions):
--   sqlite3 lanl.db < sql/views_lanl.sql
-- Import-LanlSlice.ps1 runs this automatically after loading.
--
-- Results are written into plain tables (defined in schema.sql) rather than persistent
-- views, so older SQLite builds (PSSQLite 3.8.8, the ODBC driver) can read them and Power BI
-- imports thousands of aggregate rows instead of millions of events.
--
-- Conventions
--   * day = time / 86400 (dataset day index; time is seconds from dataset start).
--   * Only LogOn orientation is analysed, even if the import kept other orientations.
--   * Windows come from lanl_window; end_time is exclusive.
--   * Red-team labels = distinct users in lanl_redteam during the detection window.

BEGIN;

-- Logon events inside an analysis window. TEMP objects are never stored in the file.
DROP VIEW IF EXISTS temp.wa;
CREATE TEMP VIEW wa AS
SELECT a.time, a.time / 86400 AS day, a.time / 3600 AS hour, w.window_name,
       a.src_user, a.dst_user, a.src_computer, a.dst_computer,
       a.auth_type, a.logon_type, a.outcome
FROM lanl_auth a
JOIN lanl_window w ON a.time >= w.start_time AND a.time < w.end_time
WHERE a.orientation = 'LogOn';

DROP TABLE IF EXISTS temp.labels;
CREATE TEMP TABLE labels AS
SELECT DISTINCT r.user
FROM lanl_redteam r
JOIN lanl_window w ON w.window_name = 'detection'
WHERE r.time >= w.start_time AND r.time < w.end_time;

-- New user -> computer pairs ------------------------------------------------
-- Distinct baseline pairs go into a keyed temp table so the anti-join is one index probe
-- per detection pair rather than a scan of the event table.
DROP TABLE IF EXISTS temp.base_pairs;
CREATE TEMP TABLE base_pairs (
  src_user TEXT, dst_computer TEXT, PRIMARY KEY (src_user, dst_computer)
) WITHOUT ROWID;
INSERT OR IGNORE INTO base_pairs
SELECT src_user, dst_computer FROM wa WHERE window_name = 'baseline';

DELETE FROM lanl_new_pairs;
INSERT INTO lanl_new_pairs (user, dst_computer, first_time, logons, is_redteam_pair)
SELECT d.src_user, d.dst_computer, d.first_time, d.logons,
       EXISTS (SELECT 1 FROM lanl_redteam r, lanl_window w
                WHERE w.window_name = 'detection'
                  AND r.time >= w.start_time AND r.time < w.end_time
                  AND r.user = d.src_user AND r.dst_computer = d.dst_computer)
FROM (
  SELECT src_user, dst_computer, MIN(time) AS first_time, COUNT(*) AS logons
  FROM wa WHERE window_name = 'detection'
  GROUP BY src_user, dst_computer
) d
LEFT JOIN base_pairs b ON b.src_user = d.src_user AND b.dst_computer = d.dst_computer
WHERE b.src_user IS NULL;

-- Per user, per day ---------------------------------------------------------
DELETE FROM lanl_user_daily;
WITH hourly AS (
  SELECT src_user, day, hour, SUM(outcome = 'Fail') AS fails
  FROM wa GROUP BY src_user, day, hour
),
burst AS (
  SELECT src_user, day, MAX(fails) AS max_fails FROM hourly GROUP BY src_user, day
),
np AS (
  SELECT user, first_time / 86400 AS day, COUNT(*) AS n FROM lanl_new_pairs GROUP BY user, day
)
INSERT INTO lanl_user_daily
SELECT u.src_user, u.day, u.window_name, u.logons, u.failures,
       ROUND(1.0 * u.failures / u.logons, 4),
       b.max_fails, u.fan_out, u.src_computers, u.ntlm,
       ROUND(1.0 * u.ntlm / u.logons, 4),
       u.interactive, u.remote_interactive, u.network_cleartext,
       CASE WHEN u.window_name = 'detection' THEN COALESCE(np.n, 0) END,
       u.src_user IN (SELECT user FROM labels)
FROM (
  SELECT src_user, day, window_name,
         COUNT(*) AS logons,
         SUM(outcome = 'Fail') AS failures,
         COUNT(DISTINCT dst_computer) AS fan_out,
         COUNT(DISTINCT src_computer) AS src_computers,
         SUM(auth_type = 'NTLM') AS ntlm,
         SUM(logon_type IN ('Interactive', 'RemoteInteractive', 'CachedInteractive')) AS interactive,
         SUM(logon_type = 'RemoteInteractive') AS remote_interactive,
         SUM(logon_type = 'NetworkCleartext') AS network_cleartext
  FROM wa
  GROUP BY src_user, day, window_name
) u
JOIN burst b ON b.src_user = u.src_user AND b.day = u.day
LEFT JOIN np ON np.user = u.src_user AND np.day = u.day;

-- Per destination computer, per day (NTLM share, ANONYMOUS LOGON volume) ------
DELETE FROM lanl_computer_daily;
INSERT INTO lanl_computer_daily
SELECT dst_computer, day, COUNT(*), COUNT(DISTINCT src_user),
       SUM(auth_type = 'NTLM'),
       ROUND(1.0 * SUM(auth_type = 'NTLM') / COUNT(*), 4),
       SUM(src_user LIKE 'ANONYMOUS LOGON%')
FROM wa
GROUP BY dst_computer, day;

-- Service-like accounts ------------------------------------------------------
-- LANL user names are anonymised, so "looks like a service" is behavioural: active in at
-- least 80% of baseline hours (machine-like regularity), or not a U#### user name.
DELETE FROM lanl_service_like;
WITH base AS (
  SELECT src_user, COUNT(DISTINCT hour) AS active_hours
  FROM wa WHERE window_name = 'baseline' GROUP BY src_user
),
base_len AS (
  SELECT (end_time - start_time) / 3600.0 AS hours FROM lanl_window WHERE window_name = 'baseline'
),
det AS (
  SELECT src_user,
         SUM(logon_type IN ('Interactive', 'RemoteInteractive', 'CachedInteractive')) AS interactive
  FROM wa WHERE window_name = 'detection' GROUP BY src_user
)
INSERT INTO lanl_service_like
SELECT b.src_user,
       CASE WHEN b.src_user NOT LIKE 'U%' THEN 'non-user name' ELSE 'active most baseline hours' END,
       b.active_hours,
       COALESCE(d.interactive, 0)
FROM base b
CROSS JOIN base_len l
LEFT JOIN det d ON d.src_user = b.src_user
WHERE (b.src_user NOT LIKE 'U%' AND b.src_user NOT LIKE 'ANONYMOUS LOGON%')
   OR b.active_hours >= 0.8 * l.hours;

-- Indicator scores over the whole detection window -----------------------------
-- Population: every user with a logon in the detection window except ANONYMOUS LOGON,
-- which is a protocol artefact rather than an identity (it gets its own computer view).
DELETE FROM lanl_indicator_score;
WITH pop AS (
  SELECT src_user AS user,
         SUM(outcome = 'Fail') AS failures,
         COUNT(DISTINCT dst_computer) AS fan_out,
         SUM(auth_type = 'NTLM') AS ntlm_logons,
         SUM(logon_type IN ('RemoteInteractive', 'NetworkCleartext')) AS rare_logon_types
  FROM wa
  WHERE window_name = 'detection' AND src_user NOT LIKE 'ANONYMOUS LOGON%'
  GROUP BY src_user
),
feat AS (
  SELECT p.*,
         COALESCE(n.new_pairs, 0) AS new_pairs,
         COALESCE(d.failure_burst, 0) AS failure_burst,
         COALESCE(s.detection_interactive_logons, 0) AS service_interactive
  FROM pop p
  LEFT JOIN (SELECT user, COUNT(*) AS new_pairs FROM lanl_new_pairs GROUP BY user) n
         ON n.user = p.user
  LEFT JOIN (SELECT user, MAX(max_failures_per_hour) AS failure_burst FROM lanl_user_daily
              WHERE window_name = 'detection' GROUP BY user) d
         ON d.user = p.user
  LEFT JOIN lanl_service_like s ON s.user = p.user
),
ranked AS (
  SELECT f.*,
         PERCENT_RANK() OVER (ORDER BY failures)         AS pr_fail,
         PERCENT_RANK() OVER (ORDER BY fan_out)          AS pr_fan,
         PERCENT_RANK() OVER (ORDER BY new_pairs)        AS pr_new,
         PERCENT_RANK() OVER (ORDER BY ntlm_logons)      AS pr_ntlm,
         PERCENT_RANK() OVER (ORDER BY rare_logon_types) AS pr_rare
  FROM feat f
),
long AS (
  SELECT 'failures' AS indicator, user, failures AS score FROM ranked
  UNION ALL SELECT 'failure_burst', user, failure_burst FROM ranked
  UNION ALL SELECT 'fan_out', user, fan_out FROM ranked
  UNION ALL SELECT 'new_pairs', user, new_pairs FROM ranked
  UNION ALL SELECT 'ntlm_logons', user, ntlm_logons FROM ranked
  UNION ALL SELECT 'rare_logon_types', user, rare_logon_types FROM ranked
  UNION ALL SELECT 'service_interactive', user, service_interactive FROM ranked
  -- Equal-weight mean of percentile ranks; scale-free, so no indicator dominates by magnitude.
  UNION ALL SELECT 'combined_risk', user,
                   ROUND((pr_fail + pr_fan + pr_new + pr_ntlm + pr_rare) / 5.0, 6) FROM ranked
  -- Lateral-movement pair only: the two indicators that describe "touching new machines".
  UNION ALL SELECT 'combined_lateral', user, ROUND((pr_fan + pr_new) / 2.0, 6) FROM ranked
)
INSERT INTO lanl_indicator_score
SELECT indicator, user, score,
       ROW_NUMBER() OVER (PARTITION BY indicator ORDER BY score DESC, user),
       user IN (SELECT user FROM labels)
FROM long;

-- Precision / recall at several top-N cut-offs ----------------------------------
-- A user is flagged when ranked within N and the score is above zero.
DELETE FROM lanl_detection_eval;
WITH cutoffs(top_n) AS (VALUES (5), (10), (20), (50), (100), (250)),
lab AS (SELECT COUNT(*) AS n FROM labels),
hits AS (
  SELECT s.indicator, c.top_n,
         SUM(s.rank <= c.top_n AND s.score > 0) AS flagged,
         SUM(s.rank <= c.top_n AND s.score > 0 AND s.is_redteam) AS tp
  FROM lanl_indicator_score s CROSS JOIN cutoffs c
  GROUP BY s.indicator, c.top_n
)
INSERT INTO lanl_detection_eval
SELECT h.indicator, h.top_n, h.flagged, h.tp, h.flagged - h.tp, lab.n,
       ROUND(CASE WHEN h.flagged > 0 THEN 1.0 * h.tp / h.flagged END, 4),
       ROUND(CASE WHEN lab.n > 0 THEN 1.0 * h.tp / lab.n END, 4),
       ROUND(CASE WHEN h.flagged + lab.n > 0 THEN 2.0 * h.tp / (h.flagged + lab.n) END, 4)
FROM hits h, lab;

COMMIT;
