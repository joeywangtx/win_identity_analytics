-- Identity analytics schema (Part 1 local collector + Part 2 LANL).
-- Safe to re-run: every object uses IF NOT EXISTS.
--
-- Compatibility: this file and every VIEW in the project must parse on SQLite 3.8.8,
-- the engine bundled with PSSQLite 1.1.0. SQLite parses the whole schema whenever a
-- connection opens, so a single view using newer syntax (window functions, IIF, UPSERT)
-- would make the collector fail. Window-function work happens in the sqlite3 CLI and is
-- materialized into plain tables (see views_lanl.sql).
--
-- Timestamps are UTC text 'YYYY-MM-DD HH:MM:SS' so they sort and compare as strings.

-- ---------------------------------------------------------------------------
-- Part 1: local collector
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS runs (
  run_id             INTEGER PRIMARY KEY,
  started_at         TEXT NOT NULL,
  finished_at        TEXT,
  host               TEXT,
  events_loaded      INTEGER,
  accounts           INTEGER,
  group_members      INTEGER,
  last_record_before INTEGER,   -- highest EventRecordID in the DB when the run started
  last_record_after  INTEGER,
  status             TEXT NOT NULL,   -- running | success | warning | failed
  notes              TEXT,            -- warnings such as a log rollover gap
  error              TEXT
);

CREATE TABLE IF NOT EXISTS account_snapshot (
  run_id            INTEGER NOT NULL,
  sid               TEXT NOT NULL,
  name              TEXT,
  enabled           INTEGER,
  last_logon        TEXT,
  pwd_last_set      TEXT,
  pwd_never_expires INTEGER,
  pwd_required      INTEGER,
  description       TEXT,
  PRIMARY KEY (run_id, sid)
);

CREATE TABLE IF NOT EXISTS group_membership (
  run_id        INTEGER NOT NULL,
  group_name    TEXT,
  group_sid     TEXT,           -- group names are localized; SIDs are not
  member_sid    TEXT,
  member_name   TEXT,           -- NULL when the SID cannot be resolved
  member_source TEXT            -- Local | ActiveDirectory | AzureAD | MicrosoftAccount | Unknown | Orphaned
);
CREATE INDEX IF NOT EXISTS ix_gm_run ON group_membership(run_id);

CREATE TABLE IF NOT EXISTS auth_event (
  record_id    INTEGER PRIMARY KEY,   -- Security log EventRecordID; PK makes reloads idempotent
  time_created TEXT NOT NULL,
  event_id     INTEGER NOT NULL,
  target_user  TEXT,
  target_sid   TEXT,
  logon_type   INTEGER,
  status_code  TEXT,
  sub_status   TEXT,
  source_ip    TEXT,
  process_name TEXT,
  auth_package TEXT
);
CREATE INDEX IF NOT EXISTS ix_auth_time ON auth_event(time_created);
CREATE INDEX IF NOT EXISTS ix_auth_user ON auth_event(target_user);
CREATE INDEX IF NOT EXISTS ix_auth_sid  ON auth_event(target_sid);

CREATE TABLE IF NOT EXISTS account_change (
  record_id    INTEGER PRIMARY KEY,
  time_created TEXT NOT NULL,
  event_id     INTEGER NOT NULL,
  actor        TEXT,
  target_user  TEXT,
  target_sid   TEXT,
  group_name   TEXT,
  group_sid    TEXT
);
CREATE INDEX IF NOT EXISTS ix_change_time ON account_change(time_created);

-- Reference data ------------------------------------------------------------

-- Admin-level built-in groups, keyed by well-known SID so it works on any OS language.
CREATE TABLE IF NOT EXISTS privileged_group (
  group_sid TEXT PRIMARY KEY,
  label     TEXT NOT NULL
);
INSERT OR IGNORE INTO privileged_group VALUES
  ('S-1-5-32-544', 'Administrators'),
  ('S-1-5-32-547', 'Power Users'),
  ('S-1-5-32-548', 'Account Operators'),
  ('S-1-5-32-549', 'Server Operators'),
  ('S-1-5-32-551', 'Backup Operators'),
  ('S-1-5-32-555', 'Remote Desktop Users'),
  ('S-1-5-32-578', 'Hyper-V Administrators'),
  ('S-1-5-32-580', 'Remote Management Users');

CREATE TABLE IF NOT EXISTS event_ref (
  event_id INTEGER PRIMARY KEY,
  label    TEXT NOT NULL,
  category TEXT NOT NULL   -- auth | lifecycle | group | lockout | audit
);
INSERT OR IGNORE INTO event_ref VALUES
  (4624, 'Logon success',               'auth'),
  (4625, 'Logon failure',               'auth'),
  (4648, 'Logon with explicit creds',   'auth'),
  (4672, 'Special privileges assigned', 'auth'),
  (4720, 'Account created',             'lifecycle'),
  (4722, 'Account enabled',             'lifecycle'),
  (4723, 'Password change attempt',     'lifecycle'),
  (4724, 'Password reset',              'lifecycle'),
  (4725, 'Account disabled',            'lifecycle'),
  (4726, 'Account deleted',             'lifecycle'),
  (4738, 'Account changed',             'lifecycle'),
  (4767, 'Account unlocked',            'lockout'),
  (4740, 'Account locked out',          'lockout'),
  (4732, 'Added to local group',        'group'),
  (4733, 'Removed from local group',    'group'),
  (1102, 'Security log cleared',        'audit');

CREATE TABLE IF NOT EXISTS logon_type_ref (
  logon_type INTEGER PRIMARY KEY,
  label      TEXT NOT NULL
);
INSERT OR IGNORE INTO logon_type_ref VALUES
  (0, 'System'), (2, 'Interactive'), (3, 'Network'), (4, 'Batch'), (5, 'Service'),
  (7, 'Unlock'), (8, 'NetworkCleartext'), (9, 'NewCredentials'),
  (10, 'RemoteInteractive'), (11, 'CachedInteractive'),
  (12, 'CachedRemoteInteractive'), (13, 'CachedUnlock');

-- NTSTATUS codes seen in 4625 Status / SubStatus.
CREATE TABLE IF NOT EXISTS status_code_ref (
  status_code TEXT PRIMARY KEY,
  label       TEXT NOT NULL
);
INSERT OR IGNORE INTO status_code_ref VALUES
  ('0xC000006D', 'Bad username or authentication info (generic)'),
  ('0xC000006A', 'Bad password'),
  ('0xC0000064', 'Unknown user'),
  ('0xC0000234', 'Account locked out'),
  ('0xC0000072', 'Account disabled'),
  ('0xC000006F', 'Outside allowed logon hours'),
  ('0xC0000070', 'Workstation restriction'),
  ('0xC0000071', 'Password expired'),
  ('0xC0000193', 'Account expired'),
  ('0xC0000224', 'Password must change at next logon'),
  ('0xC000015B', 'Logon type not granted'),
  ('0xC0000133', 'Clock skew'),
  ('0xC000006E', 'Account restriction');

-- ---------------------------------------------------------------------------
-- Part 2: LANL enterprise authentication slice
-- ---------------------------------------------------------------------------

-- Column order matches auth.txt so filtered lines can be .import-ed unchanged.
CREATE TABLE IF NOT EXISTS lanl_auth (
  time         INTEGER NOT NULL,   -- seconds from dataset start, not a real date
  src_user     TEXT,
  dst_user     TEXT,
  src_computer TEXT,
  dst_computer TEXT,
  auth_type    TEXT,
  logon_type   TEXT,
  orientation  TEXT,
  outcome      TEXT                -- Success | Fail
);
CREATE INDEX IF NOT EXISTS ix_lanl_time    ON lanl_auth(time);
CREATE INDEX IF NOT EXISTS ix_lanl_srcuser ON lanl_auth(src_user);
CREATE INDEX IF NOT EXISTS ix_lanl_dstcomp ON lanl_auth(dst_computer);

CREATE TABLE IF NOT EXISTS lanl_redteam (
  time         INTEGER NOT NULL,
  user         TEXT,
  src_computer TEXT,
  dst_computer TEXT
);

-- Analysis windows; end_time is exclusive.
CREATE TABLE IF NOT EXISTS lanl_window (
  window_name TEXT PRIMARY KEY,    -- baseline | detection
  start_time  INTEGER NOT NULL,
  end_time    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS lanl_import_log (
  import_id            INTEGER PRIMARY KEY,
  started_at           TEXT,
  finished_at          TEXT,
  source_file          TEXT,
  window_start         INTEGER,
  window_end           INTEGER,
  rows_read            INTEGER,   -- every line read from the .gz before stopping
  rows_before_window   INTEGER,
  rows_in_window       INTEGER,
  dropped_orientation  INTEGER,   -- LogOff / TGS / TGT / AuthMap
  dropped_computer_acct INTEGER,  -- source user ends in '$'
  rows_written         INTEGER,   -- lines written to the CSV
  rows_loaded          INTEGER,   -- rows in lanl_auth after .import
  redteam_rows         INTEGER,
  status               TEXT,
  notes                TEXT
);

-- Aggregates for Power BI. Created empty here so views always resolve; views_lanl.sql
-- refills them with the sqlite3 CLI (it needs window functions).
CREATE TABLE IF NOT EXISTS lanl_user_daily (
  user                  TEXT,
  day                   INTEGER,
  window_name           TEXT,
  logons                INTEGER,
  failures              INTEGER,
  failure_rate          REAL,
  max_failures_per_hour INTEGER,   -- burstiness
  fan_out               INTEGER,   -- distinct destination computers
  src_computers         INTEGER,
  ntlm_logons           INTEGER,
  ntlm_share            REAL,
  interactive_logons    INTEGER,   -- Interactive + RemoteInteractive + CachedInteractive
  remote_interactive    INTEGER,
  network_cleartext     INTEGER,
  new_pairs             INTEGER,   -- detection window only
  is_redteam            INTEGER,
  PRIMARY KEY (user, day)
);

CREATE TABLE IF NOT EXISTS lanl_new_pairs (
  user            TEXT,
  dst_computer    TEXT,
  first_time      INTEGER,
  logons          INTEGER,
  is_redteam_pair INTEGER
);

CREATE TABLE IF NOT EXISTS lanl_computer_daily (
  dst_computer     TEXT,
  day              INTEGER,
  logons           INTEGER,
  distinct_users   INTEGER,
  ntlm_logons      INTEGER,
  ntlm_share       REAL,
  anonymous_logons INTEGER,
  PRIMARY KEY (dst_computer, day)
);

CREATE TABLE IF NOT EXISTS lanl_service_like (
  user                         TEXT PRIMARY KEY,
  reason                       TEXT,
  baseline_active_hours        INTEGER,
  detection_interactive_logons INTEGER
);

CREATE TABLE IF NOT EXISTS lanl_indicator_score (
  indicator  TEXT,
  user       TEXT,
  score      REAL,
  rank       INTEGER,
  is_redteam INTEGER,
  PRIMARY KEY (indicator, user)
);

CREATE TABLE IF NOT EXISTS lanl_detection_eval (
  indicator     TEXT,
  top_n         INTEGER,
  flagged       INTEGER,
  true_pos      INTEGER,
  false_pos     INTEGER,
  labeled_users INTEGER,
  precision     REAL,
  recall        REAL,
  f1            REAL,
  PRIMARY KEY (indicator, top_n)
);
