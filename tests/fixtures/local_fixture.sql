-- Small hand-built dataset with known answers for tests/ViewsLocal.Tests.ps1.
-- Reference run = run 2 (2026-10-24 02:00:00). Run 1 is older; run 3 failed and must be ignored.
-- SID prefix S-1-5-21-1-2-3- stands in for the machine SID.

INSERT INTO runs (run_id, started_at, finished_at, host, events_loaded, accounts, group_members, status, error) VALUES
  (1, '2026-10-23 02:00:00', '2026-10-23 02:00:05', 'IDLAB-VM', 10, 2, 1, 'success', NULL),
  (2, '2026-10-24 02:00:00', '2026-10-24 02:00:06', 'IDLAB-VM', 17, 6, 5, 'success', NULL),
  (3, '2026-10-24 12:00:00', '2026-10-24 12:00:01', 'IDLAB-VM', NULL, NULL, NULL, 'failed', 'Access is denied');

-- Run 1 snapshot (stale; views must not use it).
INSERT INTO account_snapshot VALUES
  (1, 'S-1-5-21-1-2-3-1001', 'jsmith', 0, NULL, NULL, 0, 1, 'stale row'),
  (1, 'S-1-5-21-1-2-3-1002', 'svc_backup', 1, NULL, NULL, 1, 1, NULL);
INSERT INTO group_membership VALUES
  (1, 'Administrators', 'S-1-5-32-544', 'S-1-5-21-1-2-3-1002', 'IDLAB-VM\svc_backup', 'Local');

-- Run 2 snapshot.
-- run_id, sid, name, enabled, last_logon, pwd_last_set, never_expires, required, description
INSERT INTO account_snapshot VALUES
  (2, 'S-1-5-21-1-2-3-500',  'labadmin',        1, '2026-10-23 08:00:00', '2026-09-01 00:00:00', 0, 1, 'Lab administrator'),
  (2, 'S-1-5-21-1-2-3-1001', 'jsmith',          1, '2026-10-22 09:30:00', '2025-06-01 00:00:00', 0, 1, 'Analyst'),
  (2, 'S-1-5-21-1-2-3-1002', 'svc_backup',      1, NULL,                  '2026-05-01 00:00:00', 1, 1, NULL),
  (2, 'S-1-5-21-1-2-3-1003', 'temp_contractor', 1, '2026-09-01 00:00:00', '2026-08-01 00:00:00', 0, 0, 'Contractor'),
  (2, 'S-1-5-21-1-2-3-1004', 'old_user',        0, NULL,                  NULL,                  0, 1, 'Leaver'),
  (2, 'S-1-5-21-1-2-3-1005', 'never_user',      1, NULL,                  '2026-10-01 00:00:00', 0, 1, 'Unused');

INSERT INTO group_membership VALUES
  (2, 'Administrators',       'S-1-5-32-544', 'S-1-5-21-1-2-3-500',  'IDLAB-VM\labadmin',        'Local'),
  (2, 'Administrators',       'S-1-5-32-544', 'S-1-5-21-1-2-3-1003', 'IDLAB-VM\temp_contractor', 'Local'),
  (2, 'Administrators',       'S-1-5-32-544', 'S-1-5-21-1-2-3-1999', NULL,                       'Orphaned'),
  (2, 'Users',                'S-1-5-32-545', 'S-1-5-21-1-2-3-1001', 'IDLAB-VM\jsmith',          'Local'),
  (2, 'Remote Desktop Users', 'S-1-5-32-555', 'S-1-5-21-1-2-3-1001', 'IDLAB-VM\jsmith',          'Local');

-- record_id, time, event_id, user, sid, logon_type, status, sub_status, ip, process, package
INSERT INTO auth_event VALUES
  (1,  '2026-10-20 08:00:00', 4624, 'svc_backup',      'S-1-5-21-1-2-3-1002', 5, NULL, NULL, NULL, NULL, 'Negotiate'),
  -- 5 bad passwords then lockout (record 7)
  (2,  '2026-10-23 10:00:00', 4625, 'temp_contractor', NULL, 3, '0xC000006D', '0xC000006A', '192.168.56.20', NULL, 'NTLM'),
  (3,  '2026-10-23 10:01:00', 4625, 'temp_contractor', NULL, 3, '0xC000006D', '0xC000006A', '192.168.56.20', NULL, 'NTLM'),
  (4,  '2026-10-23 10:02:00', 4625, 'temp_contractor', NULL, 3, '0xC000006D', '0xC000006A', '192.168.56.20', NULL, 'NTLM'),
  (5,  '2026-10-23 10:03:00', 4625, 'temp_contractor', NULL, 3, '0xC000006D', '0xC000006A', '192.168.56.20', NULL, 'NTLM'),
  (6,  '2026-10-23 10:04:00', 4625, 'temp_contractor', NULL, 3, '0xC000006D', '0xC000006A', '192.168.56.20', NULL, 'NTLM'),
  (8,  '2026-10-23 11:00:00', 4625, 'ghost',           NULL, 3, '0xC000006D', '0xC0000064', '192.168.56.20', NULL, 'NTLM'),
  (9,  '2026-10-22 09:00:00', 4625, 'jsmith',          NULL, 2, '0xC000006A', '0x00000000', '127.0.0.1', NULL, 'Negotiate'),
  -- after the unlock (record 10): 2 failures then a second lockout (record 13)
  (11, '2026-10-23 10:30:00', 4625, 'temp_contractor', NULL, 3, '0xC000006D', '0xC000006A', '192.168.56.20', NULL, 'NTLM'),
  (12, '2026-10-23 10:31:00', 4625, 'temp_contractor', NULL, 3, '0xC000006D', '0xC000006A', '192.168.56.20', NULL, 'NTLM'),
  -- a logon by an account that was later deleted
  (26, '2026-10-12 12:00:00', 4624, 'deleted_user',    'S-1-5-21-1-2-3-1006', 2, NULL, NULL, '127.0.0.1', NULL, 'Negotiate');

-- record_id, time, event_id, actor, target_user, target_sid, group_name, group_sid
INSERT INTO account_change VALUES
  (7,  '2026-10-23 10:04:30', 4740, 'IDLAB-VM$', 'temp_contractor', 'S-1-5-21-1-2-3-1003', NULL, NULL),
  (10, '2026-10-23 10:20:00', 4767, 'labadmin',  'temp_contractor', 'S-1-5-21-1-2-3-1003', NULL, NULL),
  (13, '2026-10-23 10:32:00', 4740, 'IDLAB-VM$', 'temp_contractor', 'S-1-5-21-1-2-3-1003', NULL, NULL),
  (20, '2026-10-21 09:15:00', 4732, 'labadmin',  NULL, 'S-1-5-21-1-2-3-1003', 'Administrators', 'S-1-5-32-544'),
  (21, '2026-10-22 09:15:00', 4733, 'labadmin',  NULL, 'S-1-5-21-1-2-3-1002', 'Administrators', 'S-1-5-32-544'),
  (22, '2026-10-22 09:20:00', 4732, 'labadmin',  NULL, 'S-1-5-21-1-2-3-1001', 'Users',          'S-1-5-32-545'),
  (23, '2026-10-10 09:00:00', 4720, 'labadmin',  'temp_contractor', 'S-1-5-21-1-2-3-1003', NULL, NULL),
  (24, '2026-10-15 09:00:00', 4725, 'labadmin',  'old_user',        'S-1-5-21-1-2-3-1004', NULL, NULL),
  (25, '2026-10-16 09:00:00', 4726, 'labadmin',  'deleted_user',    'S-1-5-21-1-2-3-1006', NULL, NULL),
  (27, '2026-10-18 18:00:00', 1102, 'labadmin',  NULL, NULL, NULL, NULL);
