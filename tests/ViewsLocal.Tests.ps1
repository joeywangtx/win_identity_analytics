# Runs every local view on tests/fixtures/local_fixture.sql through PSSQLite, which also
# proves the views parse on its bundled SQLite 3.8.8.
BeforeAll {
    Import-Module PSSQLite
    Import-Module (Join-Path $PSScriptRoot '..\collector\IdentityCollector.psm1') -Force

    $script:Db = Join-Path $TestDrive 'views.db'
    $conn = New-SQLiteConnection -DataSource $script:Db
    try {
        Initialize-IdentityDatabase -Connection $conn
        Invoke-SqlFile -Connection $conn -Path (Join-Path $PSScriptRoot 'fixtures\local_fixture.sql')
    }
    finally { $conn.Close(); $conn.Dispose() }

    function Get-Rows([string]$Query) { , @(Invoke-SqliteQuery -DataSource $script:Db -Query $Query) }
}

Describe 'v_reference_run' {
    It 'uses the latest successful run, ignoring the later failed one' {
        $r = Get-Rows 'SELECT * FROM v_reference_run'
        $r[0].run_id   | Should -Be 2
        $r[0].ref_time | Should -Be '2026-10-24 02:00:00'
    }
}

Describe 'v_dormant_accounts' {
    BeforeAll { $script:Rows = Get-Rows 'SELECT * FROM v_dormant_accounts ORDER BY name' }

    It 'returns enabled accounts inactive > 30 days or never used' {
        $script:Rows.name | Should -Be @('never_user', 'temp_contractor')
    }
    It 'gives the reason and days inactive' {
        ($script:Rows | Where-Object name -eq 'never_user').reason | Should -Be 'never logged on'
        ($script:Rows | Where-Object name -eq 'temp_contractor').days_inactive | Should -Be 53
    }
    It 'uses the event log when LastLogon is empty' {
        $script:Rows.name | Should -Not -Contain 'svc_backup'
    }
}

Describe 'v_privileged_accounts' {
    BeforeAll { $script:Rows = Get-Rows 'SELECT * FROM v_privileged_accounts ORDER BY privileged_group, member_name' }

    It 'lists members of admin-level groups from the latest run only' {
        $script:Rows.Count | Should -Be 4
        $script:Rows.member_name | Should -Not -Contain 'IDLAB-VM\svc_backup'
    }
    It 'flags the dormant admin and the orphaned SID' {
        ($script:Rows | Where-Object is_dormant -eq 1).member_name | Should -Be 'IDLAB-VM\temp_contractor'
        ($script:Rows | Where-Object is_orphaned -eq 1).member_sid | Should -Be 'S-1-5-21-1-2-3-1999'
    }
    It 'includes Remote Desktop Users as privileged' {
        ($script:Rows | Where-Object privileged_group -eq 'Remote Desktop Users').member_name | Should -Be 'IDLAB-VM\jsmith'
    }
}

Describe 'v_password_hygiene' {
    It 'buckets password age' {
        $r = Get-Rows 'SELECT name, age_bucket FROM v_password_hygiene ORDER BY name'
        $map = @{}; $r | ForEach-Object { $map[$_.name] = $_.age_bucket }
        $map['labadmin']        | Should -Be '0-90'
        $map['jsmith']          | Should -Be '365+'
        $map['svc_backup']      | Should -Be '90-365'
        $map['old_user']        | Should -Be 'never set'
    }
    It 'marks never-expires and not-required as issues' {
        $r = Get-Rows 'SELECT name FROM v_password_hygiene WHERE has_issue = 1 ORDER BY name'
        $r.name | Should -Be @('jsmith', 'old_user', 'svc_backup', 'temp_contractor')
    }
}

Describe 'v_auth_failures_daily' {
    BeforeAll { $script:Rows = Get-Rows 'SELECT * FROM v_auth_failures_daily ORDER BY day, target_user' }

    It 'groups failures by day, account, logon type and reason' {
        $script:Rows.Count | Should -Be 3
        $tc = $script:Rows | Where-Object target_user -eq 'temp_contractor'
        $tc.failures        | Should -Be 7
        $tc.logon_type_name | Should -Be 'Network'
    }
    It 'uses SubStatus when Status is the generic 0xC000006D' {
        ($script:Rows | Where-Object target_user -eq 'temp_contractor').reason_code | Should -Be '0xC000006A'
        ($script:Rows | Where-Object target_user -eq 'ghost').reason | Should -Be 'Unknown user'
    }
    It 'falls back to Status when SubStatus is 0x0' {
        ($script:Rows | Where-Object target_user -eq 'jsmith').reason | Should -Be 'Bad password'
    }
}

Describe 'v_lockouts' {
    BeforeAll { $script:Rows = Get-Rows 'SELECT * FROM v_lockouts ORDER BY lockout_time' }

    It 'returns one row per lockout' {
        $script:Rows.Count | Should -Be 2
    }
    It 'measures failures and time from first failure to lockout' {
        $script:Rows[0].failures_before_lockout | Should -Be 5
        $script:Rows[0].minutes_to_lockout      | Should -Be 4.5
    }
    It 'only counts failures after the previous unlock' {
        $script:Rows[1].failures_before_lockout | Should -Be 2
        $script:Rows[1].minutes_to_lockout      | Should -Be 2
    }
}

Describe 'v_privileged_group_changes' {
    It 'shows admin-group adds/removes with actor, resolving members by SID' {
        $r = Get-Rows 'SELECT * FROM v_privileged_group_changes ORDER BY time_created'
        $r.Count     | Should -Be 2
        $r[0].action | Should -Be 'added'
        $r[0].member | Should -Be 'temp_contractor'
        $r[0].actor  | Should -Be 'labadmin'
        $r[1].action | Should -Be 'removed'
        $r[1].member | Should -Be 'svc_backup'
    }
}

Describe 'v_account_lifecycle' {
    It 'lists lifecycle and lockout events but not group or audit events' {
        $r = Get-Rows 'SELECT * FROM v_account_lifecycle ORDER BY time_created'
        $r.Count | Should -Be 6
        $r.action | Should -Contain 'Account created'
        $r.action | Should -Contain 'Account deleted'
        $r.event_id | Should -Not -Contain 4732
    }
}

Describe 'v_data_quality' {
    It 'reports orphaned SIDs, missing descriptions and events for unknown accounts' {
        $r = Get-Rows 'SELECT * FROM v_data_quality ORDER BY issue'
        $r.Count | Should -Be 3
        ($r | Where-Object issue -eq 'orphaned_sid').object               | Should -Be 'S-1-5-21-1-2-3-1999'
        ($r | Where-Object issue -eq 'missing_description').object        | Should -Be 'svc_backup'
        ($r | Where-Object issue -eq 'event_user_not_in_snapshot').object | Should -Be 'S-1-5-21-1-2-3-1006'
    }
}

Describe 'v_kri_summary' {
    BeforeAll {
        $script:Kri = @{}
        foreach ($row in (Get-Rows 'SELECT * FROM v_kri_summary')) { $script:Kri[$row.indicator] = $row }
    }

    It 'turns red for a dormant privileged account' {
        $script:Kri['Dormant privileged accounts'].value  | Should -Be 1
        $script:Kri['Dormant privileged accounts'].status | Should -Be 'red'
    }
    It 'stays green for 2 lockouts against a threshold of 3' {
        $script:Kri['Lockouts in last 7 days'].value  | Should -Be 2
        $script:Kri['Lockouts in last 7 days'].status | Should -Be 'green'
    }
    It 'rates the remaining local indicators' {
        $script:Kri['Password never expires'].status                  | Should -Be 'amber'
        $script:Kri['Password not required'].status                   | Should -Be 'red'
        $script:Kri['Privileged group changes in last 7 days'].value  | Should -Be 2
        $script:Kri['Security log cleared (30 days)'].status          | Should -Be 'red'
        $script:Kri['Failed collector runs (14 days)'].value          | Should -Be 1
    }
    It "reports 'no data' for LANL indicators when no LANL slice is loaded" {
        $script:Kri['LANL best indicator F1'].status | Should -Be 'no data'
    }
}

Describe 'v_run_history' {
    It 'computes run duration' {
        (Get-Rows 'SELECT duration_sec FROM v_run_history WHERE run_id = 2')[0].duration_sec | Should -Be 6
    }
}
