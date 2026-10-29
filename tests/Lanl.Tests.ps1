# End-to-end test of lanl/Import-LanlSlice.ps1 + sql/views_lanl.sql on a tiny slice where
# every count is known. Needs the sqlite3 CLI on PATH (skipped otherwise).
BeforeDiscovery {
    $script:NoCli = -not (Get-Command sqlite3 -ErrorAction SilentlyContinue)
}

BeforeAll {
    Import-Module PSSQLite
    $script:Importer = Join-Path $PSScriptRoot '..\lanl\Import-LanlSlice.ps1'

    function Write-Gzip([string]$Path, [string[]]$Lines) {
        $fs = [IO.File]::Create($Path)
        $gz = New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Compress)
        $w = New-Object IO.StreamWriter($gz, (New-Object Text.UTF8Encoding($false)))
        try { foreach ($l in $Lines) { $w.Write($l + "`n") } } finally { $w.Dispose() }
    }
    function Get-Rows([string]$Query) { , @(Invoke-SqliteQuery -DataSource $script:Db -Query $Query) }

    # Baseline = day 1 (86400-172799), detection = day 2 (172800-259199).
    $auth = @(
        '100,U1@DOM1,U1@DOM1,C1,C1,Kerberos,Network,LogOn,Success'          # before window
        '86500,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success'        # baseline pair U1->C2
        '86600,U2@DOM1,U2@DOM1,C3,C4,NTLM,Network,LogOn,Success'
        '86700,C5$@DOM1,C5$@DOM1,C5,C6,Kerberos,Network,LogOn,Success'      # computer account
        '86800,U1@DOM1,U1@DOM1,C1,C2,?,?,LogOff,Success'                    # orientation
        '86900,U3@DOM1,U3@DOM1,C7,C8,Kerberos,Network,TGS,Success'          # orientation
        '172900,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success'       # known pair
        '173000,U2@DOM1,U2@DOM1,C3,C9,NTLM,Network,LogOn,Fail'
        '173001,U2@DOM1,U2@DOM1,C3,C9,NTLM,Network,LogOn,Fail'
        '173100,U9@DOM1,U9@DOM1,C17693,C10,Kerberos,Network,LogOn,Success'  # red team
        '173150,U9@DOM1,U9@DOM1,C17693,C11,Kerberos,Network,LogOn,Success'  # red team
        '173200,U9@DOM1,U9@DOM1,C17693,C12,Kerberos,Network,LogOn,Success'
        '173300,U9@DOM1,U9@DOM1,C17693,C13,Kerberos,Network,LogOn,Success'
        '173500,ANONYMOUS LOGON@C586,ANONYMOUS LOGON@C586,C2,C586,NTLM,Network,LogOn,Success'
        '174000,U4@DOM1,U4@DOM1,C14,C14,Kerberos,RemoteInteractive,LogOn,Success'
        '259300,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success'       # past window: stop
        '259400,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success'       # never read
    )
    $redteam = @(
        '173100,U9@DOM1,C17693,C10'
        '173150,U9@DOM1,C17693,C11'
        '500000,U7@DOM1,C17693,C99'   # outside the detection window
    )
    $dir = Join-Path $TestDrive 'lanl'
    New-Item -ItemType Directory $dir | Out-Null
    Write-Gzip (Join-Path $dir 'auth.txt.gz') $auth
    Write-Gzip (Join-Path $dir 'redteam.txt.gz') $redteam
    $script:Db = Join-Path $dir 'lanl.db'
}

Describe 'Import-LanlSlice' -Skip:$script:NoCli {
    BeforeAll {
        & $script:Importer -AuthPath (Join-Path $dir 'auth.txt.gz') -RedTeamPath (Join-Path $dir 'redteam.txt.gz') `
            -Database $script:Db -BaselineDays 1 -DetectionDays 2 6>$null | Out-Null
        $script:Log = (Get-Rows 'SELECT * FROM lanl_import_log')[0]
    }

    It 'records row counts at each step and stops at the end of the window' {
        $script:Log.rows_read             | Should -Be 16
        $script:Log.rows_before_window    | Should -Be 1
        $script:Log.rows_in_window        | Should -Be 14
        $script:Log.dropped_orientation   | Should -Be 2
        $script:Log.dropped_computer_acct | Should -Be 1
        $script:Log.rows_written          | Should -Be 11
        $script:Log.rows_loaded           | Should -Be 11
        $script:Log.status                | Should -Be 'success'
    }

    It 'loads all red-team rows and the windows' {
        $script:Log.redteam_rows | Should -Be 3
        (Get-Rows "SELECT * FROM lanl_window WHERE window_name = 'detection'")[0].start_time | Should -Be 172800
    }

    It 'finds user->computer pairs not seen in the baseline' {
        $pairs = Get-Rows "SELECT * FROM lanl_new_pairs WHERE user = 'U9@DOM1' ORDER BY dst_computer"
        $pairs.dst_computer    | Should -Be @('C10', 'C11', 'C12', 'C13')
        $pairs.is_redteam_pair | Should -Be @(1, 1, 0, 0)
        (Get-Rows "SELECT * FROM lanl_new_pairs WHERE user = 'U1@DOM1'").Count | Should -Be 0
    }

    It 'computes per-user daily aggregates' {
        $u2 = (Get-Rows "SELECT * FROM lanl_user_daily WHERE user = 'U2@DOM1' AND day = 2")[0]
        $u2.failures     | Should -Be 2
        $u2.failure_rate | Should -Be 1
        $u2.ntlm_share   | Should -Be 1
        $u9 = (Get-Rows "SELECT * FROM lanl_user_daily WHERE user = 'U9@DOM1'")[0]
        $u9.fan_out    | Should -Be 4
        $u9.new_pairs  | Should -Be 4
        $u9.is_redteam | Should -Be 1
    }

    It 'counts ANONYMOUS LOGON per destination computer' {
        (Get-Rows "SELECT * FROM lanl_computer_daily WHERE dst_computer = 'C586'")[0].anonymous_logons | Should -Be 1
    }

    It 'excludes ANONYMOUS LOGON from user scoring' {
        (Get-Rows "SELECT * FROM lanl_indicator_score WHERE user LIKE 'ANONYMOUS%'").Count | Should -Be 0
    }

    It 'measures precision and recall against red-team users in the detection window' {
        $np = (Get-Rows "SELECT * FROM lanl_detection_eval WHERE indicator = 'new_pairs' AND top_n = 5")[0]
        $np.labeled_users | Should -Be 1      # U7 is outside the window
        $np.flagged       | Should -Be 3      # U9, U2, U4 have new pairs
        $np.true_pos      | Should -Be 1
        $np.precision     | Should -Be 0.3333
        $np.recall        | Should -Be 1

        $fail = (Get-Rows "SELECT * FROM lanl_detection_eval WHERE indicator = 'failures' AND top_n = 5")[0]
        $fail.flagged | Should -Be 1
        $fail.recall  | Should -Be 0
        $fail.f1      | Should -Be 0
    }

    It 'ranks the red-team user first on the lateral-movement score' {
        (Get-Rows "SELECT user FROM lanl_indicator_score WHERE indicator = 'combined_lateral' AND rank = 1")[0].user |
            Should -Be 'U9@DOM1'
    }

    It 'leaves the aggregate tables readable by PSSQLite (SQLite 3.8.8)' {
        (Get-Rows 'SELECT * FROM v_kri_summary WHERE part = ''lanl''').Count | Should -Be 3
        (Get-Rows "SELECT status FROM v_kri_summary WHERE indicator = 'LANL best indicator F1'")[0].status | Should -Be 'info'
    }

    It 'replaces the previous slice on re-import instead of appending' {
        & $script:Importer -AuthPath (Join-Path $dir 'auth.txt.gz') -RedTeamPath (Join-Path $dir 'redteam.txt.gz') `
            -Database $script:Db -BaselineDays 1 -DetectionDays 2 6>$null | Out-Null
        (Get-Rows 'SELECT COUNT(*) AS n FROM lanl_auth')[0].n     | Should -Be 11
        (Get-Rows 'SELECT COUNT(*) AS n FROM lanl_redteam')[0].n  | Should -Be 3
        (Get-Rows 'SELECT COUNT(*) AS n FROM lanl_import_log')[0].n | Should -Be 2
    }
}
