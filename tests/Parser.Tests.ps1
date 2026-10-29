BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\collector\IdentityCollector.psm1') -Force
    $script:Events = Join-Path $PSScriptRoot 'fixtures\events'
    function Read-Fixture([string]$Id) {
        ConvertFrom-SecurityEventXml -Xml ([IO.File]::ReadAllText((Join-Path $script:Events "$Id.xml")))
    }
}

Describe 'ConvertFrom-SecurityEventXml' {
    It 'parses a 4624 logon success into auth_event' {
        $r = Read-Fixture 4624
        $r.Table        | Should -Be 'auth_event'
        $r.record_id    | Should -Be 81234
        $r.event_id     | Should -Be 4624
        $r.time_created | Should -Be '2026-10-20 14:03:11'
        $r.target_user  | Should -Be 'jsmith'
        $r.target_sid   | Should -Be 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        $r.logon_type   | Should -Be 2
        $r.source_ip    | Should -Be '127.0.0.1'
        $r.process_name | Should -Be 'C:\Windows\System32\svchost.exe'
        $r.auth_package | Should -Be 'Negotiate'
        $r.status_code  | Should -BeNullOrEmpty
    }

    It 'parses a 4625 failure, normalising status codes and dropping placeholder values' {
        $r = Read-Fixture 4625
        $r.Table        | Should -Be 'auth_event'
        $r.target_user  | Should -Be 'temp_contractor'
        $r.target_sid   | Should -BeNullOrEmpty   # S-1-0-0 (NULL SID)
        $r.logon_type   | Should -Be 3
        $r.status_code  | Should -Be '0xC000006D'
        $r.sub_status   | Should -Be '0xC000006A'
        $r.source_ip    | Should -Be '192.168.56.20'
        $r.process_name | Should -BeNullOrEmpty   # '-'
        $r.auth_package | Should -Be 'NTLM'
    }

    It 'parses a 4740 lockout into account_change' {
        $r = Read-Fixture 4740
        $r.Table       | Should -Be 'account_change'
        $r.record_id   | Should -Be 81251
        $r.target_user | Should -Be 'temp_contractor'
        $r.target_sid  | Should -Be 'S-1-5-21-1111111111-2222222222-3333333333-1003'
        $r.actor       | Should -Be 'IDLAB-VM$'
        $r.group_name  | Should -BeNullOrEmpty
    }

    It 'parses a 4732 group add with the member SID and the group SID' {
        $r = Read-Fixture 4732
        $r.Table       | Should -Be 'account_change'
        $r.actor       | Should -Be 'labadmin'
        $r.target_user | Should -BeNullOrEmpty   # local members are logged as '-'
        $r.target_sid  | Should -Be 'S-1-5-21-1111111111-2222222222-3333333333-1002'
        $r.group_name  | Should -Be 'Administrators'
        $r.group_sid   | Should -Be 'S-1-5-32-544'
    }

    It 'reads 1102 log-cleared fields from UserData' {
        $r = Read-Fixture 1102
        $r.Table    | Should -Be 'account_change'
        $r.event_id | Should -Be 1102
        $r.actor    | Should -Be 'labadmin'
    }

    It 'returns nothing for an event ID it does not collect' {
        Read-Fixture 4634 | Should -BeNullOrEmpty
    }

    It 'reads fields by name, not position' {
        # Same 4740 with the Data elements reversed must parse identically.
        $doc = [xml][IO.File]::ReadAllText((Join-Path $script:Events '4740.xml'))
        $ed = $doc.Event['EventData']
        $nodes = @($ed.ChildNodes)
        [array]::Reverse($nodes)
        foreach ($n in $nodes) { [void]$ed.AppendChild($n) }
        $r = ConvertFrom-SecurityEventXml -Xml $doc.OuterXml
        $r.target_user | Should -Be 'temp_contractor'
        $r.actor       | Should -Be 'IDLAB-VM$'
    }
}

Describe 'ConvertTo-NtStatus' {
    It 'upper-cases and pads hex codes' {
        ConvertTo-NtStatus '0xc0000064' | Should -Be '0xC0000064'
        ConvertTo-NtStatus '0x0'        | Should -Be '0x00000000'
    }
    It 'returns null for placeholders' {
        ConvertTo-NtStatus '-' | Should -BeNullOrEmpty
        ConvertTo-NtStatus ''  | Should -BeNullOrEmpty
    }
}
