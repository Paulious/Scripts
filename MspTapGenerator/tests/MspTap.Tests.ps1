#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    $env:LOCALAPPDATA = $TestDrive
    $src = Join-Path $PSScriptRoot '..\src\Modules'
    Import-Module (Join-Path $src 'MspTap.Core\MspTap.Core.psm1') -Force -Global
    Import-Module (Join-Path $src 'MspTap.Data\MspTap.Data.psm1') -Force -Global
    $samples = Join-Path $PSScriptRoot '..\samples'
}

Describe 'Log scrubbing (TAP must never reach the log)' {
    It 'redacts registered TAP values' {
        Register-LogSecret 'Xk9#fT2pQ7zL'
        Protect-LogText 'created Xk9#fT2pQ7zL for bob' | Should -Be 'created [REDACTED] for bob'
    }
    It 'redacts a TAP at the end of a sentence or inside key=value' {
        Register-LogSecret 'EndOfSentence77'
        Protect-LogText 'the pass is EndOfSentence77.' | Should -Be 'the pass is [REDACTED].'
        Protect-LogText 'tap=EndOfSentence77;' | Should -Be 'tap=[REDACTED];'
    }
    It 'keeps only hashes, never the plain value, in the registry' {
        Register-LogSecret 'PlainValueCheck9'
        (Get-SecretRegistry).Keys | Should -Not -Contain 'PlainValueCheck9'
        Clear-LogSecrets
        Protect-LogText 'PlainValueCheck9' | Should -Be 'PlainValueCheck9'
    }
    It 'redacts temporaryAccessPass JSON members' {
        Protect-LogText '{"temporaryAccessPass":"abc123XYZ","x":1}' | Should -Not -Match 'abc123XYZ'
    }
    It 'redacts bearer tokens' { Protect-LogText 'Authorization: Bearer abcDEF123.456' | Should -Not -Match 'abcDEF123' }
    It 'never writes a registered TAP to the log file' {
        Register-LogSecret 'SuperSecretTap99'
        Write-AppLog -Message 'result SuperSecretTap99 done'
        (Get-ChildItem (Get-LogDirectory) -Filter *.jsonl | Get-Content -Raw) | Should -Not -Match 'SuperSecretTap99'
    }
}

Describe 'Validation helpers' {
    It 'accepts GUID and domain tenant ids' {
        Test-TenantIdentifier '11111111-2222-3333-4444-555555555555' | Should -BeTrue
        Test-TenantIdentifier 'contoso.onmicrosoft.com' | Should -BeTrue
    }
    It 'rejects junk tenant ids' { Test-TenantIdentifier "x'; drop" | Should -BeFalse }
    It 'checks UPN shape' { Test-UpnFormat 'a@b.co' | Should -BeTrue; Test-UpnFormat 'nope' | Should -BeFalse }
    It 'neutralises spreadsheet formulas' { Protect-ExportCell '=HYPERLINK("x")' | Should -Be "'=HYPERLINK(`"x`")" }
}

Describe 'Invoke-WithRetry' {
    It 'retries 429 then succeeds' {
        $script:n = 0
        $r = Invoke-WithRetry -BaseDelaySeconds 0 -MaxAttempts 4 { $script:n++; if ($script:n -lt 3) { throw 'Response status code does not indicate success: 429 (Too Many Requests).' }; 'ok' }
        $r | Should -Be 'ok'; $script:n | Should -Be 3
    }
    It 'does not retry a 404' {
        $script:n = 0
        { Invoke-WithRetry -BaseDelaySeconds 0 { $script:n++; throw 'Request_ResourceNotFound' } } | Should -Throw
        $script:n | Should -Be 1
    }
    It 'gives up after MaxAttempts' {
        $script:n = 0
        { Invoke-WithRetry -BaseDelaySeconds 0 -MaxAttempts 2 { $script:n++; throw '429 TooManyRequests' } } | Should -Throw
        $script:n | Should -Be 2
    }
}

Describe 'CSV import' {
    It 'reads a UPN-only file' {
        $r = Import-UsersFromCsv (Join-Path $samples 'users.csv'); $r.Users.Count | Should -Be 2
    }
    It 'reads UPN + DisplayName' {
        $r = Import-UsersFromCsv (Join-Path $samples 'users_with_names.csv'); $r.Users[0].DisplayName | Should -Be 'Joe Bloggs'
    }
    It 'skips duplicates and malformed rows' {
        $f = Join-Path $TestDrive 'bad.csv'
        "UserPrincipalName`na@x.com`nA@x.com`nnotanupn`n" | Set-Content $f
        $r = Import-UsersFromCsv $f; $r.Users.Count | Should -Be 1; $r.Skipped.Count | Should -Be 2
    }
    It 'handles semicolon delimiters' {
        $f = Join-Path $TestDrive 'semi.csv'; "UPN;Name`na@x.com;Al`n" | Set-Content $f
        (Import-UsersFromCsv $f).Users[0].DisplayName | Should -Be 'Al'
    }
    It 'errors when no UPN column exists' {
        $f = Join-Path $TestDrive 'nocol.csv'; "Foo,Bar`n1,2`n" | Set-Content $f
        { Import-UsersFromCsv $f } | Should -Throw '*No UserPrincipalName*'
    }
}

Describe 'XLSX round trip' -Skip:(-not (Get-Module -ListAvailable ImportExcel)) {
    It 'exports, masks TAPs and re-imports sheet names' {
        $p = Join-Path $TestDrive 'out.xlsx'
        $row = [pscustomobject]@{ UserPrincipalName = 'a@x.com'; DisplayName = '=cmd'; Tap = (ConvertTo-SecureString 'TopSecret12' -AsPlainText -Force)
            TapLength = 11; OneTimeUse = $true; StartUtc = [datetime]::UtcNow; ExpiryUtc = [datetime]::UtcNow.AddHours(1); Status = 'Success' }
        Export-TapResult -Rows $row -Path $p -MaskTap
        (Import-Excel $p).TAP | Should -Be '********'
        (Import-Excel $p).DisplayName | Should -Be "'=cmd"
        Get-XlsxSheetName $p | Should -Contain 'TAPs'
    }
}

Describe 'Scope list' -Skip:(-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\src\Modules\MspTap.Graph\MspTap.Graph.psm1') -Force }
    It 'always requests the four required scopes' {
        $s = Get-DesiredScope -PolicyRead $false -PolicyWrite $false
        $s | Should -Contain 'UserAuthenticationMethod.ReadWrite.All'
        $s.Count | Should -Be 4
    }
    It 'adds policy scopes only when asked' {
        (Get-DesiredScope -PolicyRead $true -PolicyWrite $false) | Should -Contain 'Policy.Read.All'
        (Get-DesiredScope -PolicyRead $false -PolicyWrite $true) | Should -Contain 'Policy.ReadWrite.AuthenticationMethod'
    }
}
