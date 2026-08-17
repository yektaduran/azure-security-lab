<#
.SYNOPSIS
    Storage account configuration checks.
.DESCRIPTION
    PowerShell implementation of the storage controls in baselines/azure-storage.md.
    Mirrors python/checks/storage.py — the two are deliberately kept in parity so
    each can be used to verify the other.
#>

function Test-SharedKeyAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ResourceGroupName
    )

    $controlId = 'AZ-STO-002'
    $title     = 'Shared key access must be disabled'

    $accounts = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName

    foreach ($account in $accounts) {
        $allowed = $account.AllowSharedKeyAccess

        # $null means the property was never set, which Azure treats as enabled.
        # Only an explicit $false is compliance.
        if ($allowed -eq $false) {
            New-CheckResult -ControlId $controlId -Title $title `
                -Resource $account.StorageAccountName `
                -Status 'pass' `
                -Detail 'Shared key access is disabled' `
                -Evidence @{ allowSharedKeyAccess = $allowed }
        }
        else {
            $state = if ($null -eq $allowed) { 'not set (defaults to enabled)' } else { 'enabled' }
            New-CheckResult -ControlId $controlId -Title $title `
                -Resource $account.StorageAccountName `
                -Status 'fail' `
                -Detail "Shared key access is $state" `
                -Evidence @{ allowSharedKeyAccess = $allowed }
        }
    }
}

function Test-SecureTransfer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ResourceGroupName
    )

    $controlId = 'AZ-STO-003'
    $title     = 'Secure transfer, TLS 1.2 and no anonymous access'

    $accounts = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName

    foreach ($account in $accounts) {
        $problems = @()

        if ($account.EnableHttpsTrafficOnly -ne $true) {
            $problems += 'HTTPS-only transfer is not enforced'
        }

        if ($account.MinimumTlsVersion -ne 'TLS1_2') {
            $problems += "minimum TLS version is '$($account.MinimumTlsVersion)'"
        }

        # Same trap as above: $null is not compliance, it means Azure's default.
        if ($account.AllowBlobPublicAccess -ne $false) {
            $problems += 'anonymous blob access is not explicitly disabled'
        }

        $evidence = @{
            enableHttpsTrafficOnly = $account.EnableHttpsTrafficOnly
            minimumTlsVersion      = $account.MinimumTlsVersion
            allowBlobPublicAccess  = $account.AllowBlobPublicAccess
        }

        if ($problems.Count -eq 0) {
            New-CheckResult -ControlId $controlId -Title $title `
                -Resource $account.StorageAccountName `
                -Status 'pass' `
                -Detail 'HTTPS enforced, TLS 1.2 minimum, anonymous access disabled' `
                -Evidence $evidence
        }
        else {
            New-CheckResult -ControlId $controlId -Title $title `
                -Resource $account.StorageAccountName `
                -Status 'fail' `
                -Detail ($problems -join '; ') `
                -Evidence $evidence
        }
    }
}