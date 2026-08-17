<#
.SYNOPSIS
    Network security group checks.
.DESCRIPTION
    PowerShell implementation of AZ-NET-001 in baselines/azure-network.md.
    Mirrors python/checks/network.py. Rules are judged by what they permit,
    not by what they are called — the control exists because a rule named
    Allow-RDP-MyIP had its source set to "*".
#>

$script:AdminPorts = @(22, 3389)

$script:InternetSources = @('*', '0.0.0.0/0', 'Internet', 'Any', '::/0')

function Test-PortRangeCoversAdminPort {
    <#
        Returns the admin ports covered by a single port range expression.
        Handles "*", a single port such as "3389", and a range such as "0-65535".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $PortRange
    )

    if ($PortRange -eq '*') {
        return $script:AdminPorts
    }

    if ($PortRange -match '^(\d+)-(\d+)$') {
        $from = [int]$Matches[1]
        $to   = [int]$Matches[2]
        return $script:AdminPorts | Where-Object { $_ -ge $from -and $_ -le $to }
    }

    if ($PortRange -match '^\d+$') {
        $port = [int]$PortRange
        return $script:AdminPorts | Where-Object { $_ -eq $port }
    }

    return @()
}

function Test-AdminPortsNotInternetFacing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ResourceGroupName
    )

    $controlId = 'AZ-NET-001'
    $title     = 'Remote administration ports are not reachable from the internet'

    $nsgs = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName

    foreach ($nsg in $nsgs) {

        $exposures = @()

        foreach ($rule in $nsg.SecurityRules) {

            if ($rule.Direction -ne 'Inbound' -or $rule.Access -ne 'Allow') {
                continue
            }

            # Both fields are collections in the Az module, unlike the Python SDK
            # where the singular and plural forms are separate properties.
            $sources = @($rule.SourceAddressPrefix) + @($rule.SourceAddressPrefixes)
            $fromInternet = $sources | Where-Object { $_ -in $script:InternetSources }

            if (-not $fromInternet) {
                continue
            }

            $ranges = @($rule.DestinationPortRange) + @($rule.DestinationPortRanges)
            $covered = $ranges | ForEach-Object { Test-PortRangeCoversAdminPort -PortRange $_ } |
                Sort-Object -Unique

            if ($covered) {
                $exposures += [PSCustomObject]@{
                    rule     = $rule.Name
                    priority = $rule.Priority
                    source   = ($fromInternet -join ',')
                    ports    = ($covered -join ',')
                }
            }
        }

        $evidence = @{
            rulesEvaluated = @($nsg.SecurityRules).Count
            exposures      = $exposures
        }

        if ($exposures.Count -eq 0) {
            New-CheckResult -ControlId $controlId -Title $title `
                -Resource $nsg.Name `
                -Status 'pass' `
                -Detail 'No inbound rule exposes SSH or RDP to the internet' `
                -Evidence $evidence
        }
        else {
            $detail = ($exposures | ForEach-Object {
                "rule '$($_.rule)' allows port(s) $($_.ports) from $($_.source)"
            }) -join '; '

            New-CheckResult -ControlId $controlId -Title $title `
                -Resource $nsg.Name `
                -Status 'fail' `
                -Detail $detail `
                -Evidence $evidence
        }
    }
}