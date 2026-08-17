function New-CheckResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $Resource,
        [Parameter(Mandatory)] [ValidateSet('pass', 'fail', 'deviation', 'error')] [string] $Status,
        [Parameter(Mandatory)] [string] $Detail,
        [hashtable] $Evidence = @{}
    )

    [PSCustomObject]@{
        ControlId = $ControlId
        Title     = $Title
        Resource  = $Resource
        Status    = $Status
        Detail    = $Detail
        Evidence  = $Evidence
        CheckedAt = (Get-Date).ToUniversalTime().ToString('o')
    }
}