<#
.SYNOPSIS
    Windows host baseline checks, executed inside the VM.
.DESCRIPTION
    Runs over Invoke-AzVMRunCommand through the guest agent — no RDP, no open
    port, no account on the host. Authorisation comes from Azure RBAC.

    RunCommand returns stdout as text, not objects, so each inner script emits
    JSON and the caller converts it back. The object pipeline stops at the VM
    boundary.

    Note the inner scripts run under Windows PowerShell 5.1 as SYSTEM.
#>

function Invoke-GuestScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ResourceGroupName,
        [Parameter(Mandatory)] [string] $VMName,
        [Parameter(Mandatory)] [string] $ScriptString
    )

    $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName `
        -VMName $VMName -CommandId RunPowerShellScript -ScriptString $ScriptString

    $stdout = ($result.Value | Where-Object { $_.Code -like '*StdOut*' }).Message
    $stderr = ($result.Value | Where-Object { $_.Code -like '*StdErr*' }).Message

    [PSCustomObject]@{
        StdOut = $stdout
        StdErr = $stderr
    }
}

function Test-WindowsAuditPolicy {
    <#
        AZ-WIN-001 — the control that protects the detections.

        Every Sentinel rule in this project depends on event 4625. If the audit
        policy for Logon/Logoff is turned off, Windows stops producing those
        events, the analytics rules stop firing, and nothing raises an alarm:
        the pipeline reports healthy because it is receiving what it is being
        sent, which is nothing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ResourceGroupName,
        [Parameter(Mandatory)] [string] $VMName
    )

    $controlId = 'AZ-WIN-001'
    $title     = 'Logon auditing produces the events the detections depend on'
    # Per-subcategory requirements. Logoff and Special Logon have no meaningful
    # failure event, so demanding Failure there produces a false positive —
    # which the first version of this check duly produced. Account Lockout is
    # the mirror image: it only emits failure events (4625), so CIS asks for
    # Failure alone and demanding Success repeats the same bug backwards.
    $required = [ordered]@{
        'Logon'           = @('Success', 'Failure')
        'Logoff'          = @('Success')
        'Account Lockout' = @('Failure')
        'Special Logon'   = @('Success')
    }
    $inner = @'
$rows = auditpol /get /subcategory:"Logon,Logoff,Account Lockout,Special Logon" /r |
    ConvertFrom-Csv
$rows |
    Select-Object @{n='Subcategory';e={$_.Subcategory}},
                  @{n='Setting';e={$_.'Inclusion Setting'}} |
    ConvertTo-Json -Compress
'@

    $out = Invoke-GuestScript -ResourceGroupName $ResourceGroupName -VMName $VMName -ScriptString $inner

    if ($out.StdErr) {
        return New-CheckResult -ControlId $controlId -Title $title -Resource $VMName `
            -Status 'error' `
            -Detail "Could not read audit policy: $($out.StdErr.Trim())" `
            -Evidence @{ stderr = $out.StdErr.Trim() }
    }

    $settings = $out.StdOut | ConvertFrom-Json

    $problems = @()
    $evidence = [ordered]@{}

    # Iterate the requirements, not the returned rows: a subcategory that
    # auditpol fails to return must surface as a problem, not pass silently.
    $lookup = @{}
    foreach ($item in $settings) { $lookup[$item.Subcategory] = $item.Setting }

    foreach ($sub in $required.Keys) {
        $actual = $lookup[$sub]
        $evidence[$sub] = "required=$($required[$sub] -join ' and '); actual=$actual"

        if (-not $actual) {
            $problems += "$sub was not returned by auditpol"
            continue
        }

        $missing = $required[$sub] | Where-Object { $actual -notlike "*$_*" }
        if ($missing) {
            $problems += "$sub is '$actual', needs $($required[$sub] -join ' and ')"
        }
    }

    if ($problems.Count -eq 0) {
        New-CheckResult -ControlId $controlId -Title $title -Resource $VMName `
            -Status 'pass' `
            -Detail 'All four logon-related subcategories audit at the required level' `
            -Evidence $evidence
    }
    else {
        New-CheckResult -ControlId $controlId -Title $title -Resource $VMName `
            -Status 'fail' `
            -Detail ($problems -join '; ') `
            -Evidence $evidence
    }
}