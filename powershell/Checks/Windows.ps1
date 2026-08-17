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
    # which the first version of this check duly produced.
    $required = @{
        'Logon'           = @('Success', 'Failure')
        'Logoff'          = @('Success')
        'Account Lockout' = @('Success', 'Failure')
        'Special Logon'   = @('Success')
    }
    $inner = @'
$required = 'Logon','Logoff','Account Lockout','Special Logon'
$rows = auditpol /get /subcategory:"Logon","Logoff","Account Lockout","Special Logon" /r |
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
    $evidence = @{}

    foreach ($item in $settings) {
      $evidence[$item.Subcategory] = $item.Setting

      $needs = $required[$item.Subcategory]
      $missing = $needs | Where-Object { $item.Setting -notlike "*$_*" }

      if ($missing) {
          $problems += "$($item.Subcategory) is '$($item.Setting)', needs $($needs -join ' and ')"
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