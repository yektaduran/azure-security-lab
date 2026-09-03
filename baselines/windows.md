# Windows Host Baseline

**Scope:** vm-sec-lab-01 (Windows Server 2025). Checks execute inside the host
over `Invoke-AzVMRunCommand` through the guest agent — no RDP, no open port, no
account on the machine. Authorisation comes from Azure RBAC.

**Implementation:** `powershell/Checks/Windows.ps1`.

**Framework mapping:** CIS Microsoft Windows Server Benchmark, MITRE ATT&CK
T1562.002 (Impair Defenses: Disable Windows Event Logging).

---

## AZ-WIN-001 — Logon auditing produces the events the detections depend on

Audit policy for Logon, Logoff, Account Lockout and Special Logon must be set at
the level each subcategory can actually emit: Logon needs Success and Failure,
Logoff and Special Logon Success only, Account Lockout Failure only.

This control audits the detection pipeline itself. Every Sentinel rule in this
project rests on event 4625. If Logon auditing is turned off, Windows stops
producing the event, the analytics rules stop firing, and nothing reports a
fault — the pipeline is healthy, it is simply being sent nothing.

## AZ-WIN-002 — Defender real-time protection is enabled

`AMServiceEnabled`, `AntivirusEnabled` and `RealTimeProtectionEnabled` must all
be true. MDE onboarding gives visibility after the fact; real-time protection is
the part that acts while something is happening.

## AZ-WIN-003 — Windows Firewall enabled on all three profiles

Domain, Private and Public. The NSG filters at the fabric; the host firewall is
the layer that survives an NSG rule drifting — which this project produced once,
in `Allow-RDP-MyIP`.

---

## Status — not validated

None of these three controls has ever executed against the host.

They were written on 2 September 2026. The guest-side runs were scheduled for
3 September, the final day of the lab, and West US 2 could not allocate
`Standard_B2as_v2` that morning: `Start-AzVM` returned an allocation failure and
the VM entered a failed state. The subscription was torn down the same day.

Under AZ-AI-001, a control that has not been observed both passing and failing
is not a working control. All three were written with model assistance, which is
precisely the case that control was written for. Recording them as passing would
be the failure AZ-AI-001 exists to prevent, so they are recorded as unvalidated
instead.

What is demonstrated is the mechanism: `Invoke-AzVMRunCommand` was proven working
against this host on 17 August 2026, returning `nt authority\system`, and the
first version of AZ-WIN-001 ran successfully against real audit policy data. That
run is what exposed the bug in the original uniform Success-and-Failure
requirement, which is why the current version carries per-subcategory rules.