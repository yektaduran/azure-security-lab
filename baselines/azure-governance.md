\# Azure Governance Baseline



Controls in this family are \*\*subscription-scoped\*\*. Every other baseline in

this repository evaluates resources inside RG-Security-Lab-WestUS2; these

evaluate the subscription itself, including everything outside that boundary.



\---



\## AZ-GOV-001 — All resource groups in the subscription are managed by Terraform



\*\*Rationale\*\*

Resource management in this project is resource-group scoped: Terraform manages

RG-Security-Lab-WestUS2, the Python checker scans it, the baselines describe it,

and Sentinel collects from it. Auditing must be subscription scoped, because a

resource outside the managed boundary has no owner, no code, no baseline and no

detection covering it. The gap between the two scopes is, by definition, the set

of resources nobody is watching.



\*\*Applies to\*\*

Subscription d0ef3c7a-ba61-4f20-ae6d-c952e94459c0 (all resource groups).



\*\*Check\*\*

`python run\_checks.py` — control AZ-GOV-001, implemented in

`python/checks/governance.py`. Enumerates every resource group in the

subscription and compares against `MANAGED\_RESOURCE\_GROUPS` in

`python/config.py`. Manual equivalent: `az group list -o table`.



Runs on every scheduled and PR execution of `.github/workflows/compliance.yml`.

The pipeline identity holds Reader at subscription scope specifically so this

control can see beyond its own resource group.



\*\*Remediation\*\*

For an unmanaged resource group, one of:

\- Bring it under Terraform (`terraform import`) and add it to

&#x20; `MANAGED\_RESOURCE\_GROUPS`, or

\- Delete it if it serves no purpose, or

\- If it is created and owned by the Azure platform and cannot meaningfully be

&#x20; placed under Terraform, add it to `PLATFORM\_MANAGED\_RESOURCE\_GROUPS` with a

&#x20; written justification.



\*\*Evidence\*\*

`python/reports/compliance-\*.json`. Each AZ-GOV-001 result carries a

`classification` field with one of `unmanaged`, `platform-managed` or `summary`,

plus the resource group's location and resource count.



\*\*Status — FAIL\*\*



| Resource group | Location | Resources | Classification |

|---|---|---|---|

| RG-Security-Lab | northeurope | 2 | unmanaged — open finding |

| NetworkWatcherRG | — | 1 | platform-managed — reviewed, out of scope |



`RG-Security-Lab` holds VNET-Security-Lab and NSG-Web-Subnet, left over from the

initial North Europe attempt that was blocked by the tenant-root deny policy

`sys.blockwesteurope`. No VMs, no public IPs, no cost. Deliberately left in place

so the control could be validated against real data. Decision on import versus

deletion is outstanding.



\---



\## Notes



\### Why this control exists



This control was not planned. It was written because Defender for Cloud reported

findings against `vnet-security-lab` — a resource that none of this project's own

tooling could see. Terraform, the compliance checker, the baselines and Sentinel

were all scoped to a single resource group; Defender for Cloud assesses the whole

subscription, so it saw what they structurally could not.



The lesson generalises beyond this finding: a tool can only report on what its

scope admits, and a scope narrower than the environment produces reports that

look clean because they are incomplete. Independent verification from a

differently-scoped tool is what surfaced it.



\### Tuning rationale — NetworkWatcherRG



Azure creates `NetworkWatcherRG` automatically when Network Watcher is enabled in

a region. It cannot meaningfully be brought under Terraform and is not evidence

of a governance failure, so it does not fail the control.



It is classified rather than suppressed: the check still emits a result for it,

marked `passed=True`, stating why it is out of scope. Silently skipping it would

leave a resource group absent from the report with no record that it was ever

considered — and "why is this missing?" is a harder question to answer later than

"why is this here?".



This mirrors the tuning decision in `kql/detections/linux-account-persistence.kql`,

where AMA service accounts are excluded by a stated property (UID < 1000) rather

than by name, with the reasoning recorded alongside the query.



\### Known limitation



`governance.py` has no error handling for an authorization failure. If the

identity running the check loses Reader at subscription scope, the SDK raises and

the entire checker aborts — including the other controls, which would otherwise

have run fine. "Control failed" and "control could not run" are also

indistinguishable in the current report, since `CheckResult` carries only a

boolean. Both are open items.

