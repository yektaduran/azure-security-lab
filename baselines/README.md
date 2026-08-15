# Secure Configuration Baselines

Configuration standards for the Azure security lab, together with the checks
that verify them and the evidence required to demonstrate compliance.

## Scope

Everything in the `RG-Security-Lab-WestUS2` resource group of the lab
subscription: Windows Server 2025 and Ubuntu 22.04 virtual machines, 
Log Analytics workspace with Microsoft Sentinel, the Terraform state storage
account, and the identity configuration governing access to all of them.
Controls in the `AZ-GOV` family are the exception: they are subscription-scoped
by design, because a resource outside the managed resource group is precisely
what a resource-group-scoped baseline cannot see.

## Control format

Every control uses the same six fields. The format matters as much as the
content: a standard that cannot be checked automatically will not be checked
at all, and one without an evidence requirement cannot survive an audit.

| Field | Purpose |
|---|---|
| Rationale | Why the control exists, in terms of a specific attack path |
| Applies to | Which resources are in scope for this control |
| Check | A command that returns a deterministic pass/fail |
| Remediation | Concrete steps to bring a failing resource into compliance |
| Evidence | What artefact proves compliance, and to whom |
| Status | Current state in this environment, including accepted deviations |

Accepted deviations are recorded rather than hidden. A baseline whose every
control shows a clean pass is usually a baseline that was written after the
fact to match whatever the environment already did.

## Control index

| ID | Control | Status |
|---|---|---|
| AZ-NET-001 | Remote administration ports not exposed to the internet | Remediated |
| AZ-NET-002 | Every subnet has an NSG association | Not assessed |
| AZ-NET-003 | NSG flow logs enabled | Deviation |
| AZ-STO-001 | Storage public network access restricted | Deviation |
| AZ-STO-002 | Shared key access disabled | Pass |
| AZ-STO-003 | Secure transfer and TLS 1.2 enforced | Pass |
| AZ-STO-004 | Soft delete and versioning enabled on state storage | Pass |
| AZ-VM-001 | Trusted Launch enabled | Pass |
| AZ-VM-002 | No public IP directly attached to a workload VM | Deviation |
| AZ-VM-003 | Encryption at host enabled | Deviation |
| AZ-VM-004 | Monitoring agent installed and reporting | Pass |
| AZ-VM-005 | Automatic patching configured | Pass |
| AZ-IAM-001 | No standing subscription Owner assignments | Deviation |
| AZ-IAM-002 | Automation identities use least privilege | Pass |
| AZ-IAM-003 | MFA enforced on all interactive sign-ins | Not assessed |
| AZ-MON-001 | Security event collection configured | Pass |
| AZ-MON-002 | Detection rules produce triaged incidents | Pass |
| AZ-MON-003 | Log retention meets the defined minimum | Pass |
| AZ-IAC-001 | State backend uses identity-based access | Pass |
| AZ-IAC-002 | No secrets committed to version control | Pass |
| AZ-IAC-003 | IaC scanned for misconfiguration before apply | Pass (residual gap) |
| AZ-LNX-001 | SSH key-based auth, no direct root login | Pass |
| AZ-LNX-002 | SSH attack surface reduced | Pass |
| AZ-LNX-003 | Kernel network parameters tuned, single owner | Pass |
| AZ-LNX-004 | Out-of-band recovery exists without weakening the host | Pass |
| AZ-LNX-005 | Host firewall enforced independently of the NSG | Pass |
| AZ-LNX-006 | Host activity recorded for investigation | Pass |
| AZ-GOV-001 | All resource groups in the subscription are managed by Terraform | Pass |
| AZ-AI-001 | Generated code is validated against the environment | Pass |
| AZ-AI-002 | Generated facts are confirmed at their source | Pass |
| AZ-AI-003 | Sensitive material does not enter a prompt | Pass |
| AZ-AI-004 | Data reaching an LLM in an automated path is untrusted | Not applicable |

## Files

- `azure-network.md` — virtual network, subnets, NSGs
- `azure-storage.md` — storage accounts, with emphasis on state storage
- `azure-vm.md` — Windows virtual machine hardening
- `azure-identity.md` — RBAC, privileged access, managed identities
- `azure-monitoring.md` — logging, detection, retention
- `azure-iac.md` — Terraform and pipeline security
- `linux.md` — Linux host hardening (SSH, kernel, firewall, auditing)
- `azure-governance.md` — subscription-wide resource ownership
- `ai-assisted-work.md` — use of language models in producing this repository

## Review cadence

Monthly, and on any change to a control's underlying resource. Deviations
carry a review date; an accepted deviation with no expiry becomes permanent
by neglect.
