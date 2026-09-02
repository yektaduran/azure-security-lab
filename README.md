# Azure Security Lab

Infrastructure as code, configuration baselines, automated compliance checking
and detection engineering — built end to end on a live Azure subscription.

Every control in this repository was written against a real environment, checked
by code that runs on a schedule, and validated by making it fail before trusting
it to pass.

---

## What is here

| Directory | Contents |
|---|---|
| `terraform/` | Seventeen Azure resources under management, deployed through a GitHub Actions pipeline authenticating over OIDC with no stored secret. Every pull request runs `terraform fmt -check`, `terraform validate` and `tfsec` before producing a plan. |
| `ansible/` | Four Linux hardening roles — SSH, kernel parameters, auditd, host firewall — applied from a WSL control node. |
| `baselines/` | 28 configuration controls across eight documents, each in a fixed six-field format: rationale, applies to, check, remediation, evidence, status. |
| `python/` | A compliance checker that evaluates the live subscription against those controls and writes timestamped JSON and HTML evidence. |
| `kql/` | Sentinel detection queries, each carrying its MITRE mapping, tuning rationale and validation record. |
| `.github/workflows/` | Two pipelines: `terraform.yml` validates and plans infrastructure changes with apply behind a manual trigger, `compliance.yml` runs the baseline checks. |

## Environment

Two virtual machines — Windows Server 2025 and Ubuntu 22.04 — in a single
resource group, with a Log Analytics workspace and Microsoft Sentinel collecting
from both. Windows security events and Linux auth logs arrive through two
separate data collection rules, deliberately scoped narrowly to control ingest
cost. Terraform state lives in Azure Storage with shared key access disabled, so
the backend runs entirely on Entra ID authentication.

## Running the compliance checker

```bash
cd python
pip install -r requirements.txt
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
python run_checks.py
```

Authentication uses `DefaultAzureCredential`, so the same code runs locally
against `az login` and in the pipeline against OIDC with no changes.

Results carry one of four statuses:

- **pass** — the resource meets the control
- **fail** — it does not, and this was not expected
- **deviation** — it does not, and the deviation is documented and accepted in `baselines/`
- **error** — the check could not run at all

Only `fail` and `error` break the build. A check that could not run has proven
nothing, so it is never treated as a pass.

The checks run on every push and pull request touching `python/`, `baselines/` or
the workflow itself, and daily at 06:00 UTC. Reports are retained as build artifacts for 90 days.

---

## Findings

Each of these was found by the tooling in this repository rather than by
inspection, and each changed how something works.

**An NSG rule named for a restriction it did not apply.** `Allow-RDP-MyIP` had
its source set to `*` — RDP was open to the internet. The name described the
intent; the configuration did not implement it. Now codified in Terraform from a
variable, and checked by evaluating rule behaviour rather than rule names.

**A VM extension silently reversing host hardening.** Setting a console recovery
password caused the platform agent to write an SSH configuration drop-in
enabling password authentication. Ubuntu includes that directory before the main
config file and OpenSSH keeps the first value it reads, so the hardening was
present in the file and inert in practice. The Ansible role was idempotent
throughout — it kept reporting success. Only attempting an actual password login
found it.

**Two roles fighting over the same kernel setting.** The firewall role reapplied
its own sysctl file on every reload, undoing values set by the hardening role.
The first run looked clean; only the idempotency re-run exposed it. Resolved by
giving kernel parameters a single owner.

**An entire environment outside the tooling's field of view.** A resource group
in another region, left from an earlier attempt, was invisible to Terraform, the
checker, the baselines and Sentinel — all of which were scoped to one resource
group. Defender for Cloud, which assesses the whole subscription, reported it.
This produced control AZ-GOV-001, which now compares the subscription's actual
contents against the managed set.

The pattern across all four: a tool reports on what its scope admits, and
verification that shares the tool's assumptions confirms them rather than testing
them.

---

### Observation: Secure Score measures visibility, not security

Three score values, zero configuration changes on the resources themselves:

| Date | Score | Cause |
|------|-------|-------|
| 2026-08-15 | 56% | Baseline on the free tier |
| 2026-08-17 | 51% | Defender for Servers Plan 2 enabled: more assessment coverage surfaced more findings |
| 2026-09-01 | 68% | VMs deallocated for days: assessments went stale or NotApplicable, score drifted up |

More visibility lowered the score; less signal raised it. The score is a function of
what the platform can see. Same lesson as the orphaned resource group finding (AZ-GOV-001).
---

## Known gaps

- AzurePolicyforLinux (Guest Configuration) is Failed on vm-lnx-lab-01, so Azure cannot attest the six Linux hardening controls.
- File Integrity Monitoring produces no data; the pending MMA-to-MDE FIM migration is the likely blocker. Not pursued before teardown.
- MFA enforcement and subnet-NSG association remain unassessed (the former needs Entra ID sign-in logs in the workspace).
- AZ-WIN-004 (SMBv1) and AZ-WIN-005 (local Administrators membership) are specified but unwritten.
- powershell/ checks run locally, not in the pipeline.