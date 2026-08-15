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
| `terraform/` | Nine Azure resources under management, deployed through a GitHub Actions pipeline authenticating over OIDC with no stored secret. `tfsec` runs on every pull request. |
| `ansible/` | Four Linux hardening roles — SSH, kernel parameters, auditd, host firewall — applied from a WSL control node. |
| `baselines/` | 28 configuration controls across eight documents, each in a fixed six-field format: rationale, applies to, check, remediation, evidence, status. |
| `python/` | A compliance checker that evaluates the live subscription against those controls and writes timestamped JSON and HTML evidence. |
| `kql/` | Sentinel detection queries, each carrying its MITRE mapping, tuning rationale and validation record. |

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

The checks run on every push and pull request touching `python/` or `baselines/`,
and daily at 06:00 UTC. Reports are retained as build artifacts for 90 days.

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

## Known gaps

**Change control is unenforced.** A branch ruleset requiring pull requests and
passing checks is configured but not applied — GitHub does not enforce rulesets
on private repositories under this plan. Direct pushes to `main` remain possible.
The intent is currently met by operator discipline alone.

**Dependencies are unpinned.** `requirements.txt` specifies no versions. A major
release of an Azure SDK package has already broken an import once. The pipeline
also runs Python 3.12 while local development is on 3.14.

**Vulnerability management is not covered here.** These baselines address
misconfiguration. Vulnerability assessment on the Azure side requires Defender
for Servers, which is a paid plan and deliberately left disabled; that work is
being done separately.

**Two controls are unassessed.** MFA enforcement cannot be evidenced until Entra
ID sign-in logs are forwarded to the workspace, and subnet NSG association has
not been checked.