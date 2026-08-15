# AI-Assisted Work Baseline

**Scope:** The use of large language models in producing the infrastructure code,
detection queries, compliance checks and documentation in this repository.

**Framework mapping:** NIST AI RMF (Measure 2.5, Manage 4.1),
OWASP Top 10 for LLM Applications (LLM01 Prompt Injection, LLM09 Overreliance).

This baseline is unusual in that it governs how the rest of the repository was
built rather than a resource in the subscription. It exists because most of this
project was written with model assistance, and the failure modes that produced
were specific enough to control for.

---

## AZ-AI-001 — Generated code is validated against the environment before it is trusted

**Rationale**

Model output is syntactically correct and internally plausible by construction.
That is precisely what makes it hard to review: the reviewer is checking whether
code looks right, and it always does. The errors surface only on contact with a
real environment.

Reading generated code carefully is not a substitute. Every defect in this
project's generated code passed visual review and was caught by execution.

**Applies to**

Any compliance check, detection query, Terraform resource or Ansible task
produced with model assistance.

**Check**

A new control is not considered working until it has been observed producing
both outcomes against live data — a fail on a resource that violates it, and a
pass on one that does not. For a detection query, the equivalent is a validation
record showing which real event caused it to fire.

**Remediation**

Where a control has only ever been seen passing, deliberately introduce the
condition it detects and confirm it fails. Where that is not safe to do, record
the control as unvalidated rather than as passing.

**Evidence**

The validation record for each control. Examples in this repository:

- `AZ-GOV-001` was left failing against a real orphaned resource group until it
  had been proven in both the local environment and the pipeline, then the
  resource group was deleted and the control was observed turning green.
- `AZ-STO-003` was validated by enabling anonymous blob access, confirming the
  fail, and reverting.
- `AZ-DET-LNX-001` carries a validation record naming the account whose creation
  caused it to fire.

**Status — pass**

Every control in `python/checks/` has been observed both passing and failing.

Three defects reached working code and were caught this way rather than by
review:

- `checks/governance.py` passed `checked_at` explicitly, duplicating a field
  `base.py` already supplies through a default factory. The types disagreed and
  JSON serialisation failed at write time.
- A summary result was gated on an empty result list, which stopped being
  correct once platform-managed resource groups began populating that list. A
  separate finding counter was needed.
- An import path was generated for a package layout that had changed in a major
  release, producing an import error that named the symbol rather than the cause.

---

## AZ-AI-002 — Generated facts are confirmed at their source

**Rationale**

A model states counts, versions, resource states and command effects with the
same confidence whether or not it has grounds for them. These claims are the
most dangerous category of output because they are the least likely to be
checked: code gets run, but a sentence in a document does not.

Documentation carrying a wrong number is worse than documentation carrying none.
It reads as verified.

**Applies to**

Every quantitative or factual claim in `baselines/`, `README.md` and query
headers — resource counts, control counts, versions, dates, and any statement
that a configuration is in a particular state.

**Check**

Each such claim must be traceable to a command output. For this repository:

```bash
terraform state list | wc -l          # resource count
az resource list -g <rg> -o table     # what a resource group actually holds
az role assignment list --assignee <id> --all -o table
python run_checks.py                  # current control status
```

**Remediation**

Run the command. Where the claim cannot be tied to one, remove it rather than
softening it.

**Status — pass, with corrections on record**

Three claims were generated and later corrected against source:

- The README stated nine managed resources, carried over from the initial import
  set. `terraform state list` reported seventeen.
- An `az network watcher configure` command was described as having enabled
  Network Watcher for the region. `createdTime` on the resource showed it had
  existed since the day the VNet was created; the command returned the existing
  resource unchanged.
- A predicted check count of thirteen was stated before a run that produced
  twelve.

None of the three would have been caught by reading. All three were caught by
running something.

---

## AZ-AI-003 — Sensitive material does not enter a prompt

**Rationale**

Prompt content leaves the environment's trust boundary. Identifiers are
recoverable from a public repository anyway and carry little marginal risk;
credentials and private keys are unrecoverable once disclosed and cannot be
scoped, throttled or attributed after the fact.

The distinction is not sensitivity in the abstract but whether disclosure is
reversible. A subscription ID cannot be rotated and does not need to be. A
private key can be rotated and must be.

**Applies to**

All model interaction relating to this project.

**Check**

Before pasting, confirm the content is not a credential, private key, or the
contents of an excluded file — in this repository, `terraform.tfvars`, any
`*.tfstate`, and `~/.ssh/`.

**Remediation**

Where a secret has been disclosed, rotate it. Removing it from the conversation
is not remediation, exactly as deleting a committed secret from a later commit
is not remediation under `AZ-IAC-002`.

**Status — pass**

Shared during this project: subscription, tenant and application IDs, public IP
addresses, the administrative source IP, resource and account names, and the
contents of tracked files.

Not shared: the VM administrator password, the Linux SSH private key, the
storage account key, and the contents of `terraform.tfvars`.

The administrative source IP is the one item in the first list worth noting. It
is a residential address and it appears in `ansible/inventory.ini` in the commit
history, which is a separate finding — see the note on publishing this repository
in `azure-iac.md`.

---

## AZ-AI-004 — Data reaching an LLM in an automated path is treated as untrusted input

**Rationale**

A model reading attacker-influenced text cannot reliably distinguish instructions
in that text from instructions from its operator. Where a model sits in an
automated path, any field an attacker can write becomes an injection surface.

Security automation is a natural place for this to appear and an unusually bad
one. An incident summary, an alert description, a hostname, a username, a process
command line — all are attacker-controllable in exactly the incidents worth
summarising.

**Applies to**

Any future automation in this project that passes environment data to a model:
incident enrichment playbooks, log summarisation, report generation.

**Check**

For each such automation, identify which fields originate outside the
organisation's control, and confirm the model's output cannot take an action on
their behalf.

**Remediation**

1. Keep the model's output advisory. It may annotate an incident; it may not
   close one, change severity, or trigger a response action.
2. Pass untrusted content as clearly delimited data, and treat any instruction
   appearing inside it as content rather than direction.
3. Log the full prompt alongside the output, so an anomalous result can be
   traced to what produced it.

**Status — not applicable, controlled by design**

No automation in this project calls a model. `PB-Enrich-FailedLogon-Incident`
composes its comment from incident fields directly, with no model in the path,
so there is no injection surface.

This control is written before the exposure exists rather than after, because
the natural next step for that playbook — having a model summarise the incident —
would introduce it in a single change, and the reasoning is easier to apply than
to retrofit.

---

## Notes

### What this baseline does not claim

It does not claim the generated code was correct, or that model assistance was
free of cost. It claims the opposite: that the output required verification, that
verification found defects, and that the defects were of a consistent kind —
plausible, well-reasoned and wrong.

The controls above describe the verification that made the output usable. They
are the cost of the assistance, not a disclaimer attached to it.

### Why the failure mode is overreliance rather than injection

Prompt injection is the more discussed risk and the less relevant one here, since
no model sits in an automated path. Every actual defect in this project came from
the other direction: output that was accepted because it was well-formed. That is
`LLM09` in the OWASP list, and it is the reason `AZ-AI-001` and `AZ-AI-002` come
first.