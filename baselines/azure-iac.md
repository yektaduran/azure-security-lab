# Infrastructure as Code Security Baseline

**Scope:** The Terraform configuration under `terraform/`, its state backend,
and the version control repository holding it.

**Framework mapping:** NIST SP 800-53 CM-2, CM-3, SA-11, SA-15,
OWASP Top 10 CI/CD Security Risks.

---

## AZ-IAC-001 — State backend uses identity-based access

**Rationale**

Terraform state is a high-value target: it records every managed resource
and stores attribute values in plaintext, including credentials that the
provider accepted as input. Accessing that state through a storage account
key means a single long-lived shared secret protects the entire
environment's blueprint, with no attribution in the audit log and no ability
to scope access down.

Entra ID authentication replaces that secret with short-lived tokens tied to
a named principal, so access is attributable, revocable, and constrained by
a role assignment that can be scoped to the single account.

**Applies to**

All remote state backends.

**Check**

Inspect the backend block:

```hcl
backend "azurerm" {
  use_azuread_auth = true
}
```

`use_azuread_auth` absent or false is a fail. Confirm the account key is not
supplied through `access_key`, an `ARM_ACCESS_KEY` environment variable, or
a backend config file.

**Remediation**

1. Set `use_azuread_auth = true` in the backend block.
2. Grant the operator or pipeline identity **Storage Blob Data Contributor**
   scoped to the state storage account. Owner at subscription scope does not
   grant data-plane access; this is the most common failure point.
3. Re-run `terraform init` and confirm the backend initialises.

**Evidence**

The backend configuration from version control, plus a successful
`terraform init` log showing the backend configured without a key.

**Status — pass**

`use_azuread_auth = true` against container `tfstate` in `stseclabtfstate`,
key `security-lab.tfstate`. Data-plane access granted through a single
Storage Blob Data Contributor assignment scoped to the account. No account
key has been retrieved or configured at any point.

State locking is active and confirmed in every plan run, which prevents
concurrent applies from corrupting state — a property local state cannot
provide.

---

## AZ-IAC-002 — No secrets committed to version control

**Rationale**

A secret committed to Git is not removed by deleting it in a later commit;
it remains in history and in every clone. This makes version control a
one-way door for credentials, and treating it as such is the only workable
posture.

Two file classes carry the highest risk in a Terraform repository: variable
value files, which hold whatever was passed in, and state files, which hold
resolved attribute values in plaintext. Both must be excluded before the
first commit, not after.

**Applies to**

The entire repository, at every commit.

**Check**

```bash
git check-ignore -v terraform/terraform.tfvars
git status -u
git log --all --full-history -- "*.tfvars" "*.tfstate"
```

The first command must return a matching rule. The second must not list
`.tfvars`, `.tfstate` or `.terraform/`. The third must return nothing — if
it returns a commit, the secret is in history and must be treated as
compromised and rotated, not merely deleted.

**Remediation**

1. Add `*.tfvars`, `*.tfstate`, `*.tfstate.backup`, `.terraform/` and
   `crash.log` to `.gitignore` before the initial commit.
2. Where a secret has already been committed, rotate the credential first,
   then rewrite history. Rotation is the control; history rewriting is
   cleanup.
3. Pass values through environment variables prefixed `TF_VAR_` in automated
   contexts rather than through a file.

**Evidence**

Output of the three commands above, plus the commit listing showing which
files entered the repository.

**Status — pass**

`.gitignore` verified working before the initial commit on 2026-08-11. The
first commit contains six files — `.gitignore`, four `.tf` files and
`.terraform.lock.hcl` — and no variable or state file. The VM administrator
password and the administrative source IP are held only in
`terraform.tfvars`, which is excluded, and `vm_admin_password` is declared
`sensitive = true` so it is masked in plan output.

The lock file is deliberately committed: it pins provider versions by hash,
which is a supply-chain control rather than an oversight.

---

## AZ-IAC-003 — Infrastructure code scanned before apply

**Rationale**

Reviewing a Terraform plan by eye catches what the reviewer thinks to look
for. Automated scanning catches the classes of misconfiguration that are
easy to miss and easy to repeat — an NSG open to the internet, a storage
account without secure transfer, an unencrypted disk — before they reach the
environment rather than after.

The plan output itself also requires human attention at a specific moment. A
plan proposing to destroy and recreate a resource looks superficially like
an ordinary update; only reading the `forces replacement` annotation
distinguishes them. Any pipeline that applies without a human reading the
plan removes the one control that catches this.

**Applies to**

Every change to the Terraform configuration.

**Check**

Confirm that the following run on every change, and that the pipeline fails
on a non-zero exit:

```bash
terraform fmt -check -recursive
terraform validate
tfsec .          # or: checkov -d .
terraform plan -out=tfplan
```

**Remediation**

1. Add the format and validation checks first — they are offline, fast, and
   require no credentials, so they belong at the front of the pipeline.
2. Add a security scanner and set a severity threshold that fails the build.
3. Produce the plan on pull request and post it as a comment; require
   approval before apply on merge.
4. Authenticate the pipeline through OIDC workload identity federation
   rather than a stored service principal secret, so no long-lived
   credential exists in the CI system.

**Evidence**

Pipeline run history showing each stage's result, and the approval record
tying an apply to the plan that was reviewed.

**Status — deviation accepted**

`terraform fmt -check -recursive` and `terraform validate` both pass, run
manually. No security scanner is configured and no pipeline exists — the
repository is local, with no remote configured.

The manual process currently satisfies the intent: every plan to date has
been read before any apply, and doing so caught a proposed destroy-and-
recreate of the VM that would have destroyed the lab. But the control
depends entirely on operator discipline and produces no evidence trail.

To be closed by adding a GitHub Actions workflow with OIDC authentication,
scanning, and plan-on-PR with manual approval before apply.
