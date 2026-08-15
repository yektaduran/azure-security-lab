# Identity and Access Baseline

**Scope:** Entra ID tenant `Default Directory`, the lab subscription, and all
role assignments affecting `RG-Security-Lab-WestUS2`.

**Framework mapping:** CIS Microsoft Azure Foundations Benchmark v2.1 §1,
NIST SP 800-53 AC-2, AC-6, IA-2, MITRE ATT&CK TA0004 (Privilege Escalation).

---

## AZ-IAM-001 — No standing subscription Owner assignments

**Rationale**

Owner carries full control including the ability to grant further access, so
a compromised Owner session compromises the entire subscription with no
lateral movement required. A standing assignment is available to an attacker
at every moment, not only when the legitimate holder is working.

Eligible assignments through Privileged Identity Management reduce the
window: the role must be activated, activation can require approval and
justification, and it expires automatically. The permission still exists,
but the time during which it can be stolen shrinks from permanent to the
length of an activation.

Duplicate assignments to the same principal are a secondary concern. They
create ambiguity about which assignment is authoritative and complicate any
future removal, since revoking one leaves access intact through the other.

**Applies to**

All role assignments at subscription scope, in particular Owner, Contributor
and User Access Administrator.

**Check**

```bash
az role assignment list --subscription <subscription-id> \
  --include-inherited \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator'].{principal:principalName, role:roleDefinitionName, scope:scope}" \
  -o table
```

Any permanent Owner assignment to a user account is a fail where PIM is
available. Duplicate assignments to the same principal are a fail
regardless.

**Remediation**

1. Create a dedicated administrative account distinct from the day-to-day
   identity, or convert the existing assignment to PIM-eligible.
2. Assign the least privileged built-in role that covers routine work —
   Contributor scoped to the resource group is usually sufficient for lab
   operations — and reserve Owner for role management.
3. Remove duplicate assignments only after confirming which one is
   authoritative, and never remove the last path to access without a tested
   alternative in place.

**Evidence**

Role assignment export before and after, plus PIM activation history showing
that elevated use is time-bound and justified.

**Status — deviation accepted**

The operator account holds two Owner assignments inherited from the
subscription, both permanent. PIM is not configured; it requires an Entra ID
P2 licence, which the trial subscription does not include.

Accepted for a single-operator lab where no other principal has access and
where removing the last Owner path risks losing control of the subscription
entirely. Not acceptable in any multi-user environment.

To be revisited during the identity phase, where the correct exercise is to
build a least-privileged secondary identity and a custom role definition
rather than simply deleting one of the two entries.

---

## AZ-IAM-002 — Automation identities use least privilege

**Rationale**

Automation components authenticate as themselves rather than as a person, so
their permissions are permanent, unattended and easily over-granted. A
playbook holding Contributor on a resource group can do far more than post a
comment on an incident, and nothing in the automation itself constrains it
to its intended function.

Two properties matter: the identity should be system-assigned rather than a
service principal with a stored secret, so there is no credential to leak or
rotate, and the role should be the narrowest one that permits the intended
action.

**Applies to**

Logic App playbooks, function apps, deployment identities and the Sentinel
service principal.

**Check**

```bash
az role assignment list --resource-group <rg> \
  --query "[?principalType=='ServicePrincipal'].{principal:principalName, role:roleDefinitionName, scope:scope}" \
  -o table
```

Review each result against the action the component actually performs.
Contributor or Owner held by an automation identity is a fail unless
specifically justified.

**Remediation**

1. Enable a system-assigned managed identity on the component and remove any
   stored client secret.
2. Grant the narrowest applicable role at the narrowest applicable scope.
3. Re-test the automation end to end, since an under-granted identity fails
   silently in some connectors.

**Evidence**

Role assignment export, plus a successful execution record for the
automation proving the reduced permission set is sufficient.

**Status — pass**

Three automation identities, all scoped to the narrowest role their function
requires:

- `Azure Security Insights` (the Sentinel service principal) holds
  **Microsoft Sentinel Automation Contributor**, permitting it to trigger
  playbooks and nothing more.
- The `PB-Enrich-FailedLogon-Incident` Logic App uses a system-assigned
  managed identity holding **Microsoft Sentinel Responder**, sufficient to
  modify an incident. Contributor was deliberately not used.
- `gh-actions-azure-security-lab` (appId c31b8284-f4dc-4411-8075-18112cdda06d)
  authenticates over OIDC with no client secret and holds:

| Role | Scope | Why |
|---|---|---|
| Contributor | RG-Security-Lab-WestUS2 | `terraform apply` — write access confined to the managed resource group |
| Storage Blob Data Contributor | stseclabtfstate | State file access over Entra ID; the account has no shared key enabled |
| Reader | Subscription | AZ-GOV-001 must enumerate resource groups outside the managed one; a resource-group-scoped identity structurally cannot perform that check |

The asymmetry in that last assignment is deliberate. Write access stays as
narrow as the work requires; read access extends to whatever the audit must
cover. A control's scope cannot be narrower than the thing it is auditing, or
it reports clean by omission.

No stored secrets are involved in any of the three paths.

Verify with:

```bash
az role assignment list --assignee 6360628e-c500-454b-a8fc-fc5254e62e62 --all -o table
```

The `--all` flag is required; without it the command returns only assignments
at the default scope and silently omits the others.

---

## AZ-IAM-003 — Multi-factor authentication enforced on interactive sign-ins

**Rationale**

Password-only authentication fails against credential stuffing, phishing and
password spray — the same attack class the lab's own detection rules were
built to identify. MFA is the single control with the largest measured
reduction in account compromise, and it is the prerequisite for any
meaningful conditional access policy.

**Applies to**

All user accounts with any role assignment in the subscription, without
exception for administrators. Administrator accounts are the highest
priority, not a candidate for exemption.

**Check**

Review Conditional Access policies and per-user authentication methods in
the Entra admin centre, and confirm sign-in logs show a second factor for
administrative sessions:

```kusto
SigninLogs
| where TimeGenerated > ago(30d)
| summarize by UserPrincipalName, AuthenticationRequirement, ResultType
```

Any administrative sign-in with `AuthenticationRequirement` of
`singleFactorAuthentication` is a fail.

**Remediation**

1. Enable security defaults, or build a Conditional Access policy requiring
   MFA for all users if licensing permits the more granular approach.
2. Register a phishing-resistant method — passkey or authenticator app with
   number matching — in preference to SMS.
3. Confirm through sign-in logs rather than through the policy definition,
   since a policy in report-only mode enforces nothing.

**Evidence**

Conditional Access policy export showing the policy is enabled rather than
report-only, plus the sign-in log query output covering the review period.

**Status — not assessed**

Neither the tenant's Conditional Access configuration nor the sign-in logs
have been reviewed. `SigninLogs` requires the Entra ID diagnostic setting to
be forwarded to the workspace, which is not yet configured — so this control
currently cannot be evidenced even if it is met.

Assessing this is the first task of the identity phase.
