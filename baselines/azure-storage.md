# Azure Storage Security Baseline

**Scope:** Storage accounts in `RG-Security-Lab-WestUS2`, in particular
`stseclabtfstate`, which holds the Terraform state for the entire lab.

**Framework mapping:** CIS Microsoft Azure Foundations Benchmark v2.1 §3,
NIST SP 800-53 SC-8, SC-28, AC-3.

---

## AZ-STO-001 — Public network access must be restricted

**Rationale**

This storage account holds the Terraform state for the entire lab. The state
file contains the VM administrator password in plaintext, along with every
resource identifier, address range and topology detail of the environment,
which makes it the most sensitive single object in the subscription.

With public network access enabled for all networks, the blob data-plane
endpoint is reachable from any source on the internet, leaving authentication
as the only control standing between an external caller and that file.

The risk is therefore not anonymous access, which is already disabled, but
the loss of a credential: a leaked account key or a compromised Entra
identity can be used from anywhere. A network restriction acts as a
compensating control in exactly that scenario, since a stolen credential is
worthless from an unapproved source address.

**Applies to**

All storage accounts in scope. The requirement is strictest for accounts
holding state files, secrets or audit data.

**Check**

```bash
az storage account show \
  --name <account> \
  --resource-group <resource-group> \
  --query "{publicAccess:publicNetworkAccess, defaultAction:networkRuleSet.defaultAction, privateEndpoints:length(privateEndpointConnections)}" \
  -o json
```

Pass requires either `publicAccess = Disabled` with a private endpoint in
place, or `publicAccess = Enabled` together with
`defaultAction = Deny` and an explicit allow list. The two fields must be
read together: `publicNetworkAccess = Enabled` on its own is not a failure,
because the network rule set can still deny by default. It is the
combination of `Enabled` and `Allow` that leaves the endpoint open.

**Remediation**

1. Set the network rule default action to `Deny`.
2. Add an explicit rule for the administrative source address, or for the
   virtual network subnet from which Terraform is executed.
3. For a production equivalent, add a private endpoint and set public
   network access to `Disabled` outright.

**Evidence**

The JSON output of the check command, showing the effective default action
and the allow list, captured after remediation and dated.

**Status — deviation accepted**

`publicNetworkAccess = Enabled`, `defaultAction = Allow`, no private
endpoints. The endpoint is reachable from any internet source, protected
only by Entra ID authentication and RBAC.

Accepted on 2026-08-10 for a single-operator lab running from a dynamic
residential address, where a deny-by-default rule would lock Terraform out
whenever the address changes. Compensating controls in place: anonymous
access disabled, secure transfer required, TLS 1.2 minimum, blob versioning
and soft delete enabled, and data-plane access granted through a single
scoped Entra role assignment rather than a shared key.

To be remediated when a private endpoint is introduced.

---

## AZ-STO-002 — Shared key access must be disabled

**Rationale**

A storage account key grants unrestricted control over every container and
blob in the account. It is a long-lived, shared secret: it carries no user
identity, so its use cannot be attributed to a person in the audit log, and
it cannot be scoped down to a single container or to read-only access.
Rotating it requires coordinating every consumer at once.

Once Entra ID authorisation is in use, the keys serve no operational purpose
but remain valid. Leaving them enabled preserves a credential that bypasses
every RBAC assignment protecting the account.

**Applies to**

All storage accounts whose consumers support Entra ID authorisation.

**Check**

```bash
az storage account show \
  --name <account> \
  --resource-group <resource-group> \
  --query "allowSharedKeyAccess" \
  -o tsv
```

`true` is a fail once all consumers have been migrated to Entra ID.

**Remediation**

1. Confirm every consumer authenticates with Entra ID. For this lab that
   means the Terraform backend (`use_azuread_auth = true`) and the operator's
   own CLI session (`--auth-mode login`).
2. Disable shared key access:
   ```bash
   az storage account update --name <account> --resource-group <rg> \
     --allow-shared-key-access false
   ```
3. Re-run `terraform plan` to confirm the backend still initialises.

**Evidence**

Check output showing `false`, together with a successful `terraform plan`
run from the same day proving the backend still functions without keys.

**Status — deviation accepted**

`allowSharedKeyAccess = true`. Deliberately left enabled on 2026-08-10 as a
fallback while the Entra ID path was being proven. The Terraform backend and
all CLI operations to date have used Entra ID exclusively; no key has been
retrieved or distributed.

This deviation has no remaining justification and should be closed next.
Disabling it is a single command and reversible.

---

## AZ-STO-003 — Secure transfer and minimum TLS version

**Rationale**

Without secure transfer required, the account accepts plaintext HTTP, which
exposes both the payload and the SAS token or authorisation header in
transit. TLS versions below 1.2 carry known weaknesses and are rejected by
most compliance regimes.

**Applies to**

All storage accounts.

**Check**

```bash
az storage account show --name <account> --resource-group <rg> \
  --query "{httpsOnly:enableHttpsTrafficOnly, tls:minimumTlsVersion, anonymous:allowBlobPublicAccess}" -o json
```

Pass requires `enableHttpsTrafficOnly = true`, `minimumTlsVersion = TLS1_2`
or higher, and `allowBlobPublicAccess = false`.

**Remediation**

Set each property through the portal or `az storage account update`. All
three are non-disruptive on a modern client.

**Evidence**

Check output, dated, retained with the account's configuration record.

**Status — pass**

Secure transfer enabled, TLS 1.2 minimum, anonymous blob access disabled,
cross-tenant replication disabled. Configured at account creation on
2026-08-10.

---

## AZ-STO-004 — Recovery controls on state storage

**Rationale**

Terraform state is overwritten on every apply. Blob soft delete recovers a
deleted blob but does not recover an overwritten one, so soft delete alone
does not protect against a corrupted or truncated state write. Versioning is
what allows a rollback to the previous known-good state, and losing state
means losing Terraform's record of which real resources it manages.

**Applies to**

Storage accounts holding Terraform state, backups or audit data.

**Check**

```bash
az storage account blob-service-properties show \
  --account-name <account> --resource-group <rg> \
  --query "{versioning:isVersioningEnabled, softDelete:deleteRetentionPolicy.enabled, days:deleteRetentionPolicy.days}" -o json
```

Pass requires versioning enabled and a soft delete retention of at least
seven days.

**Remediation**

Enable blob versioning and soft delete on the blob service properties.
Enable container soft delete alongside them, since deleting the container
removes the blobs with it.

**Evidence**

Check output plus a documented restore test: a state blob restored from a
previous version, with the date and the version identifier used.

**Status — pass**

Blob versioning enabled, blob soft delete 7 days, container soft delete
7 days. Restore has not yet been tested — the control is configured but
unproven, and a restore test should be performed before this is treated as
fully evidenced.
