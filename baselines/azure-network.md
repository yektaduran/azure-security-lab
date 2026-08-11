# Azure Network Security Baseline

**Scope:** Virtual networks, subnets, network security groups and public IP
addresses in the `RG-Security-Lab-WestUS2` resource group.

**Framework mapping:** CIS Microsoft Azure Foundations Benchmark v2.1 §6,
NIST SP 800-53 SC-7, MITRE ATT&CK T1133 (External Remote Services).

**Review cadence:** Monthly, and on every change to an NSG rule set.

---

## AZ-NET-001 — Remote administration ports must not be exposed to the internet

**Rationale**

An inbound NSG rule that allows RDP (3389) or SSH (22) from `*`, `Internet`
or `0.0.0.0/0` makes the host reachable from any source on the public
internet. This is the most common initial access path for credential
brute-force and password-spray attacks against Windows hosts, and it
generates continuous authentication noise that masks genuine intrusion
attempts. A rule name that implies restriction (for example
`Allow-RDP-MyIP`) is not evidence of restriction; only the effective
source prefix is.

**Applies to**

All network security groups associated with a subnet or a network
interface within scope.

**Check**

```bash
az network nsg rule list \
  --nsg-name <nsg-name> \
  --resource-group <resource-group> \
  --query "[?access=='Allow' && direction=='Inbound' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet' || sourceAddressPrefix=='0.0.0.0/0') && (destinationPortRange=='3389' || destinationPortRange=='22' || destinationPortRange=='*')].{name:name, port:destinationPortRange, source:sourceAddressPrefix}" \
  -o table
```

A non-empty result is a **fail**. Note that `destinationPortRange` of `*`
must be treated as a fail even though the port is not named explicitly,
since it covers the administration ports.

**Remediation**

1. Narrow the rule source to a named administrative IP address or range.
2. Where an operator IP is dynamic, prefer Azure Bastion or Defender for
   Cloud just-in-time VM access over a standing allow rule.
3. Re-run the check and confirm an empty result.

**Evidence requirement**

An export of the NSG rule set showing the effective source prefix, taken
after remediation, carrying a timestamp and referencing the change record
that authorised the modification. A screenshot of the portal blade is not
sufficient on its own because it does not capture the full rule object.

**Current status**

`NSG-Security-VM-01` / rule `Allow-RDP-MyIP` was found with
`sourceAddressPrefix = *` on 2026-08-10 — RDP was reachable from the whole
internet despite the rule name. Source narrowed to the administrative IP
the same day and the rule was subsequently codified in Terraform, with the
address held in a variable rather than committed to the repository.

**Accepted deviation**

The control is met by a static IP allow rule rather than by Bastion or
just-in-time access. The operator address is a dynamic residential IP, so
the rule requires manual update whenever it changes, and any other host
behind the same public address is also permitted. Accepted for a lab
environment; to be revisited when Azure Bastion is introduced.

---

## AZ-NET-002 — *(to be written)*

Candidate controls for this file:

- No NSG rule may allow any protocol from any source to any destination
  (an effective `*/*/*` allow rule).
- Every subnet must have an NSG associated with it.
- NSG flow logs must be enabled and delivered to a storage account or
  workspace, so that denied and allowed traffic can be reconstructed
  after an incident.
