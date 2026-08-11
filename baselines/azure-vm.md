# Windows Virtual Machine Security Baseline

**Scope:** `vm-sec-lab-01` (Windows Server 2025 Datacenter Azure Edition,
Standard_B2as_v2) and any future Windows workload in
`RG-Security-Lab-WestUS2`.

**Framework mapping:** CIS Microsoft Azure Foundations Benchmark v2.1 §7,
CIS Microsoft Windows Server Benchmark, NIST SP 800-53 SI-2, SC-28, AC-17.

---

## AZ-VM-001 — Trusted Launch must be enabled

**Rationale**

Secure Boot verifies the bootloader and kernel signature at startup,
preventing a rootkit or bootkit from loading ahead of the operating system.
The virtual TPM provides a hardware root of trust for measured boot and for
key storage. Together they defend the layer beneath the operating system,
where endpoint protection has no visibility.

Both settings are fixed at deployment. They cannot be enabled on an existing
VM, which is why a Terraform plan that changes them shows a forced
replacement rather than an in-place update.

**Applies to**

All generation 2 virtual machines.

**Check**

```bash
az vm show --name <vm> --resource-group <rg> \
  --query "securityProfile.uefiSettings" -o json
```

Pass requires `secureBootEnabled = true` and `vTpmEnabled = true`.

**Remediation**

Cannot be remediated in place. The VM must be redeployed with
`security_type = "TrustedLaunch"` and both settings enabled. Plan the
rebuild rather than attempting a live change.

**Evidence**

Check output, plus the Terraform resource definition showing
`secure_boot_enabled` and `vtpm_enabled` set to `true`, so that the setting
is enforced on any future rebuild rather than depending on a portal default.

**Status — pass**

Both enabled. Codified in Terraform on 2026-08-10 after an import plan
initially proposed destroying and recreating the VM because these attributes
were absent from the configuration.

---

## AZ-VM-002 — No public IP directly attached to a workload VM

**Rationale**

A public IP on the VM's network interface places the host's management
surface directly on the internet. Every RDP listener reachable this way is
continuously scanned and subjected to credential attacks; the detection rules
in this lab exist precisely because that traffic arrives.

Restricting the NSG source address reduces exposure but does not eliminate
it: the address is still routable, still scannable, and any host sharing the
approved public address inherits the access.

**Applies to**

All virtual machines carrying a workload or holding credentials.

**Check**

```bash
az vm list-ip-addresses --name <vm> --resource-group <rg> -o json
```

Any populated `publicIpAddresses` entry on a workload VM is a fail.

**Remediation**

1. Deploy Azure Bastion in the virtual network and connect over the Azure
   backbone rather than the public internet.
2. Alternatively enable Defender for Cloud just-in-time VM access, which
   opens the management port only for an approved window and source.
3. Remove the public IP association from the network interface.

**Evidence**

Check output showing no public address, together with the Bastion or JIT
configuration and a sample of successful administrative sessions routed
through it.

**Status — deviation accepted**

`vm-sec-lab-01` holds a static Standard public IP with RDP permitted from a
single administrative address. Accepted because Azure Bastion costs
approximately USD 0.19 per hour continuously, which would consume a
significant share of the remaining trial credit, and because the exposure is
already narrowed at the NSG (see AZ-NET-001).

Residual risk acknowledged: the administrative address is a dynamic
residential IP, so the allow rule is periodically stale, and the RDP
listener remains reachable from that address by any host behind it.

Review when Bastion or JIT access is introduced.

---

## AZ-VM-003 — Encryption at host must be enabled

**Rationale**

Managed disks are encrypted at rest by default, but the temp disk, the OS
cache and the data flowing between the hypervisor host and the storage
service are not. Encryption at host closes that gap by encrypting the data
on the physical host itself, covering the paths that platform disk
encryption does not reach.

**Applies to**

All virtual machines handling sensitive data, and all VMs subject to a
regulatory encryption requirement.

**Check**

```bash
az vm show --name <vm> --resource-group <rg> \
  --query "securityProfile.encryptionAtHost" -o tsv
```

`false` or null is a fail.

**Remediation**

1. Register the `EncryptionAtHost` feature on the subscription if it is not
   already registered.
2. Deallocate the VM.
3. Set `encryption_at_host_enabled = true` and apply.
4. Start the VM and confirm the check now returns `true`.

Requires downtime but not a rebuild.

**Evidence**

Check output showing `true`, dated, with the change record covering the
maintenance window.

**Status — deviation accepted**

`encryptionAtHost = false`. Not enabled during the initial build. The VM
holds no production or personal data; its only sensitive content is the
local administrator credential, which is also present in Terraform state and
governed by AZ-STO-001 and AZ-STO-002.

Low effort to remediate. Suitable candidate to close alongside the next
planned maintenance window.

---

## AZ-VM-004 — Monitoring agent installed and reporting

**Rationale**

A host that does not forward security events cannot be monitored,
investigated or attested. The Azure Monitor Agent, driven by a data
collection rule, is the supported mechanism for delivering Windows Security
events to a Log Analytics workspace. An agent that is installed but not
delivering data is functionally equivalent to no agent at all, which is why
this control is verified against ingested data rather than against the
extension's provisioning state.

**Applies to**

All virtual machines in scope.

**Check**

Extension present:

```bash
az vm extension list --vm-name <vm> --resource-group <rg> \
  --query "[].{name:name, state:provisioningState}" -o table
```

Data actually arriving — run in the Log Analytics workspace:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| summarize Events = count(), LastSeen = max(TimeGenerated) by Computer
```

A host absent from the second result is a fail regardless of the first.

**Remediation**

1. Install the Azure Monitor Agent extension.
2. Associate the VM with a data collection rule that includes the
   `Microsoft-SecurityEvent` stream.
3. Confirm ingestion with the KQL query above.

**Evidence**

The KQL result showing event counts and a recent `LastSeen` timestamp for
every in-scope host, exported and dated.

**Status — pass**

`AzureMonitorWindowsAgent` installed and provisioned. Data collection rule
`dcr-sentinel-securityevents` delivers the `Microsoft-SecurityEvent` stream
to `LAW-Security-Lab`; 4625 events confirmed arriving in the `SecurityEvent`
table and driving live detections.

Note: while the VM is deallocated for cost control, no events are produced.
This is expected and not a control failure, but it does mean the check must
be run against a period when the host was running.

---

## AZ-VM-005 — Automatic patching configured

**Rationale**

Unpatched operating system vulnerabilities remain the most reliably
exploited weakness on internet-reachable hosts. Automatic patching by the
platform removes the dependency on an operator remembering to apply updates,
and produces an assessment record that can be queried rather than asserted.

**Applies to**

All virtual machines in scope.

**Check**

```bash
az vm show --name <vm> --resource-group <rg> \
  --query "osProfile.windowsConfiguration.patchSettings" -o json
```

Pass requires `patchMode = AutomaticByPlatform` and
`assessmentMode = AutomaticByPlatform`.

**Remediation**

Set both modes to `AutomaticByPlatform` and configure a maintenance
configuration if patching must occur in a defined window.

**Evidence**

Check output, plus a Defender for Cloud or Update Manager compliance report
showing outstanding patches and their age.

**Status — pass**

`patchMode = AutomaticByPlatform`, `assessmentMode = AutomaticByPlatform`,
`rebootSetting = IfRequired`. Codified in Terraform.

Caveat worth recording: a VM that is deallocated most of the time receives
patches only during its running windows, so the configured mode overstates
the real patch cadence in this environment.
