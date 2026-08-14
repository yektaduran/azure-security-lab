# Linux Host Hardening Baseline

**Scope:** `vm-lnx-lab-01` (Ubuntu 22.04 LTS, ARM64, Standard_B2pls_v2) and
any future Linux host in `RG-Security-Lab-WestUS2`.

**Applied by:** Ansible roles `ssh_hardening`, `sysctl_hardening`, `auditd`
and `ufw` in this repository, run from a WSL control node against the
`linux_lab` inventory group.

**Framework mapping:** CIS Ubuntu Linux 22.04 LTS Benchmark §3 (Network
Configuration), §4 (Logging and Auditing), §5.2 (SSH Server Configuration);
NIST SP 800-53 AC-17, AU-2, IA-2, SC-7; MITRE ATT&CK T1110 (Brute Force),
T1078 (Valid Accounts), T1562.001 (Impair Defenses).

---

## AZ-LNX-001 — SSH authentication must be key-based, with no direct root login

**Rationale**

Password authentication over SSH exposes every account on the host to
credential guessing from any source that can reach port 22. This is not
theoretical here: the Sentinel detection rules built earlier in this lab
exist because an internet-reachable management port attracts continuous
authentication attempts. A public key cannot be guessed the same way — the
attacker needs the private key, not a string a human chose and may have
reused elsewhere.

Direct root login deserves separate treatment even where keys are enforced.
Ubuntu's default of `prohibit-password` blocks password logins for root but
still permits root to authenticate with a key. The problem is not the
strength of that authentication; it is attribution. A session opened as root
carries no record of which person opened it, so every subsequent action in
the audit log belongs to a shared account. Requiring administrators to
authenticate as themselves and elevate through `sudo` preserves that link —
visibly so in the audit trail, where the `auid` field retains the original
login identity across privilege escalation.

Terraform already sets `disable_password_authentication = true`, which
raises the question of why this control exists at all. Three reasons: that
setting governs how Azure **provisions** the host and asserts nothing about
its state afterwards; it covers `PasswordAuthentication` only, leaving
`PermitRootLogin` and the rest at image defaults chosen for compatibility;
and a deployment-time attribute cannot be re-checked, so it produces no
evidence. Provisioning sets the initial state, configuration management
holds it there, and this control verifies it.

**Where the setting has to live**

Ubuntu's `sshd_config` begins with `Include /etc/ssh/sshd_config.d/*.conf`,
and OpenSSH keeps the **first** value it reads for any keyword. Files in
that directory are therefore authoritative over the main file, and among
themselves they are read in filename order. Cloud-init and the Azure VM
agent both write there. Setting a value in `/etc/ssh/sshd_config` alone is
not sufficient and can be silently ineffective — see AZ-LNX-004.

The `ssh_hardening` role writes `/etc/ssh/sshd_config.d/00-hardening.conf`,
which sorts ahead of the vendor drop-ins, and continues to set the same
values in the main file so the intent is visible in both places.

**Applies to**

All Linux hosts in scope, including hosts built from an image believed to be
hardened already.

**Check**

Read the effective running configuration, not the file:

```bash
ansible -i inventory.ini linux_lab -m shell --become \
  -a "sshd -T | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication)'"
```

Pass requires all three:

```
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
```

Then verify independently, from outside the automation:

```bash
ssh azureadmin@<public-ip>          # must fail: Permission denied (publickey)
```

The second check is not redundant. `sshd -T` reflects what the daemon
loaded; attempting a password login proves what it actually enforces, and it
is the check that found the failure described in AZ-LNX-004.

**Remediation**

```bash
ansible-playbook -i inventory.ini site.yml --check --diff   # review first
ansible-playbook -i inventory.ini site.yml --diff           # then apply
```

The role writes SSH configuration with `validate: /usr/sbin/sshd -t -f %s`,
so a change producing an unparseable configuration is rejected before the
file lands. Always run the dry run first, and confirm access from a second
session after the daemon restarts while the original session is still open.

**Evidence**

The `sshd -T` output and the rejected password login, both dated, together
with a playbook run showing `changed=0` — the first two prove the state is
correct, the third proves it is held there rather than set by hand.

**Status — pass**

Applied 2026-08-11, re-established 2026-08-13 after the regression described
in AZ-LNX-004:

```
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
```

`PermitRootLogin` was a genuine change from the image default of
`prohibit-password`.

**Accepted deviation**

The administrative private key is stored without a passphrase. Anyone who
obtains the key file can use it directly, with no second factor. Accepted
for a single-operator lab; in a shared or production environment the key
would carry a passphrase held in an agent, or the host would be reached
through a bastion brokering short-lived credentials.

---

## AZ-LNX-002 — SSH attack surface must be reduced to what the host needs

**Rationale**

`MaxAuthTries` caps authentication attempts within a single connection. The
default of 6 gives an attacker six tries per TCP connection rather than one,
multiplying the throughput of a guessing campaign sixfold for the same
number of connections — and connection count is what rate limiting and
network controls actually observe. Lowering it to 3 does not stop an
attacker willing to reconnect, but it makes each connection cheaper to
detect and the campaign as a whole noisier.

`X11Forwarding` tunnels the X11 display protocol over SSH. On a server with
no graphical environment there is nothing legitimate to forward, so the
feature contributes only attack surface: a listening socket on the server
side and a history of forwarding and cookie-handling vulnerabilities. Ubuntu
ships it enabled for desktop convenience, which is the wrong default for an
unattended host.

Both illustrate the same principle: an unused feature is not neutral. It is
code that runs, a socket that listens, and configuration surface that
whoever reviews the host next has to understand.

**Applies to**

All Linux hosts in scope with no legitimate requirement for graphical
forwarding.

**Check**

```bash
ansible -i inventory.ini linux_lab -m shell --become \
  -a "sshd -T | grep -E '^(maxauthtries|x11forwarding)'"
```

Pass requires `maxauthtries 3` and `x11forwarding no`.

**Remediation**

Covered by the `ssh_hardening` role, driven by `ssh_max_auth_tries` and
`ssh_x11_forwarding` in the role's `defaults/`. A host with a genuine
forwarding requirement should override the variable in inventory rather than
have the role skipped.

**Evidence**

`sshd -T` output as above, plus the role's variable definitions from version
control showing the values are set deliberately.

**Status — pass**

Applied and verified 2026-08-11: `maxauthtries 3`, `x11forwarding no`. Both
were genuine changes from the image defaults of 6 and `yes`.

---

## AZ-LNX-003 — Kernel network parameters must be tuned, and owned by one manager

**Rationale**

The kernel's network stack accepts several behaviours by default that a
server has no need for and that an attacker can use.

ICMP redirect acceptance lets a host on the local segment rewrite this
machine's routing table — a path to interception on a shared network.
Redirect sending is equally unnecessary: this host is not a router and has
no business advising others about routes. Source routing lets the sender
dictate a packet's path, defeating the assumption that a source address
reflects where the packet came from. Reverse path filtering enforces that
assumption in the other direction, dropping packets whose source is not
routable back out of the arrival interface — the kernel-level equivalent of
uRPF. SYN cookies keep the listening socket usable during a SYN flood.
Martian logging records packets with impossible source addresses, often the
first visible sign of spoofing.

The ownership half of this control matters as much as the values. Multiple
components write kernel parameters and the last one to run wins, silently.
This lab produced a working example: `ufw` reapplies `/etc/ufw/sysctl.conf`
on every reload, and that file sets `log_martians=0`. The Ansible role set
it to 1, ufw put it back to 0 on its next reload, and neither tool reported
a problem. A parameter with two managers has no effective value — it has
whichever value ran most recently.

**Applies to**

All Linux hosts in scope.

**Check**

```bash
ansible -i inventory.ini linux_lab -m shell --become \
  -a "sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects \
      net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.rp_filter \
      net.ipv4.tcp_syncookies net.ipv4.conf.all.log_martians"
```

Pass requires redirects and source routing at 0, `rp_filter` at 1,
`tcp_syncookies` at 1, `log_martians` at 1.

Ownership is checked by running the playbook twice. A second run reporting
`changed=0` proves nothing else is overwriting these values; a parameter
that reappears as `changed` on every run has a competing manager.

**Remediation**

The `sysctl_hardening` role writes `/etc/sysctl.d/60-hardening.conf` via
`ansible.posix.sysctl`, applying values to the running kernel and persisting
them in one step, without touching `/etc/sysctl.conf` and its distribution
defaults. The `ufw` role blanks `IPT_SYSCTL=` in `/etc/default/ufw` so the
firewall manages rules only and kernel tuning has a single owner.

**Evidence**

The `sysctl` output above, plus two consecutive playbook runs where the
second reports `changed=0`.

**Status — pass**

Applied 2026-08-13. Thirteen parameters set, covering both `all.*` and
`default.*` variants so interfaces added later inherit the same values, plus
IPv6 redirect acceptance. Verified on the host and idempotent on re-run.

**Note on `rp_filter`**

Set to 1 (strict) rather than 2 (loose). Strict mode drops packets on hosts
with asymmetric routing — multiple interfaces, or a VPN where return traffic
takes a different path. Safe on this single-NIC VM; revisit before applying
the role to a multi-homed host.

---

## AZ-LNX-004 — Out-of-band recovery must exist, and must not weaken the host

**Rationale**

Every network control on this host is scoped to a single administrative
source address: the NSG rule, and the host firewall rule behind it. That is
the correct posture, and it carries a specific failure mode — when the
operator's address changes, both controls exclude the operator along with
everyone else. The address here is a dynamic residential IP, so this is a
matter of when rather than whether.

The NSG can be corrected from the portal. The host firewall cannot: fixing
`ufw` requires a shell, and the only route to that shell is the port `ufw`
is now blocking. Without a recovery path this is one DHCP lease away from an
unreachable virtual machine.

Azure's serial console provides that path, reaching a login prompt
independently of the network stack. It is only useful with credentials that
work at a console, which a key-only host does not have — so a recovery
password is required for the recovery path to function at all.

**That password must be set with care, because setting it can undo the
host's hardening.** On this VM, `az vm user update --password` installed the
VMAccess extension, which wrote
`/etc/ssh/sshd_config.d/50-cloud-init.conf` containing
`PasswordAuthentication yes`. Because Ubuntu includes that directory from
the top of `sshd_config` and OpenSSH keeps the first value it reads, the
hardened setting in the main file stopped applying. Password authentication
over the internet became possible, using a password chosen for console
recovery. The same operation also removed the passwordless sudo rule the
automation depended on.

Two properties of this failure are worth recording. It was silent: both
tools reported success, and the Ansible role continued to report
`changed=0`, because it was correctly writing a file that no longer decided
the outcome. And it was invisible to the idempotency check, which compares
the role's intent against the role's own artefact rather than against the
daemon's effective configuration. Only an independent test — attempting a
password login from outside the automation — revealed it.

**Applies to**

Any host whose management access is restricted by source address, and any
host where a recovery credential is provisioned out of band.

**Check**

The recovery path exists:

```
Azure portal → vm-lnx-lab-01 → Help → Serial console   # must reach a login prompt
```

The recovery credential has not weakened remote access:

```bash
ssh azureadmin@<public-ip>          # must fail: Permission denied (publickey)
```

No vendor drop-in is overriding the hardened settings:

```bash
ansible -i inventory.ini linux_lab -m shell --become \
  -a "grep -rn PasswordAuthentication /etc/ssh/sshd_config.d/; sshd -T | grep -i passwordauth"
```

The last command is the diagnostic one: it shows both what the fragments
declare and which value won.

**Remediation**

1. Re-run the hardening playbook after any use of `az vm user update`, VM
   reset operations, or agent-driven changes. Treat those as configuration
   events requiring reconciliation, not as read-only conveniences.
2. Keep the hardened values in `/etc/ssh/sshd_config.d/00-hardening.conf` so
   they take precedence over vendor fragments whatever those contain.
3. Confirm with an actual password login attempt, not with `sshd -T` alone.

**Evidence**

A serial console screenshot reaching the login prompt, a rejected password
login against the public address, and the drop-in listing showing
`00-hardening.conf` present and effective. All dated.

**Status — pass, with a standing risk**

Serial console verified reaching a login prompt on 2026-08-13. A recovery
password is set for `azureadmin`; SSH password authentication is disabled,
so the credential is usable only at the console.

The regression described above occurred on 2026-08-13 and was closed the
same day by moving the hardened settings into `00-hardening.conf`.

**Accepted deviations**

- The recovery password was initially set to a value already in use in a
  separate lab environment. Reusing a credential across environments means a
  compromise in one reaches the other; to be replaced with a unique value
  held in a password manager.
- Passwordless sudo was removed as a side effect of the same operation, so
  playbook runs now require `--ask-become-pass`. Functional rather than a
  security weakness, but unattended runs are not currently possible.
- Nothing prevents a future agent-driven change from recreating this
  regression.
- A daily scheduled pipeline run now performs the automated portion of these
  checks (see AZ-IAC-003). The manual verifications — the serial console test
  and the password login attempt — remain unautomated, so an agent-driven
  regression that only affects those would still go unnoticed.

---

## AZ-LNX-005 — A host firewall must be enforced independently of the cloud network control

**Rationale**

The NSG already restricts inbound traffic to SSH from one address, which
invites the question of why the host needs its own firewall. The answer is
that the two controls fail differently and are administered differently. An
NSG rule can be widened by anyone with network permissions in the
subscription, frequently while troubleshooting something unrelated, and the
change takes effect across its whole scope at once. A host firewall survives
that: it is administered with the host, by whoever administers the host, and
it constrains traffic reaching the interface regardless of how it got there
— including traffic originating inside the virtual network, which an NSG
scoped to internet ingress may not evaluate at all.

The ordering of operations matters more than the rules themselves. Enabling
a default-deny firewall before the rule permitting management access exists
disconnects the session performing the change, and on a remote host that is
unrecoverable without out-of-band access. Rule first, default policy second,
enablement last.

**Applies to**

All Linux hosts in scope.

**Check**

```bash
ansible -i inventory.ini linux_lab -m shell --become -a "ufw status verbose"
```

Pass requires status `active`, default `deny (incoming)`, and an explicit
allow rule for each service the host is meant to expose — no more.

**Remediation**

The `ufw` role installs the package, adds allow rules from
`ufw_allowed_rules`, sets default policies, enables logging, and only then
enables the firewall. Preserve that order in any change to the role.

**Evidence**

`ufw status verbose` output showing the active ruleset, dated, together with
confirmation that management access still works after enablement — taken
from a session established after the change, not the one that made it.

**Status — pass**

Applied and verified 2026-08-13:

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
22/tcp    ALLOW IN    95.70.168.162    # SSH from admin IP
```

**Accepted deviation**

The allow rule is scoped to a dynamic residential address and requires
manual update whenever it changes. Any other host behind that address is
also permitted. See AZ-LNX-004 for the recovery path this makes necessary.

---

## AZ-LNX-006 — Host activity must be recorded for investigation

**Rationale**

Everything above is preventive. Audit logging is what makes an incident
answerable afterwards: which account authenticated, from where, what was
executed, which files changed. Without it a compromise is discovered as an
outcome rather than reconstructed as a sequence, and the questions asked
after an incident — when did this start, what else did they touch — have no
source of truth.

`auditd` also records the identity behind privilege escalation. Its `auid`
field retains the account that opened the session even after `sudo`, which
is the mechanism making the attribution argument in AZ-LNX-001 operational
rather than aspirational.

Log volume needs bounding, because a full disk is a realistic outage and an
audit daemon can fill one. The controlling settings are rotation size and
count, and the actions taken as space runs low.

**Applies to**

All Linux hosts in scope.

**Check**

Service state and configuration:

```bash
ansible -i inventory.ini linux_lab -m shell --become \
  -a "systemctl is-active auditd; systemctl is-enabled auditd; \
      grep -E '^(max_log_file|num_logs|space_left_action|admin_space_left_action|disk_full_action)' /etc/audit/auditd.conf"
```

Records are actually being written:

```bash
ansible -i inventory.ini linux_lab -m shell --become \
  -a "ausearch -m USER_LOGIN -ts recent | tail -20"
```

A service that is active but producing no records is a fail. `is-enabled`
matters as much as `is-active`: a daemon that does not survive reboot leaves
a gap nobody notices.

**Remediation**

The `auditd` role installs the package, configures rotation and disk-space
actions, and ensures the service is started and enabled.

**Evidence**

Service state output plus a sample of `USER_LOGIN` records showing real
sessions with source addresses and `auid` values, dated.

**Status — pass**

Applied and verified 2026-08-13. Service active and enabled;
`max_log_file 32`, `num_logs 5`, rotation on. `USER_LOGIN` records confirmed
for administrative sessions, showing source address and `auid=1000`.

**Accepted deviation**

`admin_space_left_action` is set to `syslog` rather than the CIS
recommendation of `halt`. `halt` is correct where losing audit records is
less acceptable than losing the service, which is a real requirement in some
regulated environments. It is the wrong trade here: the usual cause of a
full audit partition is broken log rotation rather than an attack, so `halt`
is more likely to stop the host over a maintenance fault than over an
intrusion — and this host's recovery path is a serial console that a halted
machine does not offer. Growth is bounded instead by `max_log_file` and
`num_logs` to roughly 160 MB against a 30 GB disk.

**Gap — partially closed 2026-08-13**

Authentication records now leave the host. The Azure Monitor Agent forwards
the `auth` and `authpriv` syslog facilities to `LAW-Security-Lab` through
`dcr-linux-auth`, so SSH sessions and privilege escalation on this host are
queryable alongside the Windows security events and survive the loss of the
machine. Verified in the `Syslog` table the same day.

Two parts remain open. The forwarding covers syslog rather than `auditd`'s
own records, so file-integrity and command-execution events written to
`/var/log/audit/audit.log` stay local; closing that needs the audisp syslog
plugin and a decision about the ingest volume it would add. Detection now consumes this data: the analytics rule
`Linux - Local Account Persistence` (query held in
`kql/detections/linux-account-persistence.kql`) alerts on interactive account
creation and privileged group membership changes. Validated 2026-08-15.

Still open: auditd's own records remain local, since forwarding covers syslog
rather than /var/log/audit/audit.log..
