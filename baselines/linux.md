# Linux Host Hardening Baseline

**Scope:** `vm-lnx-lab-01` (Ubuntu 22.04 LTS, ARM64, Standard_B2pls_v2) and
any future Linux host in `RG-Security-Lab-WestUS2`.

**Applied by:** Ansible role `ssh_hardening` in this repository, run from a
WSL control node against the `linux_lab` inventory group.

**Framework mapping:** CIS Ubuntu Linux 22.04 LTS Benchmark §5.2 (SSH Server
Configuration), NIST SP 800-53 AC-17, IA-2, IA-5, MITRE ATT&CK T1110
(Brute Force), T1078 (Valid Accounts).

---

## AZ-LNX-001 — SSH authentication must be key-based, with no direct root login

**Rationale**

Password authentication over SSH exposes every account on the host to
credential guessing from any source that can reach port 22. This is not a
theoretical concern in this environment: the Sentinel detection rules built
earlier in this lab exist because an internet-reachable management port
attracts continuous authentication attempts, and the incidents they raised
were real failed-logon bursts. A public key cannot be guessed in the same
way — the attacker needs the private key, not a string that a human chose
and might have reused.

Direct root login deserves separate treatment even where keys are enforced.
Ubuntu's default of `prohibit-password` already blocks password logins for
root, but still permits root to authenticate with a key. The problem is not
the strength of that authentication; it is attribution. A session that opens
as root carries no record of which person opened it, so every subsequent
action in the audit log is attributed to a shared account. Requiring
administrators to authenticate as themselves and elevate through `sudo`
preserves that link, and it also means revoking one person's access does not
require rotating a credential shared by everyone.

The third question this control has to answer is why it exists at all when
the Terraform definition already sets `disable_password_authentication =
true`. Three reasons:

- That setting governs how Azure **provisions** the host. It writes the
  intended configuration once, at creation. It does not prevent anyone from
  editing `sshd_config` afterwards, and it does not detect it if they do.
- It covers `PasswordAuthentication` only. `PermitRootLogin` and the
  remaining SSH settings are left at the image defaults, which are chosen
  for compatibility rather than for security.
- A control that cannot be re-checked is not a control. The Terraform
  attribute is a deployment-time assertion; this baseline defines a
  runtime check that can be run at any point afterwards and produces
  evidence.

The distinction generalises: provisioning sets the initial state, and
configuration management holds it there.

**Applies to**

All Linux hosts in scope, including any host built from an image that is
believed to be hardened already.

**Check**

Read the effective running configuration rather than the file, so that
defaults which are not written out are still evaluated:

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

Reading `/etc/ssh/sshd_config` directly is not sufficient. A setting that
appears only as a comment is still in force at its default value, so the
file can look permissive or restrictive in ways the running daemon is not.

**Remediation**

Run the `ssh_hardening` role:

```bash
ansible-playbook -i inventory.ini site.yml --check --diff   # review first
ansible-playbook -i inventory.ini site.yml --diff           # then apply
```

The role edits `sshd_config` with `validate: /usr/sbin/sshd -t -f %s`, so a
change that would produce an unparseable configuration is rejected before
the file is written. Always run the dry run first, and confirm SSH access
from a second session after the daemon restarts, while the original session
is still open.

**Evidence**

The `sshd -T` output above, dated, together with the playbook run showing
`changed=0` on a second execution — the first proves the state is correct,
the second proves it is held there rather than having been set by hand.

**Status — pass**

Applied and verified 2026-08-11:

```
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
```

`PasswordAuthentication` and `PubkeyAuthentication` were already effective
at these values but were present only as commented defaults; the role writes
them explicitly so the intent is recorded in the file rather than inherited.
`PermitRootLogin` was a genuine change, from the image default of
`prohibit-password`.

**Accepted deviation**

The administrative private key is stored without a passphrase. Anyone who
obtains the key file can use it directly, with no second factor. Accepted
for a single-operator lab; in a shared or production environment the key
would carry a passphrase and be held in an agent, or the host would be
reached through a bastion that brokers short-lived credentials instead.

---

## AZ-LNX-002 — SSH attack surface must be reduced to what the host needs

**Rationale**

Two settings beyond authentication materially change what an attacker can
attempt against the SSH daemon.

`MaxAuthTries` caps the authentication attempts allowed within a single
connection. The default of 6 means an attacker gets six tries per TCP
connection rather than one, which multiplies the throughput of a guessing
campaign by six for the same number of connections — and connection count
is the thing rate-limiting and network controls actually see. Lowering it to
3 does not stop an attacker who is willing to reconnect, but it makes each
connection cheaper to detect and the overall campaign noisier.

`X11Forwarding` tunnels the X11 display protocol over the SSH session. On a
server with no graphical environment there is nothing legitimate to forward,
so the feature contributes only attack surface: it opens a listening socket
on the server side and has historically been the subject of forwarding and
cookie-handling vulnerabilities. Ubuntu ships it enabled for desktop
convenience, which is the wrong default for an unattended host.

Both are examples of the same principle. A feature that is not used is not
neutral — it is code that runs, a socket that listens, and a configuration
surface that has to be understood by whoever reviews the host next.

**Applies to**

All Linux hosts in scope with no legitimate requirement for graphical
forwarding.

**Check**

```bash
ansible -i inventory.ini linux_lab -m shell --become \
  -a "sshd -T | grep -E '^(maxauthtries|x11forwarding)'"
```

Pass requires:

```
maxauthtries 3
x11forwarding no
```

**Remediation**

Covered by the same `ssh_hardening` role, driven by the
`ssh_max_auth_tries` and `ssh_x11_forwarding` variables in the role's
`defaults/`. A host with a genuine forwarding requirement should override
the variable in inventory rather than have the role skipped.

**Evidence**

`sshd -T` output as above, plus the role's variable definitions from version
control showing the value is set deliberately rather than left to chance.

**Status — pass**

Applied and verified 2026-08-11: `maxauthtries 3`, `x11forwarding no`. Both
were genuine changes — 6 and `yes` respectively in the image default.

---

## AZ-LNX-003 — Configuration changes must be made through code, not by hand

**Rationale**

An environment described by code has two sources of truth the moment someone
changes it another way, and the second one is invisible. Both mechanisms
still report success — the code says the host is compliant, the host is
running something else — so the divergence is not discovered by looking at
either one alone.

This lab produced a working example. The administrative SSH key was replaced
using `az vm user update`. That command does not modify the virtual
machine's `admin_ssh_key` property: it installs the VMAccess extension,
which appends the new key to `authorized_keys` on the running host. Access
worked immediately, and nothing appeared to be wrong. The next Terraform plan
proposed destroying and recreating the virtual machine, because
`admin_ssh_key` is an attribute that forces replacement and the value in the
configuration no longer matched what was intended.

A second, subtler instance followed from the same change. The corrected key
value was updated in the local `terraform.tfvars` but not in the
corresponding GitHub Actions secret, so the same configuration produced a
clean plan locally and a destroy-and-recreate plan in the pipeline. One
variable, two sources, and the disagreement was visible only to whoever ran
both.

**Applies to**

All infrastructure and host configuration managed by Terraform or Ansible.

**Check**

Terraform state matches the environment:

```bash
terraform plan   # expect: No changes
```

Host state matches the roles:

```bash
ansible-playbook -i inventory.ini site.yml --check --diff   # expect: changed=0
```

Run both from the pipeline as well as locally. A variable supplied from more
than one place is only verified when every source has been exercised.

**Remediation**

1. Where the environment is right and the code is stale, update the code to
   match and confirm with a clean plan.
2. Where the code is right, apply it — after reading the plan, because a
   corrective apply is exactly where a forced replacement hides.
3. Where a variable has several sources, reconcile every one of them. Fixing
   the local copy alone leaves the pipeline holding the old value.

**Evidence**

A clean `terraform plan` and a `changed=0` Ansible run from the same day,
both from the pipeline rather than only from a workstation.

**Status — pass, with a known weakness**

Both drifts described above were found and closed on 2026-08-11 and
2026-08-13 respectively. Plans are clean locally and in the pipeline.

The weakness is structural rather than current: nothing prevents a manual
change from being made again. The branch ruleset that would require changes
to arrive through a reviewed pull request is configured but not enforced
(see AZ-IAC-003), and no scheduled drift detection runs — divergence is
found when someone happens to run a plan, not when it occurs. A scheduled
plan-only pipeline run would close this.
