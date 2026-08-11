# Monitoring and Detection Baseline

**Scope:** `LAW-Security-Lab` Log Analytics workspace, Microsoft Sentinel,
data collection rules and diagnostic settings across
`RG-Security-Lab-WestUS2`.

**Framework mapping:** CIS Microsoft Azure Foundations Benchmark v2.1 §5,
NIST SP 800-53 AU-2, AU-6, AU-11, IR-4.

---

## AZ-MON-001 — Security event collection configured for all hosts

**Rationale**

Detection is bounded by collection: a rule cannot fire on an event that was
never ingested. Windows authentication events in particular are the
foundation of credential-attack detection, and their absence produces silent
blind spots rather than visible failures.

Collection also has to be deliberate. Overlapping data collection rules
targeting the same host ingest the same event more than once, which inflates
cost and distorts any count-based detection threshold — a rule that fires on
five failed logons will fire on two-and-a-half real attempts if every event
arrives twice.

**Applies to**

All virtual machines, and all Azure resources that emit diagnostic logs.

**Check**

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| summarize Events = count(), Last = max(TimeGenerated) by Computer, EventID
| order by Computer asc, Events desc
```

Every in-scope host must appear. Duplicate ingestion is visible as event
counts roughly double the expected volume.

**Remediation**

1. Associate each host with a data collection rule carrying the
   `Microsoft-SecurityEvent` stream.
2. Audit all DCRs targeting the same host and remove overlapping streams.
3. Confirm with the query above over a period when the host was running.

**Evidence**

Query output covering the review period, showing every in-scope host with a
recent timestamp and plausible event volumes.

**Status — pass**

`dcr-sentinel-securityevents` delivers the `Microsoft-SecurityEvent` stream
from `vm-sec-lab-01` to `LAW-Security-Lab`; 4625 events confirmed present in
the `SecurityEvent` table. A second rule, `DCR-Security-Lab`, was narrowed to
Application and System event levels 1–3 specifically to remove a duplicate
ingestion path.

---

## AZ-MON-002 — Detection rules must produce triaged incidents

**Rationale**

A detection rule that produces an incident nobody can act on is worse than
no rule at all, because it consumes analyst attention while providing no
signal. Three properties separate a usable rule from noise: entities are
mapped so the incident names a real account and host, related alerts are
grouped so one campaign produces one incident, and known-benign activity is
tuned out automatically rather than closed by hand each time.

Tuning must be recorded with a classification. Marking expected activity as
a false positive corrupts the rule-quality metrics and eventually leads
somebody to weaken a rule that was working correctly; the correct
classification is benign positive.

**Applies to**

All scheduled analytics rules in the workspace.

**Check**

Review each enabled rule for entity mappings and alert grouping
configuration, then measure the outcome:

```kusto
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize Incidents = count() by Title, Severity, Classification
| order by Incidents desc
```

A single title producing many separate incidents for the same account and
host indicates grouping is misconfigured.

**Remediation**

1. Map account, host and IP entities on every rule.
2. Enable alert grouping on stable entities. Do not group on volatile
   details such as a failure counter, which changes between alerts and
   defeats the grouping it appears to support.
3. Encode known-benign activity as an automation rule that sets severity and
   closes with a benign-positive classification and a written comment.

**Evidence**

The query output above, plus the automation rule definition and a sample
incident showing the applied classification and comment.

**Status — pass**

Two scheduled rules in place: `Multiple Failed Logon Attempts - Windows VM`
(4625 threshold) and a correlated 4625-to-4624 rule detecting successful
brute force. Both map Account, Host and IP entities. Grouping is configured
on Account and Host over a five-hour window, with re-open enabled so
recurring activity resurfaces after closure.

Automation rule `Tune - Known Admin Account Failed Logons` closes incidents
for the known lab administrator account as benign positive with an
explanatory comment; a second automation rule invokes the enrichment
playbook. Verified on 2026-08-10: the tuned account produced an
Informational closed incident while a different account produced a Medium
open incident from the same host.

---

## AZ-MON-003 — Log retention meets the defined minimum

**Rationale**

Retention determines how far back an investigation can reach. Intrusions are
frequently discovered months after initial access, and a workspace holding
thirty days of data cannot answer questions about a compromise that began
before that window. Retention is also the control most often set by default
rather than by decision, so it must be stated explicitly and justified
against the environment's requirement rather than left at whatever the
platform chose.

**Applies to**

All Log Analytics workspaces and archived log destinations.

**Check**

```bash
az monitor log-analytics workspace show \
  --workspace-name <workspace> --resource-group <rg> \
  --query "{retention:retentionInDays, sku:sku.name, quota:workspaceCapping.dailyQuotaGb}" -o json
```

Compare against the documented minimum for the environment.

**Remediation**

Set interactive retention to the required period, and configure long-term
archive for data that must be kept beyond it. Where cost is the constraint,
archive tiers are substantially cheaper than interactive retention and
preserve the ability to search historically.

**Evidence**

Check output, together with the documented retention requirement it is being
measured against. Retention without a stated requirement cannot pass or
fail.

**Status — pass against the lab requirement**

`LAW-Security-Lab` retains 30 days on the PerGB2018 tier, with no daily
ingestion cap configured. Thirty days is the defined minimum for this lab
and is met.

Recorded gap: this would not satisfy a regulated production environment,
where 90 days interactive and one year archived is the common expectation.
The absence of an ingestion cap is also worth noting — on a trial
subscription an ingestion spike would consume credit without any ceiling.
