# Evidence

Captured 2026-09-01, before subscription expiry (~2026-09-04).
Final checker run and teardown records added 2026-09-03.

| Path | Contents | How captured |
|------|----------|--------------|
| monitor/ | 3 DCR definitions + associations | `az monitor data-collection rule show` / `association list --rule-name` |
| sentinel/ | Analytics rules, automation rules, incidents, Logic App definition and run history | `az rest` (SecurityInsights 2023-02-01), `az resource show` |
| defender/ | Secure score, MCSB compliance, Defender plans, all assessments (34 Healthy / 36 Unhealthy / 14 NotApplicable) | `az rest` (Microsoft.Security), `az security assessment list` |
| terraform/ | `state list` (17 resources), final plan ("No changes") | Terraform CLI |
| screenshots/ | Portal views, named `YYYY-MM-DD_area_topic.png` | Azure portal |
| checker/ | Final compliance run (JSON + HTML) | `python run_checks.py`, added 2026-09-03 |

Notes:
- `Microsoft.Security/subAssessments` returned `SubAssessmentsDeprecated` on 2026-09-01;
  vulnerability findings now live in individual assessments (defender/assessments.json).
- Admin/public IPs redacted where they appeared (`ADMIN_IP_REDACTED`).
- Secure Score at capture time was 68% with VMs deallocated; see the score-vs-visibility
  note in the root README.