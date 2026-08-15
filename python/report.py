"""Render check results as JSON and HTML."""

import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

HTML_TEMPLATE = Template("""<!doctype html>
<html><head><meta charset="utf-8"><title>Compliance report</title>
<style>
 body { font-family: system-ui, sans-serif; margin: 2rem; color: #222; }
 table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
 th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #ddd; }
 th { background: #f4f4f4; }
 .pass { color: #1a7f37; font-weight: 600; }
 .fail { color: #b42318; font-weight: 600; }
 .deviation { color: #9a6700; font-weight: 600; }
 .error { color: #8250df; font-weight: 600; }
 .meta { color: #666; font-size: .9rem; }
 code { background: #f6f8fa; padding: .1rem .3rem; border-radius: 3px; }
</style></head><body>
<h1>Azure baseline compliance report</h1>
<p class="meta">Generated {{ generated_at }} &middot; subscription <code>{{ subscription_id }}</code></p>
<p class="meta">{{ summary.total }} checks &middot;
   {{ summary.pass }} pass &middot;
   {{ summary.fail }} fail &middot;
   {{ summary.deviation }} accepted deviation &middot;
   {{ summary.error }} error</p>
<table>
<tr><th>Control</th><th>Resource</th><th>Result</th><th>Detail</th><th>Evidence</th></tr>
{% for r in results %}
<tr>
  <td><strong>{{ r.control_id }}</strong><br><span class="meta">{{ r.title }}</span></td>
  <td>{{ r.resource }}</td>
  <td class="{{ r.status.value }}">{{ r.status.value.upper() }}</td>
  <td>{{ r.detail }}</td>
  <td><code>{{ r.evidence }}</code></td>
</tr>
{% endfor %}
</table>
</body></html>""")


def _summarise(results) -> dict:
    counts = Counter(r.status.value for r in results)
    return {
        "total": len(results),
        "pass": counts.get("pass", 0),
        "fail": counts.get("fail", 0),
        "deviation": counts.get("deviation", 0),
        "error": counts.get("error", 0),
    }


def write_reports(results, subscription_id, output_dir="reports"):
    out = Path(output_dir)
    out.mkdir(exist_ok=True)

    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    generated_at = now.isoformat(timespec="seconds")
    summary = _summarise(results)

    payload = {
        "generated_at": generated_at,
        "subscription_id": subscription_id,
        "summary": summary,
        "results": [asdict(r) for r in results],
    }

    json_path = out / f"compliance-{stamp}.json"
    json_path.write_text(json.dumps(payload, indent=2))

    html_path = out / f"compliance-{stamp}.html"
    html_path.write_text(HTML_TEMPLATE.render(
        results=results,
        generated_at=generated_at,
        subscription_id=subscription_id,
        summary=summary,
    ))

    return json_path, html_path