"""Render check results as JSON and HTML."""

import json
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
 .meta { color: #666; font-size: .9rem; }
 code { background: #f6f8fa; padding: .1rem .3rem; border-radius: 3px; }
</style></head><body>
<h1>Azure baseline compliance report</h1>
<p class="meta">Generated {{ generated_at }} &middot;
   {{ total }} checks &middot; {{ failed }} failed</p>
<table>
<tr><th>Control</th><th>Resource</th><th>Result</th><th>Detail</th><th>Evidence</th></tr>
{% for r in results %}
<tr>
  <td><strong>{{ r.control_id }}</strong><br><span class="meta">{{ r.title }}</span></td>
  <td>{{ r.resource }}</td>
  <td class="{{ 'pass' if r.passed else 'fail' }}">{{ 'PASS' if r.passed else 'FAIL' }}</td>
  <td>{{ r.detail }}</td>
  <td><code>{{ r.evidence }}</code></td>
</tr>
{% endfor %}
</table>
</body></html>""")


def write_reports(results, output_dir="reports"):
    out = Path(output_dir)
    out.mkdir(exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload = [asdict(r) for r in results]
    failed = sum(1 for r in results if not r.passed)

    json_path = out / f"compliance-{stamp}.json"
    json_path.write_text(json.dumps(payload, indent=2))

    html_path = out / f"compliance-{stamp}.html"
    html_path.write_text(HTML_TEMPLATE.render(
        results=results,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        total=len(results),
        failed=failed,
    ))

    return json_path, html_path
