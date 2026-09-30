"""Export a self-contained, searchable view of a local JSONL session trace."""

from __future__ import annotations

import html
import json
from pathlib import Path


def export_dashboard(log_path: Path, output_path: Path) -> Path:
    cards = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        label = html.escape(
            str(event.get("event", "event")) + " · " + str(event.get("tool", ""))
        )
        body = html.escape(json.dumps(event, ensure_ascii=False, indent=2))
        cards.append(
            f'<details class="event"><summary>{label}</summary><pre>{body}</pre></details>'
        )
    document = (
        """<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>IDA MCP session</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;background:#101721;color:#dae3ee}h1{font-weight:500}input{box-sizing:border-box;width:100%;padding:14px;border:1px solid #64748b;border-radius:8px;background:#182332;color:inherit}details{margin:16px 0;background:#182332;padding:16px;border-radius:8px}summary{cursor:pointer;color:#7dd3fc}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px ui-monospace,monospace}p{color:#94a3b8}</style>
<h1>IDA MCP session</h1><p>Local execution trace · code, results, errors and durations</p><input type="search" id="search" placeholder="Filter events / tools / code">
"""
        + "\n".join(cards)
        + """<script>document.getElementById('search').addEventListener('input',e=>{let q=e.target.value.toLowerCase();document.querySelectorAll('.event').forEach(n=>n.hidden=!n.textContent.toLowerCase().includes(q))})</script></html>"""
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")
    return output_path
