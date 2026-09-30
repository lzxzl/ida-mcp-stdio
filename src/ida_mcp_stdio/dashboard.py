"""Local session timelines and a portable, self-contained dashboard export."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import threading
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .transcripts import (
    canonical_agent,
    iter_transcript_references,
    load_transcript,
    number,
    parse_timestamp,
    read_records,
    recorded_usage,
    resolve_reference,
    session_files,
    skipped_records,
    sum_usage,
)


def _identifier(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


class DashboardStore:
    """Refresh local traces and authorize only their explicitly linked transcripts."""

    def __init__(self, state_dir: Path, session_paths: list[Path] | None = None):
        self.state_dir = state_dir.expanduser().resolve()
        self.session_paths = session_paths
        self._transcripts: dict[str, tuple[Path, str]] = {}
        self._lock = threading.RLock()

    def snapshot(self, *, include_transcript_items: bool = True) -> dict:
        sessions, allowlist = [], {}
        paths = (
            self.session_paths
            if self.session_paths is not None
            else session_files(self.state_dir)
        )
        for path in paths:
            path = path.expanduser().resolve()
            records, warnings = read_records(path)
            groups: dict[str, list[dict]] = {}
            current = path.stem
            for record in records:
                identity = record.get("session_id", record.get("mcp_server_id"))
                if isinstance(identity, str) and identity:
                    current = identity
                groups.setdefault(current, []).append(record)
            if not groups:
                groups[path.stem] = []
            for session_id, group in groups.items():
                summary = self._summarize(path, session_id, group, warnings)
                seen_transcripts = set()
                for kind, recorded in iter_transcript_references(group):
                    try:
                        source = resolve_reference(recorded, path)
                    except (OSError, ValueError) as exc:
                        summary["warnings"].append(
                            f"Cannot resolve transcript {recorded}: {exc}"
                        )
                        continue
                    kind = canonical_agent(kind)
                    if (kind, source) in seen_transcripts:
                        continue
                    seen_transcripts.add((kind, source))
                    token = _identifier(kind + "\n" + str(source))
                    allowlist[token] = (source, kind)
                    view = load_transcript(source, kind)
                    reference = {
                        "id": token,
                        "kind": kind,
                        "path": recorded,
                        "url": "/api/transcripts/" + token,
                        "usage": view["usage"],
                        "task_seconds": view["task_seconds"],
                        "warnings": view["warnings"],
                    }
                    if include_transcript_items:
                        reference["items"] = view["items"]
                    summary["transcripts"].append(reference)
                # Agent usage belongs to the linked transcript; do not add it to
                # potentially duplicated tool-level usage recorded by MCP.
                if summary["transcripts"]:
                    summary["usage"] = sum_usage(
                        (r["usage"] for r in summary["transcripts"]),
                        "linked transcripts (shared sessions may overlap)",
                    )
                    summary["warnings"].extend(
                        warning
                        for warning in summary["usage"].get("warnings", [])
                        if warning not in summary["warnings"]
                    )
                    times = [
                        r["task_seconds"]
                        for r in summary["transcripts"]
                        if r["task_seconds"] is not None
                    ]
                    summary["task_seconds"] = sum(times) if times else None
                sessions.append(summary)
        sessions.sort(key=lambda s: s["started_at"] or "", reverse=True)
        with self._lock:
            self._transcripts = allowlist
        return {
            "sessions": sessions,
            "refreshed_at": datetime.now(timezone.utc).isoformat(),
            "source": str(self.state_dir),
        }

    @staticmethod
    def _summarize(
        path: Path, session_id: str, records: list[dict], warnings: list[str]
    ) -> dict:
        timestamps = [parse_timestamp(r.get("timestamp", r.get("ts"))) for r in records]
        times = [t for t in timestamps if t is not None]
        started, ended = (min(times), max(times)) if times else (None, None)
        events = {r.get("event") for r in records if isinstance(r.get("event"), str)}
        stopped = bool(events & {"shutdown", "mcp_stopped", "session_stopped"})
        calls = [
            r
            for r in records
            if isinstance(r.get("event"), str)
            and r["event"] in {"tool_start", "tool_call"}
        ]
        errors = [
            r
            for r in records
            if r.get("event") == "tool_error" or r.get("is_error") is True
        ]
        latencies, pending = [], {}
        timeline = []
        for index, record in enumerate(records):
            event = str(record.get("event", "event"))
            timestamp = timestamps[index]
            call_id = record.get("request_id", record.get("call_id"))
            call_key = json.dumps(call_id, sort_keys=True)
            duration = number(record.get("duration"))
            if duration is None:
                milliseconds = number(record.get("duration_ms"))
                duration = milliseconds / 1000 if milliseconds is not None else None
            if event in {"tool_start", "tool_call"}:
                pending[call_key] = timestamp
            elif event in {"tool_end", "tool_result", "tool_error"}:
                call_start = pending.pop(call_key, None)
                if duration is None and timestamp and call_start:
                    duration = max(0, (timestamp - call_start).total_seconds())
                if duration is not None:
                    latencies.append(duration)
            timeline.append(
                {
                    "timestamp": timestamp.isoformat() if timestamp else None,
                    "event": str(event),
                    "tool": str(record.get("tool", "")),
                    "call_id": call_id,
                    "duration_seconds": duration,
                    "is_error": record in errors,
                    "record": record,
                }
            )
        usages = [
            recorded_usage(r.get("usage"), r.get("cost"))
            for r in records
            if isinstance(r.get("usage"), dict) or number(r.get("cost")) is not None
        ]
        usage = sum_usage(usages, "MCP records")
        return {
            "id": _identifier(str(path) + "\n" + session_id),
            "session_id": session_id,
            "path": str(path),
            "agent": next(
                (r["agent"] for r in records if isinstance(r.get("agent"), str)),
                "unknown",
            ),
            "status": "stopped" if stopped else "recording / unknown",
            "started_at": started.isoformat() if started else None,
            "last_activity_at": ended.isoformat() if ended else None,
            "elapsed_seconds": (
                (ended - started).total_seconds() if started and ended else None
            ),
            "task_seconds": None,
            "tool_calls": len(calls),
            "errors": len(errors),
            "pending_calls": len(pending),
            "latency_seconds": latencies,
            "usage": usage,
            "timeline": timeline,
            "transcripts": [],
            "warnings": list(warnings) + usage["warnings"],
            "skipped_records": skipped_records(warnings),
        }

    def transcript(self, token: str) -> dict | None:
        with self._lock:
            reference = self._transcripts.get(token)
        if reference is None:
            return None
        path, kind = reference
        try:
            if path.resolve() != path:
                return None
        except (OSError, ValueError):
            return None
        return load_transcript(path, kind)


_STYLE = """
:root{color-scheme:dark;--bg:#0b1220;--panel:#152238;--muted:#a5b4c8;--text:#e5edf8;--border:#334764;--accent:#8bd4ff}
*{box-sizing:border-box}body{font:14px system-ui,sans-serif;background:var(--bg);color:var(--text);margin:0}
header,main{max-width:1500px;margin:auto;padding:24px}header{border-bottom:1px solid var(--border)}h1{font-size:24px;margin:0 0 8px}
h2{font-size:19px}h3{font-size:15px}p,.muted{color:var(--muted)}button,input,select{font:inherit;color:inherit;background:var(--panel);border:1px solid var(--border);border-radius:7px;padding:9px}
button{cursor:pointer}button:hover{border-color:var(--accent)}input{min-width:220px;flex:1}.controls,.metrics{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
input[type=checkbox]{min-width:0;width:16px;flex:0;padding:0}.controls label{display:flex;align-items:center;gap:6px}
.layout{display:grid;grid-template-columns:320px 1fr;gap:24px}.session{width:100%;text-align:left;margin:0 0 10px;padding:14px}.session.active{border-color:var(--accent)}
.metric{min-width:140px;padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--panel)}.metric b{display:block;font-size:19px;margin-top:6px}.metric small{color:var(--muted)}
.event{border-left:3px solid var(--border);padding:12px 16px;margin:10px 0;background:var(--panel);border-radius:5px}.error{border-color:#fb7185}.agent{border-color:#a78bfa}summary{cursor:pointer;color:var(--accent)}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px ui-monospace,monospace;line-height:1.6}code{color:var(--accent)}.warning{color:#facc15}.tag{display:inline-block;margin:3px 8px 3px 0;font-size:12px;color:var(--muted)}a{color:var(--accent)}
@media(max-width:800px){.layout{grid-template-columns:1fr}header,main{padding:16px}aside{max-height:250px;overflow:auto}}
"""

_SCRIPT = r"""
const $=id=>document.getElementById(id);let data=INITIAL,selected=null;
const node=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n};
const fmt=n=>n===null||n===undefined?'—':Number.isFinite(Number(n))?Number(n).toLocaleString(undefined,{maximumFractionDigits:3}):'Unavailable / 不可用';
function metric(label,value,note){const n=node('div',undefined,'metric');n.append(node('span',label),node('b',value));if(note)n.append(node('small',note));return n}
function render(){const q=$('search').value.toLowerCase();const filter=$('agentFilter').value;const list=$('sessions');list.replaceChildren();
const sessions=data.sessions.filter(s=>(!filter||s.agent===filter)&&JSON.stringify(s).toLowerCase().includes(q));
if(!sessions.some(s=>s.id===selected))selected=sessions[0]?.id;for(const s of sessions){const b=node('button',`${s.agent} · ${s.session_id}`,'session'+(s.id===selected?' active':''));b.append(node('div',`${s.status} · ${s.tool_calls} tools · ${s.errors} errors`,'muted'),node('div',s.started_at||'No timestamp / 无时间','muted'));b.onclick=()=>{selected=s.id;render()};list.append(b)}
$('source').textContent=`${data.source} · ${data.refreshed_at}`;const panel=$('detail');panel.replaceChildren();const s=sessions.find(s=>s.id===selected);if(!s){panel.append(node('p','No matching sessions / 无匹配会话'));return}
panel.append(node('h2',s.session_id),node('p',s.path));const metrics=node('div',undefined,'metrics');const u=s.usage;
metrics.append(metric('Tools / 工具',fmt(s.tool_calls)),metric('Errors / 错误',fmt(s.errors)),metric('Elapsed / 会话耗时',fmt(s.elapsed_seconds)+' s','First to last record / 首末记录'),metric('Task time / 任务时间',fmt(s.task_seconds)+' s','Recorded prompt/work intervals / 记录区间'),metric('Mean tool latency / 平均工具延迟',s.latency_seconds.length?fmt(s.latency_seconds.reduce((a,b,i)=>a+(b-a)/(i+1),0))+' s':'—'),metric('Tokens in / 输入',u.has_tokens?fmt(u.input):'—'),metric('Tokens out / 输出',u.has_tokens?fmt(u.output):'—'),metric('Recorded cost / 记录费用',u.unavailable?.includes('cost')?'Unavailable / 不可用':u.cost===null?'Unavailable / 无记录':fmt(u.cost),u.cost_partial?'Partial / 部分记录':'Recorded values only / 仅记录值'));panel.append(metrics);
panel.append(node('p',`${u.scope} · cache read ${u.has_tokens?fmt(u.cache_read):'—'} · cache write ${u.has_tokens?fmt(u.cache_write):'—'} · reasoning ${u.has_tokens?fmt(u.reasoning):'—'}`,'muted'));
for(const w of s.warnings)panel.append(node('p',w,'warning'));let timeline=s.timeline.map(e=>({...e,type:'mcp',label:e.event+' · '+e.tool,body:e.record}));
for(const t of s.transcripts){const detail=node('details');detail.append(node('summary',`Linked ${t.kind} / 关联转录 · ${t.path}`));detail.append(node('p',`Token scope: ${t.usage.scope} · task time ${fmt(t.task_seconds)} s`));for(const w of t.warnings)detail.append(node('p',w,'warning'));for(const item of t.items||[]){timeline.push({type:'agent',timestamp:item.timestamp,label:t.kind+' · '+item.kind+' · '+item.tool,body:item,tool:item.tool,is_error:false,call_id:item.call_id})}panel.append(detail)}
panel.append(node('h3','Timeline / 时间线'));const kind=$('eventFilter').value;timeline=timeline.filter(e=>(!kind||(kind==='errors'?e.is_error:kind==='agent'?e.type==='agent':kind==='tools'?e.tool:e.type==='mcp'))&&JSON.stringify(e).toLowerCase().includes(q));
timeline.sort((a,b)=>{const ts=x=>typeof x==='number'?(x>1e11?x:x*1000):Date.parse(x)||0;return ts(a.timestamp)-ts(b.timestamp)});
for(const e of timeline){const card=node('details',undefined,'event'+(e.is_error?' error':'')+(e.type==='agent'?' agent':''));const label=node('summary',e.label);label.append(node('span',` · ${e.timestamp||'—'}${e.duration_seconds!=null?' · '+fmt(e.duration_seconds)+' s':''}${e.call_id!=null?' · #'+e.call_id:''}`,'tag'));card.append(label,node('pre',JSON.stringify(e.body,null,2)));panel.append(card)}
}
function filters(){const options=new Set(data.sessions.map(s=>s.agent));const old=$('agentFilter').value;$('agentFilter').replaceChildren(node('option','All agents / 全部客户端'));for(const a of options){const option=node('option',a);option.value=a;$('agentFilter').append(option)}$('agentFilter').firstChild.value='';$('agentFilter').value=old}
async function refresh(){if(!LIVE){render();return}try{const r=await fetch('/api/sessions',{cache:'no-store'});if(!r.ok)throw Error(r.status);data=await r.json();filters();render();$('status').textContent='Updated / 已刷新'}catch(e){$('status').textContent='Refresh failed / 刷新失败: '+e.message}}
for(const id of ['search','agentFilter','eventFilter'])$(id).addEventListener('input',render);$('refresh').onclick=refresh;$('auto').onchange=()=>{if($('auto').checked)refresh()};filters();render();setInterval(()=>{if(LIVE&&$('auto').checked)refresh()},5000);
"""


def render_dashboard(snapshot: dict, *, live: bool = False) -> str:
    """Render a complete offline view, escaping embedded data before JavaScript."""
    payload = (
        json.dumps(snapshot, ensure_ascii=False, allow_nan=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    return (
        """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>IDA MCP · Sessions / 会话</title><style>"""
        + _STYLE
        + """</style></head><body><header><h1>IDA MCP · Sessions / 会话</h1><p>Local traces, linked agent transcripts and recorded usage / 本地执行记录、关联客户端转录和已记录用量</p><p id="source"></p><div class="controls"><input type="search" id="search" placeholder="Search events / tools / code · 搜索事件、工具、代码"><select id="agentFilter"></select><select id="eventFilter"><option value="">All events / 全部事件</option><option value="mcp">MCP lifecycle / 生命周期</option><option value="tools">Tools / 工具</option><option value="errors">Errors / 错误</option><option value="agent">Agent / 客户端</option></select><button id="refresh">Refresh / 刷新</button><label><input id="auto" type="checkbox" checked> Auto refresh / 自动刷新</label><span id="status"></span></div></header><main class="layout"><aside id="sessions"></aside><section id="detail"></section></main><script>const INITIAL="""
        + payload
        + ";const LIVE="
        + ("true" if live else "false")
        + ";\n"
        + _SCRIPT
        + "</script></body></html>"
    )


def export_dashboard(log_path: Path, output_path: Path) -> Path:
    """Export one JSONL trace or a state directory to standalone HTML."""
    paths = [log_path] if log_path.is_file() else None
    store = DashboardStore(log_path if paths is None else log_path.parent, paths)
    snapshot = store.snapshot()
    sources = {Path(s["path"]).resolve() for s in snapshot["sessions"]}
    sources.update(path for path, _kind in store._transcripts.values())
    if output_path.expanduser().resolve() in sources:
        raise ValueError("Output cannot overwrite a trace or linked transcript")
    document = render_dashboard(snapshot)
    output_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")
    output_path.chmod(0o600)
    return output_path


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def create_dashboard_server(
    store: DashboardStore, host: str = "127.0.0.1", port: int = 8745
) -> ThreadingHTTPServer:
    """Create an unstarted loopback server; useful to embedding applications."""
    if not _loopback(host):
        raise ValueError("Dashboard must bind to a loopback address")

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, mime: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            try:
                authority = urlsplit("//" + self.headers.get("Host", ""))
                allowed = (
                    authority.hostname is not None
                    and _loopback(authority.hostname)
                    and authority.port in {None, self.server.server_port}
                    and not authority.username
                    and not authority.path
                    and not authority.query
                    and not authority.fragment
                )
                origin = self.headers.get("Origin")
                if origin:
                    parsed_origin = urlsplit(origin)
                    allowed = (
                        allowed
                        and parsed_origin.scheme == "http"
                        and parsed_origin.hostname is not None
                        and _loopback(parsed_origin.hostname)
                        and parsed_origin.port == self.server.server_port
                    )
            except ValueError:
                allowed = False
            if not allowed:
                self._send(403, b"Localhost requests only", "text/plain; charset=utf-8")
                return
            route = urlsplit(self.path)
            if route.query or route.fragment:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
                return
            if route.path == "/":
                self._send(
                    200,
                    render_dashboard(store.snapshot(), live=True).encode("utf-8"),
                    "text/html; charset=utf-8",
                )
                return
            if route.path == "/api/sessions":
                value = store.snapshot()
            elif route.path.startswith("/api/transcripts/"):
                store.snapshot(include_transcript_items=False)
                value = store.transcript(route.path.removeprefix("/api/transcripts/"))
                if value is None:
                    self._send(404, b"Not found", "text/plain; charset=utf-8")
                    return
            else:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
                return
            self._send(
                200,
                json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )

        def log_message(self, format: str, *args) -> None:
            pass

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET

    return Server((host, port), Handler)


def serve_dashboard(
    state_dir: Path,
    host: str = "127.0.0.1",
    port: int = 8745,
    open_browser: bool = False,
) -> None:
    server = create_dashboard_server(DashboardStore(state_dir), host, port)
    try:
        if open_browser:
            address = f"[{host}]" if ":" in host else host
            webbrowser.open(f"http://{address}:{server.server_port}/")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
