import argparse
import asyncio
import html
import json
import time
from dataclasses import asdict, dataclass
from typing import Any

from common.crypto import CryptoBox
from common.protocol import (
    BUFFER_SIZE,
    ProtocolError,
    close_writer,
    read_encrypted_frame,
    read_handshake,
    read_json_frame,
    write_encrypted_frame,
    write_json_frame,
    write_stream_eof,
)


@dataclass(frozen=True)
class ServerConfig:
    listen_host: str
    listen_port: int
    admin_host: str
    admin_port: int
    token: str
    cipher: str


@dataclass
class ConnectionRecord:
    id: int
    client: str
    target: str
    protocol: str
    started_at: float
    ended_at: float | None = None
    uploaded: int = 0
    downloaded: int = 0
    status: str = "connecting"
    error: str = ""


class StatsStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._next_id = 1
        self._records: dict[int, ConnectionRecord] = {}
        self._history: list[dict[str, Any]] = []
        self._start_time: float | None = None

    async def open(self, client: str, target: str, protocol: str) -> int:
        async with self._lock:
            record_id = self._next_id
            self._next_id += 1
            if self._start_time is None:
                self._start_time = time.time()
            self._records[record_id] = ConnectionRecord(
                id=record_id,
                client=client,
                target=target,
                protocol=protocol,
                started_at=time.time(),
            )
            self._sample_locked(force=True)
            return record_id

    async def set_status(self, record_id: int, status: str) -> None:
        async with self._lock:
            if record_id in self._records:
                self._records[record_id].status = status
                self._sample_locked()

    async def add_uploaded(self, record_id: int, size: int) -> None:
        async with self._lock:
            if record_id in self._records:
                self._records[record_id].uploaded += size
                self._sample_locked()

    async def add_downloaded(self, record_id: int, size: int) -> None:
        async with self._lock:
            if record_id in self._records:
                self._records[record_id].downloaded += size
                self._sample_locked()

    async def close(self, record_id: int, status: str = "closed", error: str = "") -> None:
        async with self._lock:
            record = self._records.get(record_id)
            if record:
                record.status = status
                record.error = error
                record.ended_at = time.time()
                self._sample_locked(force=True)

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            records = sorted(self._records.values(), key=lambda item: item.id, reverse=True)
            total_uploaded = sum(item.uploaded for item in records)
            total_downloaded = sum(item.downloaded for item in records)
            active = sum(1 for item in records if item.ended_at is None)

            # --- rate calculation from recent history ---
            h = self._history
            upload_rate = 0.0
            download_rate = 0.0
            if len(h) >= 2:
                window = h[-10:]
                dt = window[-1]["time"] - window[0]["time"]
                if dt > 0:
                    upload_rate = max(0, (window[-1]["uploaded"] - window[0]["uploaded"]) / dt)
                    download_rate = max(0, (window[-1]["downloaded"] - window[0]["downloaded"]) / dt)

            # --- protocol distribution ---
            protocol_stats: dict[str, int] = {"http": 0, "https": 0, "socks5": 0}
            target_map: dict[str, dict[str, Any]] = {}
            client_map: dict[str, dict[str, Any]] = {}
            status_stats: dict[str, int] = {
                "connecting": 0, "connected": 0, "active": 0,
                "closed": 0, "error": 0, "failed": 0,
            }
            for r in records:
                p = r.protocol.lower()
                if p in protocol_stats:
                    protocol_stats[p] += 1
                s = r.status.lower()
                if s in status_stats:
                    status_stats[s] += 1
                # target aggregation (strip port)
                host = r.target.rsplit(":", 1)[0] if ":" in r.target else r.target
                if host.startswith("[") and host.endswith("]"):
                    host = host[1:-1]  # unwrap IPv6 brackets
                if host not in target_map:
                    target_map[host] = {"host": host, "count": 0, "uploaded": 0, "downloaded": 0}
                target_map[host]["count"] += 1
                target_map[host]["uploaded"] += r.uploaded
                target_map[host]["downloaded"] += r.downloaded
                # client aggregation (strip port)
                ip = r.client.rsplit(":", 1)[0] if ":" in r.client else r.client
                if ip not in client_map:
                    client_map[ip] = {"ip": ip, "count": 0, "uploaded": 0, "downloaded": 0}
                client_map[ip]["count"] += 1
                client_map[ip]["uploaded"] += r.uploaded
                client_map[ip]["downloaded"] += r.downloaded
            target_stats = sorted(target_map.values(), key=lambda x: x["count"], reverse=True)[:20]
            client_stats = sorted(client_map.values(), key=lambda x: x["count"], reverse=True)[:20]

            return {
                "active": active,
                "total_connections": len(records),
                "total_uploaded": total_uploaded,
                "total_downloaded": total_downloaded,
                "upload_rate": round(upload_rate),
                "download_rate": round(download_rate),
                "start_time": self._start_time or time.time(),
                "history": list(self._history[-120:]),
                "connections": [self._serialize(item) for item in records[:100]],
                "protocol_stats": protocol_stats,
                "target_stats": target_stats,
                "client_stats": client_stats,
                "status_stats": status_stats,
            }

    def _serialize(self, record: ConnectionRecord) -> dict[str, Any]:
        data = asdict(record)
        data["started_at_text"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.started_at))
        data["ended_at_text"] = (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.ended_at))
            if record.ended_at
            else ""
        )
        data["duration"] = round((record.ended_at or time.time()) - record.started_at, 1)
        return data

    def _sample_locked(self, force: bool = False) -> None:
        now = time.time()
        if self._history and not force and now - self._history[-1]["time"] < 1:
            return
        records = list(self._records.values())
        active = sum(1 for item in records if item.ended_at is None)
        total_up = sum(item.uploaded for item in records)
        total_down = sum(item.downloaded for item in records)
        self._history.append({"time": now, "active": active, "uploaded": total_up, "downloaded": total_down})
        self._history = self._history[-120:]


def parse_endpoint(value: str, default_host: str | None = None) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise argparse.ArgumentTypeError(f"bad endpoint: {value}")
        host = value[1:end]
        rest = value[end + 1 :]
        if not rest.startswith(":"):
            raise argparse.ArgumentTypeError(f"missing port: {value}")
        return host, int(rest[1:])
    if ":" not in value:
        if default_host is None:
            raise argparse.ArgumentTypeError(f"missing port: {value}")
        return default_host, int(value)
    host, port_text = value.rsplit(":", 1)
    return host or (default_host or "0.0.0.0"), int(port_text)


def peer_to_text(peer: Any) -> str:
    if isinstance(peer, tuple) and len(peer) >= 2:
        return f"{peer[0]}:{peer[1]}"
    return str(peer)


async def encrypted_client_to_target(
    client_reader: asyncio.StreamReader,
    target_writer: asyncio.StreamWriter,
    box: CryptoBox,
    stats: StatsStore,
    record_id: int,
) -> None:
    while True:
        data = await read_encrypted_frame(client_reader, box)
        if not data:
            await write_stream_eof(target_writer)
            return
        target_writer.write(data)
        await target_writer.drain()
        await stats.add_uploaded(record_id, len(data))


async def target_to_encrypted_client(
    target_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    box: CryptoBox,
    stats: StatsStore,
    record_id: int,
) -> None:
    while True:
        data = await target_reader.read(BUFFER_SIZE)
        if not data:
            await write_encrypted_frame(client_writer, box, b"")
            return
        await write_encrypted_frame(client_writer, box, data)
        await stats.add_downloaded(record_id, len(data))


async def relay_target(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_reader: asyncio.StreamReader,
    target_writer: asyncio.StreamWriter,
    box: CryptoBox,
    stats: StatsStore,
    record_id: int,
) -> tuple[str, str]:
    tasks = [
        asyncio.create_task(encrypted_client_to_target(client_reader, target_writer, box, stats, record_id)),
        asyncio.create_task(target_to_encrypted_client(target_reader, client_writer, box, stats, record_id)),
    ]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
        errors = [
            task.exception()
            for task in done
            if task.exception()
            and not isinstance(task.exception(), (asyncio.IncompleteReadError, ConnectionError))
        ]
        if errors:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            return "error", str(errors[0])
        return "closed", ""
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await close_writer(target_writer)
        await close_writer(client_writer)


async def handle_tunnel(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: ServerConfig,
    stats: StatsStore,
) -> None:
    peer = peer_to_text(writer.get_extra_info("peername"))
    record_id: int | None = None
    target_writer: asyncio.StreamWriter | None = None
    try:
        cipher = await read_handshake(reader, config.token, expected_cipher=config.cipher)
        box = CryptoBox(config.token, cipher)
        request = await read_json_frame(reader, box)
        if request.get("type") != "connect":
            raise ProtocolError("first tunnel frame must be a connect request")
        host = str(request.get("host", "")).strip()
        port = int(request.get("port", 0))
        protocol = str(request.get("proxy_protocol", "tcp"))
        if not host or port <= 0 or port > 65535:
            raise ProtocolError("connect request has an invalid target")
        target = f"{host}:{port}"
        record_id = await stats.open(peer, target, protocol)
        try:
            target_reader, target_writer = await asyncio.open_connection(host, port)
        except OSError as exc:
            await stats.close(record_id, "failed", str(exc))
            await write_json_frame(writer, box, {"type": "connect_response", "ok": False, "error": str(exc)})
            return

        await stats.set_status(record_id, "connected")
        await write_json_frame(writer, box, {"type": "connect_response", "ok": True})
        status, error = await relay_target(
            reader,
            writer,
            target_reader,
            target_writer,
            box,
            stats,
            record_id,
        )
        await stats.close(record_id, status, error)
    except (ProtocolError, OSError, asyncio.IncompleteReadError) as exc:
        if record_id is not None:
            await stats.close(record_id, "error", str(exc))
        print(f"tunnel from {peer} failed: {exc}")
    finally:
        await close_writer(target_writer)
        await close_writer(writer)


ADMIN_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lic-proxy Monitor</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"></script>
<style>
:root{
  --bg-root:#080c14;--bg-card:#0f1522;--bg-input:#151d2c;
  --border:#1e2a3d;--border-hover:#2d3d58;
  --text-primary:#e4eaf2;--text-secondary:#8b9fc0;--text-muted:#556580;
  --blue:#4da8ff;--green:#34d399;--amber:#fbbf24;--red:#f87171;
  --cyan:#22d3ee;--purple:#a78bfa;--gray:#6b7280;
  --radius:10px;--radius-sm:6px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
    "Microsoft YaHei","PingFang SC","Noto Sans SC",sans-serif;
  background:var(--bg-root);color:var(--text-primary);
  font-size:13px;line-height:1.5;
  overflow-y:scroll;overflow-x:hidden;
}
body::-webkit-scrollbar{width:8px}
body::-webkit-scrollbar-track{background:var(--bg-root)}
body::-webkit-scrollbar-thumb{background:#2d3d58;border-radius:4px}
body::-webkit-scrollbar-thumb:hover{background:#3d5170}

/* header */
header{
  position:sticky;top:0;z-index:100;
  display:flex;align-items:center;justify-content:space-between;
  padding:14px 28px;background:rgba(15,21,34,0.92);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border-bottom:1px solid var(--border);
}
header h1{font-size:18px;font-weight:700;letter-spacing:-0.3px}
header h1 span{color:var(--blue);font-weight:400}
.status-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);margin-right:6px;box-shadow:0 0 6px var(--green)}
.header-right{display:flex;align-items:center;gap:16px;color:var(--text-secondary);font-size:12px}
.header-right .uptime{color:var(--text-muted)}

/* main */
main{padding:20px 24px;max-width:1480px;margin:0 auto}

/* KPI cards */
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:16px}
.kpi{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:var(--radius);padding:16px 20px;
  position:relative;overflow:hidden;
  transition:border-color 0.2s;
}
.kpi:hover{border-color:var(--border-hover)}
.kpi::before{
  content:'';position:absolute;top:0;left:0;right:0;height:3px;
}
.kpi.active::before{background:var(--green)}
.kpi.total::before{background:var(--blue)}
.kpi.up::before{background:var(--blue)}
.kpi.down::before{background:var(--green)}
.kpi .kpi-label{font-size:11px;text-transform:uppercase;letter-spacing:0.6px;color:var(--text-secondary);margin-bottom:6px}
.kpi .kpi-value{font-size:28px;font-weight:800;letter-spacing:-0.5px;line-height:1.1}
.kpi .kpi-sub{font-size:11px;color:var(--text-muted);margin-top:4px}

/* chart sections */
.charts{display:grid;gap:14px;margin-bottom:16px}
.chart-row{display:grid;gap:14px}
.chart-row.r1{grid-template-columns:3fr 1fr}
.chart-row.r2{grid-template-columns:1fr 2fr}
.chart-row.r3{grid-template-columns:1fr 2fr}
.chart-box{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:var(--radius);padding:8px 14px 6px 10px;
  min-height:280px;position:relative;
}
.chart-box .chart-title{
  font-size:12px;font-weight:600;color:var(--text-secondary);
  padding:4px 0 0 4px;letter-spacing:0.3px;
}
.chart-box .chart-inner{width:100%;height:260px}
.chart-box.tall .chart-inner{height:300px}

/* table section */
.table-section{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:var(--radius);overflow:hidden;
}
.table-toolbar{
  display:flex;align-items:center;gap:10px;flex-wrap:wrap;
  padding:12px 16px;border-bottom:1px solid var(--border);
  background:rgba(15,21,34,0.6);
}
.table-toolbar input[type="search"]{
  background:var(--bg-input);border:1px solid var(--border);
  border-radius:var(--radius-sm);padding:7px 12px;
  color:var(--text-primary);font-size:12px;outline:none;
  min-width:220px;transition:border-color 0.2s;
}
.table-toolbar input[type="search"]:focus{border-color:var(--blue)}
.table-toolbar input[type="search"]::placeholder{color:var(--text-muted)}
.table-toolbar select{
  background:var(--bg-input);border:1px solid var(--border);
  border-radius:var(--radius-sm);padding:7px 10px;
  color:var(--text-primary);font-size:12px;outline:none;cursor:pointer;
}
.table-toolbar select:focus{border-color:var(--blue)}
.table-info{color:var(--text-muted);font-size:11px;margin-left:auto}
.table-wrap{overflow-x:auto;max-height:480px;overflow-y:auto}
.table-wrap::-webkit-scrollbar{width:6px;height:6px}
.table-wrap::-webkit-scrollbar-track{background:var(--bg-card)}
.table-wrap::-webkit-scrollbar-thumb{background:#2d3d58;border-radius:3px}
table{width:100%;border-collapse:collapse;font-size:12px;white-space:nowrap}
thead{position:sticky;top:0;z-index:2}
thead th{
  background:#151e30;color:var(--text-secondary);
  padding:10px 12px;text-align:left;font-weight:600;
  font-size:11px;text-transform:uppercase;letter-spacing:0.4px;
  border-bottom:2px solid var(--border);cursor:pointer;
  user-select:none;transition:color 0.15s;
}
thead th:hover{color:var(--text-primary)}
thead th .sort-arrow{font-size:10px;margin-left:2px;opacity:0.4}
thead th .sort-arrow.on{opacity:1;color:var(--blue)}
tbody td{padding:9px 12px;border-bottom:1px solid rgba(30,42,61,0.6);color:var(--text-secondary)}
tbody tr:hover td{background:rgba(77,168,255,0.03);color:var(--text-primary)}
tbody tr:nth-child(even) td{background:rgba(255,255,255,0.008)}
tbody tr:nth-child(even):hover td{background:rgba(77,168,255,0.04)}

/* status badges */
.badge{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:600;letter-spacing:0.2px}
.badge.active,.badge.connected{background:rgba(52,211,153,0.15);color:var(--green)}
.badge.connecting{background:rgba(251,191,36,0.15);color:var(--amber)}
.badge.closed{background:rgba(107,114,128,0.15);color:var(--gray)}
.badge.error,.badge.failed{background:rgba(248,113,113,0.15);color:var(--red)}

/* pagination */
.pagination{display:flex;align-items:center;justify-content:center;gap:4px;padding:12px;border-top:1px solid var(--border)}
.pagination button{
  background:var(--bg-input);border:1px solid var(--border);color:var(--text-secondary);
  border-radius:var(--radius-sm);padding:5px 11px;font-size:12px;cursor:pointer;
  transition:all 0.15s;
}
.pagination button:hover:not(:disabled){border-color:var(--blue);color:var(--text-primary)}
.pagination button:disabled{opacity:0.35;cursor:default}
.pagination button.active{background:var(--blue);border-color:var(--blue);color:#fff;font-weight:700}
.pagination .page-info{color:var(--text-muted);font-size:11px;margin:0 8px}

/* disconnected */
.disconnected{display:none;align-items:center;gap:6px;color:var(--red);font-size:12px}
.disconnected.show{display:flex}
.disconnected .dot{width:6px;height:6px;border-radius:50%;background:var(--red)}

/* responsive */
@media(max-width:1200px){
  .kpi-grid{grid-template-columns:repeat(2,1fr)}
  .chart-row.r1{grid-template-columns:1fr}
  .chart-row.r2{grid-template-columns:1fr}
  .chart-row.r3{grid-template-columns:1fr}
}
@media(max-width:768px){
  .kpi-grid{grid-template-columns:1fr}
  main{padding:12px}
  header{padding:12px 16px}
  header h1{font-size:15px}
  .header-right{display:none}
  .table-toolbar{flex-direction:column;align-items:stretch}
  .table-toolbar input[type="search"]{min-width:auto}
  .table-info{margin-left:0}
}
</style>
</head>
<body>
<header>
  <h1><span class="status-dot"></span>Lic<span>-proxy</span> Monitor</h1>
  <div class="header-right">
    <span class="uptime" id="uptime">--</span>
    <span id="clock">--:--:--</span>
    <span class="disconnected" id="disc"><span class="dot"></span>disconnected</span>
  </div>
</header>
<main>

<!-- KPI -->
<div class="kpi-grid">
  <div class="kpi active"><div class="kpi-label">Active Connections</div><div class="kpi-value" id="k-active">0</div><div class="kpi-sub" id="k-active-sub">&nbsp;</div></div>
  <div class="kpi total"><div class="kpi-label">Total Connections</div><div class="kpi-value" id="k-total">0</div><div class="kpi-sub" id="k-total-sub">&nbsp;</div></div>
  <div class="kpi up"><div class="kpi-label">Upload Rate</div><div class="kpi-value" id="k-up">0 B/s</div><div class="kpi-sub" id="k-up-sub">Total: 0 B</div></div>
  <div class="kpi down"><div class="kpi-label">Download Rate</div><div class="kpi-value" id="k-down">0 B/s</div><div class="kpi-sub" id="k-down-sub">Total: 0 B</div></div>
</div>

<!-- charts row 1: traffic + active -->
<div class="charts">
  <div class="chart-row r1">
    <div class="chart-box tall">
      <div class="chart-title">Traffic Rate</div>
      <div class="chart-inner" id="ch-traffic"></div>
    </div>
    <div class="chart-box tall">
      <div class="chart-title">Active Connections</div>
      <div class="chart-inner" id="ch-active"></div>
    </div>
  </div>
</div>

<!-- charts row 2: protocol + targets -->
<div class="charts">
  <div class="chart-row r2">
    <div class="chart-box">
      <div class="chart-title">Protocol Distribution</div>
      <div class="chart-inner" id="ch-protocol"></div>
    </div>
    <div class="chart-box">
      <div class="chart-title">Top Target Domains</div>
      <div class="chart-inner" id="ch-targets"></div>
    </div>
  </div>
</div>

<!-- charts row 3: status + clients -->
<div class="charts">
  <div class="chart-row r3">
    <div class="chart-box">
      <div class="chart-title">Connection Status</div>
      <div class="chart-inner" id="ch-status"></div>
    </div>
    <div class="chart-box">
      <div class="chart-title">Top Client IPs</div>
      <div class="chart-inner" id="ch-clients"></div>
    </div>
  </div>
</div>

<!-- table -->
<div class="table-section">
  <div class="table-toolbar">
    <input type="search" id="tb-search" placeholder="Search connections...">
    <select id="tb-status">
      <option value="all">All Status</option>
      <option value="active">Active</option>
      <option value="connecting">Connecting</option>
      <option value="connected">Connected</option>
      <option value="closed">Closed</option>
      <option value="error">Error</option>
      <option value="failed">Failed</option>
    </select>
    <select id="tb-protocol">
      <option value="all">All Protocols</option>
      <option value="http">HTTP</option>
      <option value="https">HTTPS</option>
      <option value="socks5">SOCKS5</option>
    </select>
    <span class="table-info" id="tb-info">0 connections</span>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th data-col="id">ID <span class="sort-arrow on">▼</span></th>
          <th data-col="client">Client</th>
          <th data-col="target">Target</th>
          <th data-col="protocol">Protocol</th>
          <th data-col="status">Status</th>
          <th data-col="uploaded">Upload</th>
          <th data-col="downloaded">Download</th>
          <th data-col="duration">Duration</th>
          <th data-col="error">Error</th>
        </tr>
      </thead>
      <tbody id="tb-body"></tbody>
    </table>
  </div>
  <div class="pagination" id="tb-pager"></div>
</div>

</main>

<script>
// ── helpers ──
var fmt=function(b){
  if(!b||b<0)return'0 B';
  var u=['B','KB','MB','GB','TB'],i=0;
  while(b>=1024&&i<u.length-1){b/=1024;i++}
  return b.toFixed(i>0?1:0)+' '+u[i];
};
var fmtDur=function(s){
  if(s===null||s===undefined)return'--';
  if(s<60)return Math.round(s)+'s';
  return Math.floor(s/60)+'m '+Math.round(s%60)+'s';
};
var esc=function(s){
  return String(s||'').replace(/[&<>"']/g,function(c){
    return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
};

// ── echarts init ──
var makeOpt=function(series,extra){
  var o={
    animation:true,animationDuration:600,
    backgroundColor:'transparent',
    textStyle:{color:'#8b9fc0'},
    grid:{left:52,right:16,top:10,bottom:24},
    tooltip:{backgroundColor:'#151d2c',borderColor:'#2d3d58',textStyle:{color:'#e4eaf2',fontSize:12}},
  };
  if(extra&&extra.legend){o.legend={top:0,left:0,textStyle:{color:'#8b9fc0',fontSize:11},data:extra.legend};o.grid.top=28}
  if(extra&&extra.xAxis){o.xAxis=extra.xAxis}
  else{
    o.xAxis={type:'time',axisLine:{lineStyle:{color:'#1e2a3d'}},axisLabel:{color:'#8b9fc0',fontSize:10},splitLine:{show:false}};
  }
  if(extra&&extra.yAxis){o.yAxis=extra.yAxis}
  else{
    o.yAxis={type:'value',splitLine:{lineStyle:{color:'rgba(30,42,61,0.5)'}},axisLabel:{color:'#8b9fc0',fontSize:10}};
  }
  o.series=Array.isArray(series)?series:[series];
  return o;
};

var ch={};
['traffic','active','protocol','targets','status','clients'].forEach(function(id){
  var dom=document.getElementById('ch-'+id);
  if(dom)ch[id]=echarts.init(dom,null,{renderer:'canvas'});
});

// ── chart builders ──
var buildTraffic=function(d){
  // d: {times:[ms,...], upload:[], download:[]}
  return makeOpt([
    {name:'Upload',type:'line',smooth:true,symbol:'none',lineStyle:{color:'#4da8ff',width:2},
     areaStyle:{color:new echarts.graphic.LinearGradient(0,0,0,1,[
       {offset:0,color:'rgba(77,168,255,0.18)'},{offset:1,color:'rgba(77,168,255,0.01)'}])},
     data:d.upload.map(function(v,i){return[d.times[i],v]})},
    {name:'Download',type:'line',smooth:true,symbol:'none',lineStyle:{color:'#34d399',width:2},
     areaStyle:{color:new echarts.graphic.LinearGradient(0,0,0,1,[
       {offset:0,color:'rgba(52,211,153,0.18)'},{offset:1,color:'rgba(52,211,153,0.01)'}])},
     data:d.download.map(function(v,i){return[d.times[i],v]})}
  ],{legend:['Upload','Download'],yAxis:{type:'value',splitLine:{lineStyle:{color:'rgba(30,42,61,0.5)'}},axisLabel:{color:'#8b9fc0',fontSize:10,formatter:fmt}}});
};

var buildActive=function(data){
  return makeOpt(
    {name:'Active',type:'line',smooth:true,symbol:'none',lineStyle:{color:'#fbbf24',width:2},
     areaStyle:{color:new echarts.graphic.LinearGradient(0,0,0,1,[
       {offset:0,color:'rgba(251,191,36,0.18)'},{offset:1,color:'rgba(251,191,36,0.01)'}])},
     data:data},
    {yAxis:{type:'value',minInterval:1,splitLine:{lineStyle:{color:'rgba(30,42,61,0.5)'}},axisLabel:{color:'#8b9fc0',fontSize:10}}}
  );
};

var buildPie=function(map,colors,centerText){
  var data=Object.keys(map).map(function(k){return{name:k,value:map[k]}}).filter(function(d){return d.value>0});
  if(!data.length)data=[{name:'No data',value:1,itemStyle:{color:'#1e2a3d'}}];
  return {
    backgroundColor:'transparent',
    tooltip:{trigger:'item',backgroundColor:'#151d2c',borderColor:'#2d3d58',textStyle:{color:'#e4eaf2',fontSize:12},
      formatter:function(p){return p.name+': '+p.value+' ('+p.percent+'%)'}},
    series:[{
      type:'pie',radius:['48%','72%'],center:['50%','50%'],
      avoidLabelOverlap:false,label:{show:true,position:'outside',color:'#8b9fc0',fontSize:10,
        formatter:function(p){return p.name+'\n'+p.value}},
      labelLine:{lineStyle:{color:'#2d3d58'}},
      emphasis:{scaleSize:6,label:{fontSize:13,fontWeight:'bold'}},
      itemStyle:{borderColor:'#0f1522',borderWidth:2},
      data:data
    }],
    color:colors||['#4da8ff','#34d399','#a78bfa','#22d3ee','#fbbf24','#f87171','#6b7280'],
    graphic:centerText?[{type:'text',left:'center',top:'center',style:{text:centerText,textAlign:'center',fill:'#8b9fc0',fontSize:13,fontWeight:600}}]:[]
  };
};

var buildBar=function(list,color,labelKey,valueKey){
  if(!list||!list.length)return makeOpt({type:'bar',data:[]});
  var names=list.map(function(x){var s=x[labelKey||'host'];return s.length>30?s.slice(0,28)+'…':s}).reverse();
  var vals=list.map(function(x){return x[valueKey||'count']}).reverse();
  return {
    backgroundColor:'transparent',
    tooltip:{trigger:'axis',backgroundColor:'#151d2c',borderColor:'#2d3d58',textStyle:{color:'#e4eaf2',fontSize:12},
      axisPointer:{type:'shadow'},
      formatter:function(ps){var p=ps[0];return esc(p.name)+': '+p.value}},
    grid:{left:4,right:16,top:4,bottom:20},
    xAxis:{type:'value',splitLine:{lineStyle:{color:'rgba(30,42,61,0.5)'}},axisLabel:{color:'#8b9fc0',fontSize:10,formatter:function(v){return v>=1000?(v/1000).toFixed(1)+'k':v}}},
    yAxis:{type:'category',data:names,axisLine:{lineStyle:{color:'#1e2a3d'}},axisLabel:{color:'#8b9fc0',fontSize:10},axisTick:{show:false}},
    series:[{type:'bar',data:vals,barWidth:'60%',itemStyle:{color:color||'#4da8ff',borderRadius:[0,4,4,0]},
      emphasis:{itemStyle:{color:color||'#4da8ff'}}}]
  };
};

// ── rate computation ──
var computeRates=function(history){
  var times=[],up=[],down=[];
  for(var i=1;i<history.length;i++){
    var dt=history[i].time-history[i-1].time;
    var du=history[i].uploaded-history[i-1].uploaded;
    var dd=history[i].downloaded-history[i-1].downloaded;
    times.push(history[i].time*1000);
    up.push(dt>0?Math.round(du/dt):0);
    down.push(dt>0?Math.round(dd/dt):0);
  }
  return{times:times,upload:up,download:down};
};

// ── table state ──
var allConns=[],sortCol='id',sortAsc=false;
var filterStatus='all',filterProtocol='all';
var page=0,pageSize=20;

var renderTable=function(){
  var conns=allConns.slice();
  // filter
  if(filterStatus!=='all')conns=conns.filter(function(c){return c.status===filterStatus});
  if(filterProtocol!=='all')conns=conns.filter(function(c){return c.protocol===filterProtocol});
  var q=(document.getElementById('tb-search').value||'').toLowerCase();
  if(q){
    conns=conns.filter(function(c){
      return String(c.id).includes(q)||(c.client||'').toLowerCase().includes(q)||
        (c.target||'').toLowerCase().includes(q)||(c.protocol||'').toLowerCase().includes(q);
    });
  }
  // sort
  conns.sort(function(a,b){
    var va=a[sortCol],vb=b[sortCol];
    if(typeof va==='string')va=va.toLowerCase();
    if(typeof vb==='string')vb=vb.toLowerCase();
    if(va===null||va===undefined)va='';
    if(vb===null||vb===undefined)vb='';
    if(va<vb)return sortAsc?-1:1;
    if(va>vb)return sortAsc?1:-1;
    return 0;
  });
  // paginate
  var totalPages=Math.max(1,Math.ceil(conns.length/pageSize));
  if(page>=totalPages)page=totalPages-1;
  if(page<0)page=0;
  var items=conns.slice(page*pageSize,(page+1)*pageSize);
  // render
  var tbody=document.getElementById('tb-body');
  tbody.innerHTML=items.map(function(c){
    return'<tr><td>'+c.id+'</td><td>'+esc(c.client)+'</td><td>'+esc(c.target)+'</td>'+
      '<td>'+esc(c.protocol)+'</td><td><span class="badge '+esc(c.status)+'">'+esc(c.status)+'</span></td>'+
      '<td>'+fmt(c.uploaded)+'</td><td>'+fmt(c.downloaded)+'</td><td>'+fmtDur(c.duration)+'</td>'+
      '<td style="color:var(--red)">'+esc(c.error||'')+'</td></tr>';
  }).join('');
  document.getElementById('tb-info').textContent=conns.length+' connections';
  // pagination
  var pager=document.getElementById('tb-pager');
  var html='';
  html+='<button '+(page<=0?'disabled':'')+' onclick="goPage('+(page-1)+')">◀</button>';
  for(var i=0;i<totalPages&&i<7;i++){
    var pg;
    if(totalPages<=7){pg=i}
    else if(page<=3){pg=i}
    else if(page>=totalPages-4){pg=totalPages-7+i}
    else{pg=page-3+i}
    html+='<button class="'+(pg===page?'active':'')+'" onclick="goPage('+pg+')">'+(pg+1)+'</button>';
  }
  html+='<button '+(page>=totalPages-1?'disabled':'')+' onclick="goPage('+(page+1)+')">▶</button>';
  if(totalPages>7)html+='<span class="page-info">/ '+totalPages+' pages</span>';
  pager.innerHTML=html;
};
var goPage=function(p){
  page=p;
  var conns=allConns.slice();
  if(filterStatus!=='all')conns=conns.filter(function(c){return c.status===filterStatus});
  if(filterProtocol!=='all')conns=conns.filter(function(c){return c.protocol===filterProtocol});
  var totalPages=Math.max(1,Math.ceil(conns.length/pageSize));
  if(page<0)page=0;
  if(page>=totalPages)page=totalPages-1;
  renderTable();
};

// table header click
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('thead th').forEach(function(th){
    th.addEventListener('click',function(){
      var col=th.getAttribute('data-col');
      if(!col)return;
      if(sortCol===col)sortAsc=!sortAsc;
      else{sortCol=col;sortAsc=true}
      document.querySelectorAll('thead th .sort-arrow').forEach(function(a){a.classList.remove('on')});
      th.querySelector('.sort-arrow').classList.add('on');
      th.querySelector('.sort-arrow').textContent=sortAsc?'▲':'▼';
      page=0;renderTable();
    });
  });
  document.getElementById('tb-search').addEventListener('input',function(){page=0;renderTable()});
  document.getElementById('tb-status').addEventListener('change',function(){
    filterStatus=this.value;page=0;renderTable();
  });
  document.getElementById('tb-protocol').addEventListener('change',function(){
    filterProtocol=this.value;page=0;renderTable();
  });
});

// ── refresh ──
var failCount=0,firstLoad=true;
var refresh=function(){
  fetch('/api/stats').then(function(r){return r.json()}).then(function(s){
    failCount=0;
    document.getElementById('disc').classList.remove('show');
    document.querySelector('.status-dot').style.background='var(--green)';
    document.querySelector('.status-dot').style.boxShadow='0 0 6px var(--green)';

    // KPI
    document.getElementById('k-active').textContent=s.active;
    document.getElementById('k-active-sub').textContent=(s.status_stats?Object.values(s.status_stats).reduce(function(a,b){return a+b},0):0)+' total records';
    document.getElementById('k-total').textContent=s.total_connections;
    var upDur=fmtDur(s.start_time?(Date.now()/1000-s.start_time):0);
    document.getElementById('k-total-sub').textContent='Uptime: '+upDur;
    document.getElementById('k-up').textContent=fmt(s.upload_rate)+'/s';
    document.getElementById('k-up-sub').textContent='Total: '+fmt(s.total_uploaded);
    document.getElementById('k-down').textContent=fmt(s.download_rate)+'/s';
    document.getElementById('k-down-sub').textContent='Total: '+fmt(s.total_downloaded);

    // clock + uptime
    document.getElementById('clock').textContent=new Date().toLocaleTimeString();
    if(s.start_time){
      var upSec=Math.floor(Date.now()/1000-s.start_time);
      var h=Math.floor(upSec/3600),m=Math.floor((upSec%3600)/60),sec=upSec%60;
      document.getElementById('uptime').textContent='up '+h+'h '+m+'m '+sec+'s';
    }

    // charts
    var rates=computeRates(s.history||[]);
    if(s.history&&s.history.length>1&&ch.traffic)ch.traffic.setOption(buildTraffic(rates),!firstLoad);
    if(s.history&&s.history.length>0&&ch.active){
      var ad=s.history.map(function(h){return[h.time*1000,h.active]});
      ch.active.setOption(buildActive(ad),!firstLoad);
    }
    if(s.protocol_stats&&ch.protocol){
      var protoTotal=Object.values(s.protocol_stats).reduce(function(a,b){return a+b},0);
      ch.protocol.setOption(buildPie(s.protocol_stats,['#4da8ff','#34d399','#a78bfa'],protoTotal>0?String(protoTotal):''),!firstLoad);
    }
    if(s.target_stats&&ch.targets)ch.targets.setOption(buildBar(s.target_stats,'#4da8ff','host','count'),!firstLoad);
    if(s.status_stats&&ch.status){
      var stColors={'active':'#34d399','connected':'#22d3ee','connecting':'#fbbf24','closed':'#6b7280','error':'#f87171','failed':'#f87171'};
      var stList=Object.keys(s.status_stats).filter(function(k){return s.status_stats[k]>0}).map(function(k){return s.status_stats[k]});
      var stNames=Object.keys(s.status_stats).filter(function(k){return s.status_stats[k]>0});
      ch.status.setOption(buildPie(s.status_stats,[
        stColors[stNames[0]]||'#6b7280',stColors[stNames[1]]||'#6b7280',
        stColors[stNames[2]]||'#6b7280',stColors[stNames[3]]||'#6b7280',
        stColors[stNames[4]]||'#6b7280',stColors[stNames[5]]||'#6b7280'
      ]),!firstLoad);
    }
    if(s.client_stats&&ch.clients)ch.clients.setOption(buildBar(s.client_stats,'#22d3ee','ip','count'),!firstLoad);

    // table
    allConns=s.connections||[];
    renderTable();
    firstLoad=false;
  }).catch(function(){
    failCount++;
    if(failCount>=3){
      document.getElementById('disc').classList.add('show');
      document.querySelector('.status-dot').style.background='var(--red)';
      document.querySelector('.status-dot').style.boxShadow='0 0 6px var(--red)';
    }
  });
};

// ── start ──
refresh();
var timer=setInterval(refresh,1000);

// visibility optimization
document.addEventListener('visibilitychange',function(){
  if(document.hidden){
    clearInterval(timer);
  }else{
    refresh();
    timer=setInterval(refresh,1000);
  }
});

// resize
window.addEventListener('resize',function(){
  Object.keys(ch).forEach(function(k){if(ch[k])ch[k].resize()});
});
</script>
</body></html>"""


async def write_http_response(
    writer: asyncio.StreamWriter,
    status: str,
    content_type: str,
    body: bytes,
) -> None:
    header = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    writer.write(header + body)
    await writer.drain()


async def handle_admin(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    stats: StatsStore,
) -> None:
    try:
        request = await reader.readuntil(b"\r\n\r\n")
        first_line = request.decode("iso-8859-1", "replace").splitlines()[0]
        parts = first_line.split()
        path = parts[1] if len(parts) >= 2 else "/"
        if path == "/api/stats":
            body = json.dumps(await stats.snapshot(), ensure_ascii=False).encode("utf-8")
            await write_http_response(writer, "200 OK", "application/json; charset=utf-8", body)
        else:
            await write_http_response(writer, "200 OK", "text/html; charset=utf-8", ADMIN_HTML.encode("utf-8"))
    except Exception as exc:
        body = html.escape(str(exc)).encode("utf-8")
        try:
            await write_http_response(writer, "500 Internal Server Error", "text/plain; charset=utf-8", body)
        except Exception:
            pass
    finally:
        await close_writer(writer)


async def run(config: ServerConfig) -> None:
    stats = StatsStore()
    tunnel_server = await asyncio.start_server(
        lambda reader, writer: handle_tunnel(reader, writer, config, stats),
        config.listen_host,
        config.listen_port,
    )
    admin_server = await asyncio.start_server(
        lambda reader, writer: handle_admin(reader, writer, stats),
        config.admin_host,
        config.admin_port,
    )
    tunnel_sockets = ", ".join(str(sock.getsockname()) for sock in tunnel_server.sockets or [])
    admin_sockets = ", ".join(str(sock.getsockname()) for sock in admin_server.sockets or [])
    print(f"tunnel server listening on {tunnel_sockets}, cipher={config.cipher}")
    print(f"admin dashboard listening on http://{config.admin_host}:{config.admin_port} ({admin_sockets})")
    async with tunnel_server, admin_server:
        await asyncio.gather(tunnel_server.serve_forever(), admin_server.serve_forever())


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lic-proxy remote encrypted tunnel server")
    parser.add_argument("--listen", default="0.0.0.0:9000", help="tunnel listen address")
    parser.add_argument("--admin", default="127.0.0.1:8080", help="admin dashboard listen address")
    parser.add_argument("--token", required=True, help="shared secret token")
    parser.add_argument("--cipher", choices=["aesgcm", "chacha20"], default="aesgcm")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    listen_host, listen_port = parse_endpoint(args.listen, "0.0.0.0")
    admin_host, admin_port = parse_endpoint(args.admin, "127.0.0.1")
    config = ServerConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        admin_host=admin_host,
        admin_port=admin_port,
        token=args.token,
        cipher=args.cipher,
    )
    asyncio.run(run(config))


if __name__ == "__main__":
    main()
