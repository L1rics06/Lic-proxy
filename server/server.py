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

    async def open(self, client: str, target: str, protocol: str) -> int:
        async with self._lock:
            record_id = self._next_id
            self._next_id += 1
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
            return {
                "active": active,
                "total_connections": len(records),
                "total_uploaded": total_uploaded,
                "total_downloaded": total_downloaded,
                "history": list(self._history[-120:]),
                "connections": [self._serialize(item) for item in records[:100]],
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
        total_bytes = sum(item.uploaded + item.downloaded for item in records)
        self._history.append({"time": now, "active": active, "total_bytes": total_bytes})
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


ADMIN_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lic-proxy Monitor</title>
<style>
body{margin:0;font-family:Arial,"Microsoft YaHei",sans-serif;background:#f5f7fb;color:#1f2937}
header{padding:18px 24px;background:#172033;color:white}
h1{margin:0;font-size:22px}
main{padding:20px;max-width:1180px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px}
.card{background:white;border:1px solid #d9e1ec;border-radius:8px;padding:14px}
.label{font-size:13px;color:#64748b}.value{font-size:26px;margin-top:6px;font-weight:700}
section{background:white;border:1px solid #d9e1ec;border-radius:8px;padding:14px;margin-bottom:16px}
canvas{width:100%;height:190px;border:1px solid #edf1f7;border-radius:6px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px;border-bottom:1px solid #e5eaf2;text-align:left;white-space:nowrap}
th{background:#f8fafc;color:#475569}.status{font-weight:700}.error{color:#b91c1c}
</style>
</head>
<body>
<header><h1>Lic-proxy Monitor</h1></header>
<main>
<div class="cards">
  <div class="card"><div class="label">活跃连接</div><div class="value" id="active">0</div></div>
  <div class="card"><div class="label">总连接数</div><div class="value" id="total">0</div></div>
  <div class="card"><div class="label">上传流量</div><div class="value" id="up">0 B</div></div>
  <div class="card"><div class="label">下载流量</div><div class="value" id="down">0 B</div></div>
</div>
<section><canvas id="chart" width="1100" height="190"></canvas></section>
<section>
<table>
<thead><tr><th>ID</th><th>客户端</th><th>目标</th><th>协议</th><th>状态</th><th>上传</th><th>下载</th><th>持续</th><th>错误</th></tr></thead>
<tbody id="rows"></tbody>
</table>
</section>
</main>
<script>
function fmt(n){if(n<1024)return n+" B";let u=["KB","MB","GB","TB"],i=-1;do{n/=1024;i++}while(n>=1024&&i<u.length-1);return n.toFixed(1)+" "+u[i]}
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}[c]))}
function draw(history){
 const c=document.getElementById("chart"),ctx=c.getContext("2d"),w=c.width,h=c.height;
 ctx.clearRect(0,0,w,h);ctx.strokeStyle="#d9e1ec";ctx.beginPath();ctx.moveTo(36,10);ctx.lineTo(36,h-24);ctx.lineTo(w-10,h-24);ctx.stroke();
 if(!history.length)return;
 const max=Math.max(1,...history.map(x=>x.total_bytes)); const step=(w-56)/Math.max(1,history.length-1);
 ctx.strokeStyle="#2563eb";ctx.lineWidth=2;ctx.beginPath();
 history.forEach((x,i)=>{let px=36+i*step,py=(h-24)-((x.total_bytes/max)*(h-42)); if(i===0)ctx.moveTo(px,py);else ctx.lineTo(px,py)});
 ctx.stroke();ctx.fillStyle="#64748b";ctx.fillText("total traffic",42,18);
}
async function refresh(){
 const r=await fetch("/api/stats"),s=await r.json();
 active.textContent=s.active; total.textContent=s.total_connections; up.textContent=fmt(s.total_uploaded); down.textContent=fmt(s.total_downloaded);
 rows.innerHTML=s.connections.map(c=>`<tr><td>${c.id}</td><td>${esc(c.client)}</td><td>${esc(c.target)}</td><td>${esc(c.protocol)}</td><td class="status">${esc(c.status)}</td><td>${fmt(c.uploaded)}</td><td>${fmt(c.downloaded)}</td><td>${c.duration}s</td><td class="error">${esc(c.error)}</td></tr>`).join("");
 draw(s.history);
}
refresh();setInterval(refresh,1000);
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
