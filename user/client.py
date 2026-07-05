import argparse
import asyncio
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from common.crypto import CryptoBox
from common.protocol import (
    BUFFER_SIZE,
    ProtocolError,
    close_writer,
    read_encrypted_frame,
    read_json_frame,
    write_encrypted_frame,
    write_handshake,
    write_json_frame,
    write_stream_eof,
)


@dataclass(frozen=True)
class ClientConfig:
    listen_host: str
    listen_port: int
    server_host: str
    server_port: int
    token: str
    cipher: str


@dataclass(frozen=True)
class HttpProxyRequest:
    host: str
    port: int
    protocol: str
    is_connect: bool
    initial_data: bytes


class ClientError(ValueError):
    pass


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
        port = int(rest[1:])
        return host, port
    if ":" not in value:
        if default_host is None:
            raise argparse.ArgumentTypeError(f"missing port: {value}")
        return default_host, int(value)
    host, port_text = value.rsplit(":", 1)
    return host or (default_host or "127.0.0.1"), int(port_text)


def parse_host_port(value: str, default_port: int) -> tuple[str, int]:
    value = value.strip()
    if not value:
        raise ClientError("empty host")
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ClientError("bad IPv6 host")
        host = value[1:end]
        rest = value[end + 1 :]
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, default_port


def find_host_header(lines: list[str]) -> str | None:
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip()
    return None


def parse_http_request(header_bytes: bytes) -> HttpProxyRequest:
    try:
        header_text = header_bytes.decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise ClientError("request headers are not valid HTTP text") from exc
    if not header_text.endswith("\r\n\r\n"):
        raise ClientError("incomplete HTTP headers")
    lines = header_text[:-4].split("\r\n")
    if not lines or len(lines[0].split()) != 3:
        raise ClientError("bad request line")

    method, target, version = lines[0].split()
    method_upper = method.upper()
    if method_upper == "CONNECT":
        host, port = parse_host_port(target, 443)
        return HttpProxyRequest(host, port, "https", True, b"")

    parsed = urlsplit(target)
    if parsed.scheme and parsed.netloc:
        if parsed.scheme.lower() != "http":
            raise ClientError("non-CONNECT HTTPS requests are not supported")
        host = parsed.hostname
        if not host:
            raise ClientError("request URL has no host")
        port = parsed.port or 80
        origin_target = parsed.path or "/"
        if parsed.query:
            origin_target += "?" + parsed.query
    else:
        host_header = find_host_header(lines)
        if not host_header:
            raise ClientError("HTTP request has no Host header")
        host, port = parse_host_port(host_header, 80)
        origin_target = target or "/"

    rewritten_lines = [f"{method} {origin_target} {version}"]
    for line in lines[1:]:
        if not line:
            continue
        if line.lower().startswith("proxy-connection:"):
            continue
        rewritten_lines.append(line)
    rewritten = ("\r\n".join(rewritten_lines) + "\r\n\r\n").encode("iso-8859-1")
    return HttpProxyRequest(host, port, "http", False, rewritten)


async def open_tunnel(
    config: ClientConfig,
    host: str,
    port: int,
    proxy_protocol: str,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, CryptoBox]:
    reader, writer = await asyncio.open_connection(config.server_host, config.server_port)
    box = CryptoBox(config.token, config.cipher)
    try:
        await write_handshake(writer, config.token, config.cipher)
        await write_json_frame(
            writer,
            box,
            {
                "type": "connect",
                "host": host,
                "port": int(port),
                "proxy_protocol": proxy_protocol,
            },
        )
        response = await read_json_frame(reader, box)
        if not response.get("ok"):
            raise ClientError(str(response.get("error", "server failed to connect target")))
        return reader, writer, box
    except Exception:
        await close_writer(writer)
        raise


async def stream_to_frames(
    source: asyncio.StreamReader,
    remote: asyncio.StreamWriter,
    box: CryptoBox,
) -> None:
    while True:
        data = await source.read(BUFFER_SIZE)
        if not data:
            await write_encrypted_frame(remote, box, b"")
            return
        await write_encrypted_frame(remote, box, data)


async def frames_to_stream(
    remote: asyncio.StreamReader,
    target: asyncio.StreamWriter,
    box: CryptoBox,
) -> None:
    while True:
        data = await read_encrypted_frame(remote, box)
        if not data:
            await write_stream_eof(target)
            return
        target.write(data)
        await target.drain()


async def relay_bidirectional(
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
    remote_reader: asyncio.StreamReader,
    remote_writer: asyncio.StreamWriter,
    box: CryptoBox,
) -> None:
    tasks = [
        asyncio.create_task(stream_to_frames(local_reader, remote_writer, box)),
        asyncio.create_task(frames_to_stream(remote_reader, local_writer, box)),
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
            raise errors[0]
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await close_writer(remote_writer)
        await close_writer(local_writer)


async def handle_http(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    first_byte: bytes,
    config: ClientConfig,
) -> None:
    remote_writer: asyncio.StreamWriter | None = None
    try:
        header = first_byte + await reader.readuntil(b"\r\n\r\n")
        request = parse_http_request(header)
        remote_reader, remote_writer, box = await open_tunnel(
            config, request.host, request.port, request.protocol
        )
        if request.is_connect:
            writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: Lic-proxy\r\n\r\n")
            await writer.drain()
        else:
            await write_encrypted_frame(remote_writer, box, request.initial_data)
        await relay_bidirectional(reader, writer, remote_reader, remote_writer, box)
    except (ClientError, ProtocolError, OSError, asyncio.IncompleteReadError) as exc:
        if not writer.is_closing():
            body = f"proxy error: {exc}\n".encode("utf-8", "replace")
            writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                + body
            )
            try:
                await writer.drain()
            except ConnectionError:
                pass
        await close_writer(remote_writer)
        await close_writer(writer)


def socks_reply(status: int) -> bytes:
    return b"\x05" + bytes([status]) + b"\x00\x01" + b"\x00\x00\x00\x00\x00\x00"


async def read_socks_address(reader: asyncio.StreamReader, atyp: int) -> str:
    if atyp == 1:
        return str(ipaddress.IPv4Address(await reader.readexactly(4)))
    if atyp == 3:
        size = (await reader.readexactly(1))[0]
        return (await reader.readexactly(size)).decode("idna")
    if atyp == 4:
        return str(ipaddress.IPv6Address(await reader.readexactly(16)))
    raise ClientError("unsupported SOCKS5 address type")


async def handle_socks5(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    first_byte: bytes,
    config: ClientConfig,
) -> None:
    remote_writer: asyncio.StreamWriter | None = None
    try:
        if first_byte != b"\x05":
            raise ClientError("bad SOCKS version")
        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)
        if 0 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(b"\x05\x00")
        await writer.drain()

        version, command, _reserved, atyp = await reader.readexactly(4)
        if version != 5:
            raise ClientError("bad SOCKS request version")
        if command != 1:
            writer.write(socks_reply(7))
            await writer.drain()
            return
        host = await read_socks_address(reader, atyp)
        port = int.from_bytes(await reader.readexactly(2), "big")
        remote_reader, remote_writer, box = await open_tunnel(config, host, port, "socks5")
        writer.write(socks_reply(0))
        await writer.drain()
        await relay_bidirectional(reader, writer, remote_reader, remote_writer, box)
    except (ClientError, ProtocolError, OSError, asyncio.IncompleteReadError):
        if not writer.is_closing():
            writer.write(socks_reply(1))
            try:
                await writer.drain()
            except ConnectionError:
                pass
        await close_writer(remote_writer)
        await close_writer(writer)


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: ClientConfig,
) -> None:
    peer = writer.get_extra_info("peername")
    try:
        first_byte = await reader.readexactly(1)
        if first_byte == b"\x05":
            await handle_socks5(reader, writer, first_byte, config)
        else:
            await handle_http(reader, writer, first_byte, config)
    except asyncio.IncompleteReadError:
        await close_writer(writer)
    except Exception as exc:
        print(f"client {peer} failed: {exc}")
        await close_writer(writer)


async def run(config: ClientConfig) -> None:
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, config),
        config.listen_host,
        config.listen_port,
    )
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"local proxy listening on {sockets}")
    print(f"tunnel server {config.server_host}:{config.server_port}, cipher={config.cipher}")
    async with server:
        await server.serve_forever()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lic-proxy local HTTP/HTTPS/SOCKS5 client")
    parser.add_argument("--listen", default="127.0.0.1:1080", help="local proxy listen address")
    parser.add_argument("--server", default="127.0.0.1:9000", help="remote tunnel server address")
    parser.add_argument("--token", required=True, help="shared secret token")
    parser.add_argument("--cipher", choices=["aesgcm", "chacha20"], default="aesgcm")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    listen_host, listen_port = parse_endpoint(args.listen, "127.0.0.1")
    server_host, server_port = parse_endpoint(args.server, "127.0.0.1")
    config = ClientConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        server_host=server_host,
        server_port=server_port,
        token=args.token,
        cipher=args.cipher,
    )
    asyncio.run(run(config))


if __name__ == "__main__":
    main()
