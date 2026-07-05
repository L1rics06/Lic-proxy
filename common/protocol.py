import asyncio
import base64
import hashlib
import hmac
import json
import os
import struct
import time
from typing import Any

from common.crypto import CryptoBox, SUPPORTED_CIPHERS, derive_key


MAGIC = b"LPX1"
VERSION = 1
MAX_HANDSHAKE_SIZE = 4096
MAX_FRAME_SIZE = 8 * 1024 * 1024
BUFFER_SIZE = 64 * 1024


class ProtocolError(ValueError):
    """Raised when a peer sends malformed tunnel data."""


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hmac_for(token: str, payload: dict[str, Any]) -> str:
    return hmac.new(derive_key(token), _canonical_json(payload), hashlib.sha256).hexdigest()


async def write_handshake(writer: asyncio.StreamWriter, token: str, cipher: str) -> None:
    cipher = cipher.lower()
    if cipher not in SUPPORTED_CIPHERS:
        raise ProtocolError(f"unsupported cipher: {cipher}")
    payload = {
        "version": VERSION,
        "cipher": cipher,
        "timestamp": int(time.time()),
        "nonce": base64.b64encode(os.urandom(16)).decode("ascii"),
    }
    packet = {"payload": payload, "auth": _hmac_for(token, payload)}
    data = _canonical_json(packet)
    if len(data) > MAX_HANDSHAKE_SIZE:
        raise ProtocolError("handshake is too large")
    writer.write(MAGIC + struct.pack("!H", len(data)) + data)
    await writer.drain()


async def read_handshake(
    reader: asyncio.StreamReader,
    token: str,
    expected_cipher: str | None = None,
    max_clock_skew: int = 600,
) -> str:
    magic = await reader.readexactly(len(MAGIC))
    if magic != MAGIC:
        raise ProtocolError("bad tunnel magic")
    size = struct.unpack("!H", await reader.readexactly(2))[0]
    if size <= 0 or size > MAX_HANDSHAKE_SIZE:
        raise ProtocolError("invalid handshake size")
    try:
        packet = json.loads((await reader.readexactly(size)).decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ProtocolError("handshake is not valid JSON") from exc

    payload = packet.get("payload")
    auth = packet.get("auth")
    if not isinstance(payload, dict) or not isinstance(auth, str):
        raise ProtocolError("handshake is missing payload or auth")
    if payload.get("version") != VERSION:
        raise ProtocolError("unsupported tunnel version")
    cipher = str(payload.get("cipher", "")).lower()
    if cipher not in SUPPORTED_CIPHERS:
        raise ProtocolError("unsupported cipher")
    if expected_cipher and cipher != expected_cipher.lower():
        raise ProtocolError("cipher does not match server configuration")
    timestamp = payload.get("timestamp")
    if not isinstance(timestamp, int) or abs(int(time.time()) - timestamp) > max_clock_skew:
        raise ProtocolError("handshake timestamp is outside the allowed window")
    expected_auth = _hmac_for(token, payload)
    if not hmac.compare_digest(auth, expected_auth):
        raise ProtocolError("bad tunnel token")
    return cipher


async def write_encrypted_frame(
    writer: asyncio.StreamWriter,
    box: CryptoBox,
    payload: bytes,
) -> None:
    packet = box.encrypt(payload)
    if len(packet) > MAX_FRAME_SIZE:
        raise ProtocolError("encrypted frame is too large")
    writer.write(struct.pack("!I", len(packet)) + packet)
    await writer.drain()


async def read_encrypted_frame(reader: asyncio.StreamReader, box: CryptoBox) -> bytes:
    size = struct.unpack("!I", await reader.readexactly(4))[0]
    if size <= 0 or size > MAX_FRAME_SIZE:
        raise ProtocolError("invalid encrypted frame size")
    return box.decrypt(await reader.readexactly(size))


async def write_json_frame(
    writer: asyncio.StreamWriter,
    box: CryptoBox,
    payload: dict[str, Any],
) -> None:
    await write_encrypted_frame(writer, box, _canonical_json(payload))


async def read_json_frame(reader: asyncio.StreamReader, box: CryptoBox) -> dict[str, Any]:
    try:
        payload = json.loads((await read_encrypted_frame(reader, box)).decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ProtocolError("JSON frame is invalid") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("JSON frame must contain an object")
    return payload


async def close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, RuntimeError):
        pass


async def write_stream_eof(writer: asyncio.StreamWriter) -> None:
    try:
        if writer.can_write_eof():
            writer.write_eof()
            await writer.drain()
    except (ConnectionError, OSError, RuntimeError):
        pass

