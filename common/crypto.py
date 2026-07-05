import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


SUPPORTED_CIPHERS = {"aesgcm", "chacha20"}
NONCE_SIZE = 12


class CryptoError(ValueError):
    """Raised when encryption configuration or payloads are invalid."""


def derive_key(token: str) -> bytes:
    if not token:
        raise CryptoError("token must not be empty")
    return hashlib.sha256(token.encode("utf-8")).digest()


@dataclass(frozen=True)
class CryptoBox:
    token: str
    cipher_name: str

    def __post_init__(self) -> None:
        name = self.cipher_name.lower()
        if name not in SUPPORTED_CIPHERS:
            raise CryptoError(f"unsupported cipher: {self.cipher_name}")
        object.__setattr__(self, "cipher_name", name)
        object.__setattr__(self, "_key", derive_key(self.token))
        if name == "aesgcm":
            aead = AESGCM(self._key)
        else:
            aead = ChaCha20Poly1305(self._key)
        object.__setattr__(self, "_aead", aead)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = os.urandom(NONCE_SIZE)
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, packet: bytes, aad: bytes = b"") -> bytes:
        if len(packet) < NONCE_SIZE + 16:
            raise CryptoError("encrypted packet is too short")
        nonce = packet[:NONCE_SIZE]
        ciphertext = packet[NONCE_SIZE:]
        return self._aead.decrypt(nonce, ciphertext, aad)

