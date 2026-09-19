import os
import struct
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"DRQENC01"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
ITERATIONS = 600_000
CHUNK_SIZE = 1024 * 1024


class SecureFileError(Exception):
    """Raised when secure file encryption/decryption fails."""


def _derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise SecureFileError("Password cannot be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(source_path: str, output_path: str, password: str, progress=None) -> dict:
    """Encrypt a file using AES-256-GCM with a password-derived key.

    The source file is never modified. The encrypted output contains a small
    header with the salt and nonce, followed by authenticated ciphertext.
    """
    source = Path(source_path)
    output = Path(output_path)

    if not source.is_file():
        raise SecureFileError("Select a valid file to encrypt.")
    if source.resolve() == output.resolve():
        raise SecureFileError("Encrypted output must be different from the source file.")

    password = password or ""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    total = source.stat().st_size

    # Authenticate the fixed header as additional authenticated data.
    header = MAGIC + struct.pack(">B", VERSION) + salt + nonce
    processed = 0
    with source.open("rb") as fin:
        plaintext = fin.read()
    ciphertext = aes.encrypt(nonce, plaintext, header)

    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("wb") as fout:
            fout.write(header)
            fout.write(ciphertext)
    except Exception:
        if output.exists():
            try:
                output.unlink()
            except OSError:
                pass
        raise

    if progress:
        progress(100)
    return {
        "source": str(source),
        "encrypted_file": str(output),
        "algorithm": "AES-256-GCM",
        "key_derivation": "PBKDF2-HMAC-SHA256",
        "iterations": ITERATIONS,
        "original_size": total,
        "encrypted_size": output.stat().st_size,
        "sha256_encrypted": _sha256(output),
    }


def decrypt_file(source_path: str, output_path: str, password: str, progress=None) -> dict:
    """Decrypt a DataResQ .drq encrypted file.

    Authentication is verified before the plaintext is written to disk.
    """
    source = Path(source_path)
    output = Path(output_path)

    if not source.is_file():
        raise SecureFileError("Select a valid encrypted file.")
    if source.resolve() == output.resolve():
        raise SecureFileError("Decrypted output must be different from the encrypted file.")

    raw = source.read_bytes()
    minimum = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN + 16
    if len(raw) < minimum or raw[:len(MAGIC)] != MAGIC:
        raise SecureFileError("This is not a valid DataResQ encrypted file.")

    pos = len(MAGIC)
    version = raw[pos]
    pos += 1
    if version != VERSION:
        raise SecureFileError(f"Unsupported encrypted-file version: {version}.")

    salt = raw[pos:pos + SALT_LEN]
    pos += SALT_LEN
    nonce = raw[pos:pos + NONCE_LEN]
    pos += NONCE_LEN
    header = raw[:pos]
    ciphertext = raw[pos:]

    try:
        key = _derive_key(password or "", salt)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except Exception as exc:
        raise SecureFileError("Decryption failed: wrong password or corrupted/tampered file.") from exc

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(plaintext)

    if progress:
        progress(100)
    return {
        "encrypted_file": str(source),
        "decrypted_file": str(output),
        "algorithm": "AES-256-GCM",
        "decrypted_size": len(plaintext),
        "sha256_decrypted": _sha256(output),
    }


def _sha256(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()
