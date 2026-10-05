"""Password vault using Argon2id and AES-256-GCM."""
import argparse
import base64
import binascii
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import warnings

from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF = {"name": "argon2id", "version": 19, "time_cost": 3,
       "memory_cost": 65536, "parallelism": 4, "key_bytes": 32}
MAX_FILE_BYTES = 65536


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise ValueError("Master passphrase must not be empty.")
    return hash_secret_raw(secret=passphrase.encode("utf-8"), salt=salt,
                           time_cost=3, memory_cost=65536, parallelism=4,
                           hash_len=32, type=Type.ID, version=19)


def _aad(data):
    header = {key: data[key] for key in ("version", "kdf", "hint", "salt", "nonce")}
    return json.dumps(header, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def encrypt_password(password: str, passphrase: str, hint: str = ""):
    if not password:
        raise ValueError("Password must not be empty.")
    if len(hint) > 1024:
        raise ValueError("Hint must be at most 1024 characters.")
    salt, nonce = os.urandom(16), os.urandom(12)
    data = {"version": 1, "kdf": dict(KDF), "hint": hint,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii")}
    encrypted = AESGCM(derive_key(passphrase, salt)).encrypt(
        nonce, password.encode("utf-8"), _aad(data))
    data["ciphertext"] = base64.b64encode(encrypted).decode("ascii")
    if len(json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")) + 1 > MAX_FILE_BYTES:
        raise ValueError("Password is too large for this vault format.")
    return data


def _validate(data):
    if not isinstance(data, dict):
        raise ValueError("Vault must be a JSON object.")
    legacy = set(data) == {"salt", "nonce", "ciphertext"}
    if not legacy:
        if set(data) != {"version", "kdf", "hint", "salt", "nonce", "ciphertext"}:
            raise ValueError("Unrecognized vault fields.")
        if type(data["version"]) is not int or data["version"] != 1 or data["kdf"] != KDF:
            raise ValueError("Unsupported vault version or KDF settings.")
        if not isinstance(data["hint"], str) or len(data["hint"]) > 1024:
            raise ValueError("Invalid hint.")
    try:
        values = []
        for field in ("salt", "nonce", "ciphertext"):
            if not isinstance(data[field], str) or len(data[field]) > MAX_FILE_BYTES:
                raise ValueError("Invalid encoded field.")
            values.append(base64.b64decode(data[field], validate=True))
        salt, nonce, ciphertext = values
    except (binascii.Error, UnicodeError) as exc:
        raise ValueError("Invalid Base64 in vault.") from exc
    if len(salt) != 16 or len(nonce) != 12 or len(ciphertext) < 16:
        raise ValueError("Invalid salt, nonce, or ciphertext length.")
    return salt, nonce, ciphertext, legacy


def decrypt_password(data, passphrase: str):
    salt, nonce, ciphertext, legacy = _validate(data)
    return AESGCM(derive_key(passphrase, salt)).decrypt(
        nonce, ciphertext, None if legacy else _aad(data)).decode("utf-8")


def _read_secret(prompt):
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt)


def _read_vault(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("Vault file exceeds 64 KiB.")
    data = json.loads(raw.decode("utf-8"))
    _validate(data)
    return data


def _clipboard_command(script, password):
    # Pass secrets over stdin, never in command arguments.
    encoded = base64.b64encode(password.encode("utf-8")).decode("ascii")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "$ErrorActionPreference='Stop'; " + script],
        input=encoded, text=True, capture_output=True, timeout=10,
        creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise RuntimeError("Clipboard operation failed.")


def _copy_temporarily(password):
    if sys.platform != "win32":
        raise RuntimeError("Clipboard mode requires Windows. Use --show to display explicitly.")
    decode = "$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())); "
    _clipboard_command(decode + "Set-Clipboard -Value $s", password)
    print("Password copied. Clipboard clears in 30 seconds; Ctrl+C clears it now.")
    try:
        time.sleep(30)
    finally:
        _clipboard_command(decode + "if ((Get-Clipboard -Raw) -ceq $s) { Set-Clipboard -Value '' }", password)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    encrypt = commands.add_parser("encrypt", help="Create an encrypted vault")
    encrypt.add_argument("file", type=Path)
    encrypt.add_argument("--hint", default="", help="Public reminder; do not include secrets")
    decrypt = commands.add_parser("decrypt", help="Copy decrypted password for 30 seconds")
    decrypt.add_argument("file", type=Path)
    decrypt.add_argument("--show", action="store_true", help="Print plaintext (stays in terminal)")
    args = parser.parse_args(argv)
    try:
        if args.command == "encrypt":
            if args.file.exists():
                raise ValueError("Destination exists. Choose a new filename.")
            password = _read_secret("Password to encrypt: ")
            passphrase = _read_secret("Master passphrase: ")
            if passphrase != _read_secret("Confirm master passphrase: "):
                raise ValueError("Master passphrases do not match.")
            data = encrypt_password(password, passphrase, args.hint)
            serialized = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
            fd = os.open(args.file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(serialized)
            print(f"Encrypted vault saved: {args.file}")
        else:
            data = _read_vault(args.file)
            if data.get("hint"):
                print("Public hint (verified after decrypt): " + json.dumps(data["hint"], ensure_ascii=False))
            password = decrypt_password(data, _read_secret("Master passphrase: "))
            if args.show:
                print(password)
            else:
                _copy_temporarily(password)
    except InvalidTag:
        print("Cannot decrypt: wrong passphrase or altered vault.", file=sys.stderr)
        return 1
    except (ValueError, OSError, RuntimeError, EOFError, getpass.GetPassWarning,
            subprocess.TimeoutExpired) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
