import base64
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import Encrypt as vault


class VaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "test-only-password-ภาษาไทย🔒"
        cls.passphrase = "test-only random words ไม่ใช่ความลับ"
        cls.data = vault.encrypt_password(cls.password, cls.passphrase, "Planet Project")

    def test_unicode_round_trip(self):
        self.assertEqual(vault.decrypt_password(self.data, self.passphrase), self.password)

    def test_wrong_passphrase(self):
        with self.assertRaises(InvalidTag):
            vault.decrypt_password(self.data, "wrong test passphrase")

    def test_authenticated_fields(self):
        for field in ("salt", "nonce", "ciphertext", "hint"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.data)
                if field == "hint":
                    changed[field] = "Changed hint"
                else:
                    raw = bytearray(base64.b64decode(changed[field]))
                    raw[0] ^= 1
                    changed[field] = base64.b64encode(raw).decode("ascii")
                with self.assertRaises(InvalidTag):
                    vault.decrypt_password(changed, self.passphrase)

    def test_random_salt_and_nonce(self):
        other = vault.encrypt_password(self.password, self.passphrase)
        for field in ("salt", "nonce", "ciphertext"):
            self.assertNotEqual(self.data[field], other[field])

    def test_rejects_malformed_before_kdf(self):
        cases = [[], {}, {**self.data, "salt": "***"},
                 {**self.data, "nonce": "AA=="}, {**self.data, "version": 2},
                 {**self.data, "kdf": {**vault.KDF, "memory_cost": 999999999}}]
        for data in cases:
            with self.subTest(data=data), patch.object(vault, "derive_key") as derive:
                with self.assertRaises(ValueError):
                    vault.decrypt_password(data, self.passphrase)
                derive.assert_not_called()

    def test_legacy_format(self):
        salt, nonce = b"0" * 16, b"1" * 12
        encrypted = AESGCM(vault.derive_key(self.passphrase, salt)).encrypt(
            nonce, self.password.encode(), None)
        legacy = dict(zip(("salt", "nonce", "ciphertext"),
                          (base64.b64encode(x).decode() for x in (salt, nonce, encrypted))))
        self.assertEqual(vault.decrypt_password(legacy, self.passphrase), self.password)

    def test_empty_secrets_rejected(self):
        for password, passphrase in (("", "test"), ("test", "")):
            with self.assertRaises(ValueError):
                vault.encrypt_password(password, passphrase)

    def test_cli_save_copy_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.json"
            output = io.StringIO()
            with patch.object(vault, "_read_secret", side_effect=[self.password, self.passphrase, self.passphrase]), contextlib.redirect_stdout(output):
                self.assertEqual(vault.main(["encrypt", str(path), "--hint", "Planet Project"]), 0)
            self.assertNotIn(self.password, path.read_text(encoding="utf-8"))
            self.assertNotIn(self.passphrase, path.read_text(encoding="utf-8"))
            before = path.read_bytes()
            with patch.object(vault, "_read_secret", return_value=self.passphrase), patch.object(vault, "_copy_temporarily") as clipboard, contextlib.redirect_stdout(output):
                self.assertEqual(vault.main(["decrypt", str(path)]), 0)
                clipboard.assert_called_once_with(self.password)
            self.assertNotIn(self.password, output.getvalue())
            with patch.object(vault, "_read_secret") as prompt, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(vault.main(["encrypt", str(path)]), 1)
                prompt.assert_not_called()
            self.assertEqual(path.read_bytes(), before)

    def test_cli_confirmation_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.json"
            with patch.object(vault, "_read_secret", side_effect=["test", "one", "two"]), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(vault.main(["encrypt", str(path)]), 1)
            self.assertFalse(path.exists())

    def test_oversized_file_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.json"
            path.write_bytes(b"x" * (vault.MAX_FILE_BYTES + 1))
            with self.assertRaises(ValueError):
                vault._read_vault(path)

    def test_clipboard_cleanup_on_interrupt(self):
        with patch.object(vault.sys, "platform", "win32"), patch.object(vault, "_clipboard_command") as command, patch.object(vault.time, "sleep", side_effect=KeyboardInterrupt), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                vault._copy_temporarily(self.password)
            self.assertEqual(command.call_count, 2)
            self.assertIn("-ceq", command.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
