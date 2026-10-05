"""Compatibility entry point: python Decrypt.py vault.json."""
import sys
from Encrypt import decrypt_password, main


if __name__ == "__main__":
    raise SystemExit(main(["decrypt", *sys.argv[1:]]))
