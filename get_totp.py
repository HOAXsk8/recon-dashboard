#!/usr/bin/env python3
"""
Helper utility to generate the current TOTP token for logging into RDash.
Works using standard library Python with zero external dependencies.
"""
import sys
import os
import time
import hmac
import hashlib
import struct
import base64
from pathlib import Path

def load_env():
    env_vars = {}
    env_file = Path(__file__).resolve().parent / ".env"
    if env_file.exists():
        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    env_vars[key.strip()] = val.strip().strip("'\"")
    return env_vars

def compute_totp(secret: str) -> str:
    # Normalize base32 padding
    secret = secret.strip().replace(" ", "").upper()
    padding = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(secret + padding, casefold=True)
    
    interval = int(time.time() // 30)
    msg = struct.pack(">Q", interval)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0f
    truncated_hash = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7fffffff
    code = str(truncated_hash % 1000000).zfill(6)
    return code

def main():
    env = load_env()
    secret = os.getenv("ADMIN_INITIAL_TOTP_SECRET") or env.get("ADMIN_INITIAL_TOTP_SECRET", "S5B5SRQQN3VSBAWEZLO34IQMP6HHYRXZ")
    username = "admin"
    password = os.getenv("ADMIN_INITIAL_PASSWORD") or env.get("ADMIN_INITIAL_PASSWORD", "ChangeMe123!")
    
    code = compute_totp(secret)
    remaining_seconds = 30 - int(time.time() % 30)
    
    print("\n=======================================================")
    print("  RDash - Local Admin Credentials")
    print("=======================================================")
    print(f"  Username     : {username}")
    print(f"  Password     : {password}")
    print(f"  TOTP Secret  : {secret}")
    print(f"  Current Code : {code}  ({remaining_seconds}s remaining)")
    print(f"  TOTP URI     : otpauth://totp/RDash:{username}?secret={secret}&issuer=RDash")
    print("=======================================================\n")

if __name__ == "__main__":
    main()
