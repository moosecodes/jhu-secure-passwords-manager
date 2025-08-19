'''Crypto.py'''
import os, json, base64
from dataclasses import asdict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .kdf import derive_key, Argon2Params, DEFAULT_PARAMS

NONCE_LEN = 12            # AES-GCM standard
SALT_LEN  = 16            # per-vault salt
KEY_LEN   = 32            # 256-bit AES key

def _b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def _b64d(s: str) -> bytes: return base64.b64decode(s.encode("ascii"))

def encrypt_vault(plaintext_dict: dict, password: str, params: Argon2Params = DEFAULT_PARAMS) -> dict:
    salt  = os.urandom(SALT_LEN)
    key   = derive_key(password, salt, params)
    nonce = os.urandom(NONCE_LEN)
    aead  = AESGCM(key)
    pt    = json.dumps(plaintext_dict, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ct    = aead.encrypt(nonce, pt, None)  # AAD=None; keep simple
    return {
        "version": 1,
        "kdf": "argon2id",
        "kdf_params": {"t": params.time_cost, "m": params.memory_cost, "p": params.parallelism, "hash_len": params.hash_len, "salt": _b64e(salt)},
        "cipher": "aes-gcm",
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ct),
    }

def decrypt_vault(vault_obj: dict, password: str) -> dict:
    if vault_obj.get("cipher") != "aes-gcm" or vault_obj.get("kdf") != "argon2id":
        raise ValueError("Unsupported vault format")
    kp = vault_obj["kdf_params"]
    params = Argon2Params(time_cost=kp["t"], memory_cost=kp["m"], parallelism=kp["p"], hash_len=kp["hash_len"])
    salt  = _b64d(kp["salt"])
    key   = derive_key(password, salt, params)
    nonce = _b64d(vault_obj["nonce"])
    ct    = _b64d(vault_obj["ciphertext"])
    pt    = AESGCM(key).decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))

# if __name__ == "__main__":
#     from pathlib import Path
#     from crypto import encrypt_vault, decrypt_vault
#     master = "TestOnly!2025"
#     data = {"entries":[{"site":"github.com","user":"moose","password":"dummy"}]}
#     vault = encrypt_vault(data, master)
#     dec = decrypt_vault(vault, master)
#     assert dec == data
#     print("AES-GCM OK; round-trip passed.")
