'''Key Derivation Function (KDF)'''
from dataclasses import dataclass
from argon2.low_level import Type, hash_secret_raw

@dataclass(frozen=True)
class Argon2Params:
    time_cost: int = 3
    memory_cost: int = 65536   # KiB (64 MB)
    parallelism: int = 2
    hash_len: int = 32         # key length in bytes

DEFAULT_PARAMS = Argon2Params()

def derive_key(password: str, salt: bytes, params: Argon2Params = DEFAULT_PARAMS) -> bytes:
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise ValueError("salt must be >=16 bytes")
    if not password:
        raise ValueError("password required")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=Type.ID,  # Argon2id
    )

# if __name__ == "__main__":
#     import os, binascii
#     salt = os.urandom(16)
#     key1 = derive_key("TestOnly!2025", salt)
#     key2 = derive_key("TestOnly!2025", salt)
#     assert key1 == key2
#     print("OK key:", binascii.hexlify(key1).decode()[:16], "salt:", binascii.hexlify(salt).decode())
