"""Optional independent CLI cross-check (requires Python cryptography).
Usage: python tests/check_interop.py path/to/scipher
Explicit failures keep every check active under -O and PYTHONOPTIMIZE.
"""
import pathlib
import random
import subprocess
import sys
import tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

exe = str(pathlib.Path(sys.argv[1]).resolve())
rng = random.Random(20260919)
checks = 0
with tempfile.TemporaryDirectory(prefix="scipher-interop-") as directory:
    root = pathlib.Path(directory)
    source, encrypted, recovered = [root / x for x in ("plain", "encrypted", "recovered")]
    lengths = [0, 1, 2, 15, 16, 17, 31, 32, 33, 127, 128, 129, 255, 256, 257,
               1048575, 1048576, 1048577] + [rng.randrange(0, 4097) for _ in range(82)]
    for mode in ("ctr", "gcm"):
        for size in lengths:
            key, nonce, plain = rng.randbytes(16), rng.randbytes(12), rng.randbytes(size)
            source.write_bytes(plain)
            args = ["--mode", mode, "--key", key.hex(), "--nonce", nonce.hex()]
            result = subprocess.run([exe, "encrypt", str(source), str(encrypted), *args], capture_output=True, timeout=60)
            if not (result.returncode == 0):
                raise AssertionError(result.stderr)
            actual = encrypted.read_bytes()
            if mode == "gcm":
                oracle = AESGCM(key)
                expected = oracle.encrypt(nonce, plain, None)
                if not (oracle.decrypt(nonce, actual, None) == plain):
                    raise AssertionError('oracle.decrypt(nonce, actual, None) == plain')
            else:
                encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce + bytes(4))).encryptor()
                expected = encryptor.update(plain) + encryptor.finalize()
            if not (actual == expected):
                raise AssertionError((mode, size, "ciphertext mismatch"))
            encrypted.write_bytes(expected)
            result = subprocess.run([exe, "decrypt", str(encrypted), str(recovered), *args], capture_output=True, timeout=60)
            if not (result.returncode == 0):
                raise AssertionError(result.stderr)
            if not (recovered.read_bytes() == plain):
                raise AssertionError((mode, size, "decryption mismatch"))
            checks += 1
        print(f"{mode.upper()}: {len(lengths)} independent cases passed", flush=True)
print(f"{checks} independent interoperability cases passed")
