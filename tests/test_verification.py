"""Fault injection for verification scripts, independent of the CLI and cryptography.

The stub oracle only exercises failure reporting; real interoperability is tested
separately by check_interop.py against the installed cryptography package.
"""
import os
import pathlib
import runpy
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


def probe(script, fault):
    def broken_cli(command, **kwargs):
        code = 0
        if fault == "exit":
            code = 1
        elif command[1] == "unknown" or (command[1] == "--help" and len(command) > 2):
            code = 1
        if len(command) > 3 and command[1] in ("encrypt", "decrypt"):
            pathlib.Path(command[3]).write_bytes(b"broken output")
        return subprocess.CompletedProcess(command, code, stdout=b"broken output", stderr=b"")

    # No optional dependency is needed to test detection of a mismatching result.
    ciphers = types.ModuleType("cryptography.hazmat.primitives.ciphers")
    ciphers.Cipher = lambda *_: types.SimpleNamespace(encryptor=lambda: types.SimpleNamespace(
        update=lambda _: b"reference", finalize=lambda: b""))
    ciphers.algorithms = types.SimpleNamespace(AES=lambda key: key)
    ciphers.modes = types.SimpleNamespace(CTR=lambda nonce: nonce)
    aead = types.ModuleType("cryptography.hazmat.primitives.ciphers.aead")
    aead.AESGCM = lambda _: types.SimpleNamespace(
        encrypt=lambda *_: b"reference tag", decrypt=lambda *_: b"reference plaintext")
    sys.argv = [str(script), "unused-scipher"]
    with patch("subprocess.run", side_effect=broken_cli), patch.dict(sys.modules, {
        ciphers.__name__: ciphers, aead.__name__: aead,
    }):
        runpy.run_path(str(script), run_name="__main__")


class VerificationTests(unittest.TestCase):
    def test_architecture_checker_inspects_umbrella_header(self):
        checker = pathlib.Path(__file__).resolve().parents[1] / "scripts/check_architecture.py"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "scripts").mkdir()
            headers = root / "include/streamcipher"
            headers.mkdir(parents=True)
            shutil.copy2(checker, root / "scripts/check_architecture.py")
            umbrella = headers / "streamcipher.hpp"
            for content, error in (
                ('#include "streamcipher/core/cipher.hpp"\n', None),
                ('#include <windows.h>\n', b"implementation detail escaped"),
                ('#ifdef STREAMCIPHER_AESNI\n#endif\n', b"build flags alter public declarations"),
            ):
                with self.subTest(content=content):
                    umbrella.write_text(content, encoding="utf-8")
                    result = subprocess.run([sys.executable, str(root / "scripts/check_architecture.py")],
                                            capture_output=True, timeout=15)
                    if error is None:
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn(error, result.stderr)

    def test_bad_results_cannot_report_success(self):
        for script in ("test_cli.py", "check_interop.py"):
            for fault in ("exit", "data"):
                for mode in ("normal", "-O", "environment"):
                    with self.subTest(script=script, fault=fault, mode=mode):
                        env = os.environ.copy()
                        env.pop("PYTHONOPTIMIZE", None)
                        if mode == "environment":
                            env["PYTHONOPTIMIZE"] = "1"
                        args = [sys.executable]
                        if mode == "-O":
                            args.append("-O")
                        args += [str(pathlib.Path(__file__).resolve()), "--probe", script, fault]
                        result = subprocess.run(args, capture_output=True, env=env, timeout=15)
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertIn(b"AssertionError", result.stderr, result.stderr)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--probe":
        probe(pathlib.Path(__file__).resolve().with_name(sys.argv[2]), sys.argv[3])
    else:
        unittest.main()
