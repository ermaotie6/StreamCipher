"""CLI integration tests, using only Python's standard library.

Explicit failures keep every check active under -O and PYTHONOPTIMIZE.
"""
import pathlib
import subprocess
import sys
import tempfile

exe = str(pathlib.Path(sys.argv[1]).resolve())
credentials = ['--key', '00' * 16, '--nonce', '00' * 12]


def run(*args, ok=True):
    result = subprocess.run([exe, *map(str, args)], capture_output=True, timeout=30)
    if not ((result.returncode == 0) == ok):
        raise AssertionError((args, result.returncode, result.stdout, result.stderr))
    return result.stdout.decode('utf-8', errors='replace')


with tempfile.TemporaryDirectory(prefix='scipher-cli-') as directory:
    root = pathlib.Path(directory)
    source, encrypted, recovered = [root / name for name in ('input.bin', 'encrypted.bin', 'recovered.bin')]
    run('--help')
    run('--help', '--bogus', ok=False)
    run('unknown', ok=False)
    for mode in ('ctr', 'gcm'):
        for size in (0, 1, 15, 16, 17, 1001):
            plain = bytes((i * 7) % 256 for i in range(size))
            source.write_bytes(plain)
            run('encrypt', source, encrypted, '--mode', mode, *credentials)
            run('decrypt', encrypted, recovered, '--mode', mode, *credentials)
            if not (recovered.read_bytes() == plain):
                raise AssertionError('recovered.read_bytes() == plain')
        # Invalid options and missing credentials must not replace the destination.
        before = encrypted.read_bytes()
        for options in ([], ['--key'], credentials + ['--nonce'], credentials + ['--bogus'],
                        credentials + ['--mode', 'bad'], credentials + ['--key', '11' * 16],
                        credentials + ['--chunk-size', '0'], credentials + ['--size', '1K'],
                        ['--key', 'gg' * 16, '--nonce', '00' * 12]):
            run('encrypt', source, encrypted, *options, ok=False)
            if not (encrypted.read_bytes() == before):
                raise AssertionError('encrypted.read_bytes() == before')
        run('encrypt', root / 'missing', encrypted, *credentials, ok=False)
        if not (encrypted.read_bytes() == before):
            raise AssertionError('encrypted.read_bytes() == before')
        run('encrypt', source, source, *credentials, ok=False)
        if not (source.read_bytes() == plain):
            raise AssertionError('source.read_bytes() == plain')
    bad = bytearray(encrypted.read_bytes()); bad[-1] ^= 1
    encrypted.write_bytes(bad)
    recovered.write_bytes(b'keep me')
    run('decrypt', encrypted, recovered, '--mode', 'gcm', *credentials, ok=False)
    if not (recovered.read_bytes() == b'keep me'):
        raise AssertionError("recovered.read_bytes() == b'keep me'")
    run('encrypt', source, encrypted, '--mode', 'gcm', '--chunk-size', '17', '--no-progress', *credentials)
    run('decrypt', encrypted, recovered, '--mode', 'gcm', '--chunk-size', '1K', '--no-progress', *credentials)
    if not (recovered.read_bytes() == source.read_bytes()):
        raise AssertionError('recovered.read_bytes() == source.read_bytes()')
    unicode_source = root / '中文 input 🗂.bin'
    unicode_encrypted = root / '密文.bin'
    unicode_recovered = root / '恢复.bin'
    unicode_source.write_bytes(b'Unicode path round-trip')
    run('encrypt', unicode_source, unicode_encrypted, '--mode', 'gcm', *credentials)
    run('decrypt', unicode_encrypted, unicode_recovered, '--mode', 'gcm', *credentials)
    if not (unicode_recovered.read_bytes() == unicode_source.read_bytes()):
        raise AssertionError('unicode_recovered.read_bytes() == unicode_source.read_bytes()')
    output = run('benchmark', '--size', '1K', '--iterations', '2')
    if not ('1024 bytes x 2 iterations' in output):
        raise AssertionError("'1024 bytes x 2 iterations' in output")
    if not ('inf' not in output.lower() and 'nan' not in output.lower()):
        raise AssertionError("'inf' not in output.lower() and 'nan' not in output.lower()")
    for options in (['--size', '0'], ['--iterations', '-1'], ['--size', '1Z'], ['--size'],
                    ['--size', '18446744073709551615G'], ['--iterations', '1x'], ['--bogus'],
                    ['--size', '1K', '--size', '2K'], ['--key', '00' * 16]):
        run('benchmark', *options, ok=False)
    if not (not list(root.glob('.scipher-*'))):
        raise AssertionError("not list(root.glob('.scipher-*'))")
print('CLI integration checks passed')
