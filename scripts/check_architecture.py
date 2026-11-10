"""Dependency direction and public surface checks; requires only Python stdlib."""
import pathlib
import re

root = pathlib.Path(__file__).resolve().parents[1]
errors = []
allowed = {
    "core": {"core"},
    "simd": {"simd"},
    "memory": {"memory"},
    "stream": {"core", "stream"},
}
for header in sorted((root / "include/streamcipher").rglob("*.hpp")):
    relative = header.relative_to(root / "include/streamcipher")
    text = header.read_text(encoding="utf-8")
    # The umbrella may include all public layers, but must obey common rules.
    layer = relative.parts[0] if len(relative.parts) > 1 else None
    for included in re.findall(r'#include\s*[<"]([^>"]+)', text):
        if layer and included.startswith("streamcipher/") and included.split("/")[1] not in allowed[layer]:
            errors.append(f"{relative}: disallowed public dependency {included}")
        if ".." in included or included in {"windows.h", "immintrin.h", "wmmintrin.h"}:
            errors.append(f"{relative}: implementation detail escaped into public header")
    if re.search(r"#\s*(?:if|ifdef).*STREAMCIPHER_(SIMD|AESNI)", text):
        errors.append(f"{relative}: build flags alter public declarations")
for source in (root / "src").rglob("*.cpp"):
    text = source.read_text(encoding="utf-8")
    if "apps/" in text or "catch2/" in text or "benchmark/benchmark" in text:
        errors.append(f"{source.relative_to(root)}: library depends on application/test tooling")
    if source.parent.name == "core" and "streamcipher/stream/" in text:
        errors.append(f"{source.relative_to(root)}: core depends on I/O orchestration")
if errors:
    raise SystemExit("\n".join(errors))
print("Architecture dependency checks passed")
