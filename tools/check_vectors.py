"""Check the implementation against the official vectors in vectors/ and print counts.

Usage: python tools/check_vectors.py
Exit code 0 only if every vector matches.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from canary_qday.hybrid import xwing  # noqa: E402
from canary_qday.kem import kem  # noqa: E402
from canary_qday.kem.params import STANDARD  # noqa: E402
from tests.kat.xwing_vectors import load_xwing_vectors  # noqa: E402


def _load(name: str) -> dict[str, object]:
    path = ROOT / "vectors" / "acvp" / name / "internalProjection.json"
    return dict(json.loads(path.read_text(encoding="utf-8")))


def main() -> int:
    """Run all checks."""
    results: dict[str, list[int]] = {}

    def tally(key: str, ok: bool) -> None:
        results.setdefault(key, [0, 0])[0 if ok else 1] += 1

    for g in _load("ML-KEM-keyGen-FIPS203")["testGroups"]:  # type: ignore[attr-defined]
        p = STANDARD[g["parameterSet"]]
        for t in g["tests"]:
            ek, dk = kem.keygen_internal(p, bytes.fromhex(t["d"]), bytes.fromhex(t["z"]))
            tally(f"keyGen {p.name}", ek.hex().upper() == t["ek"] and dk.hex().upper() == t["dk"])
    for g in _load("ML-KEM-encapDecap-FIPS203")["testGroups"]:  # type: ignore[attr-defined]
        p, fn = STANDARD[g["parameterSet"]], g["function"]
        for t in g["tests"]:
            if fn == "encapsulation":
                k, c = kem.encaps_internal(p, bytes.fromhex(t["ek"]), bytes.fromhex(t["m"]))
                ok = k.hex().upper() == t["k"] and c.hex().upper() == t["c"]
            elif fn == "decapsulation":
                k = kem.decaps_internal(p, bytes.fromhex(t["dk"]), bytes.fromhex(t["c"]))
                ok = k.hex().upper() == t["k"]
            else:
                check = kem.check_ek if fn == "encapsulationKeyCheck" else kem.check_dk
                arg = t["ek"] if fn == "encapsulationKeyCheck" else t["dk"]
                try:
                    check(p, bytes.fromhex(arg))
                    passed = True
                except kem.KemInputError:
                    passed = False
                ok = passed == t["testPassed"]
            tally(f"{fn} {p.name}", ok)
    for v in load_xwing_vectors():
        sk, pk = xwing.generate_key_pair_derand(v["sk"])
        ss, ct = xwing.encapsulate_derand(pk, v["eseed"])
        tally("X-Wing draft-11", pk == v["pk"] and ct == v["ct"] and ss == v["ss"]
              and xwing.decapsulate(ct, sk) == v["ss"])
    failed = 0
    for key in sorted(results):
        ok, bad = results[key]
        failed += bad
        print(f"{key:45s} {ok:3d} pass  {bad:3d} fail")
    total = sum(a + b for a, b in results.values())
    print(f"TOTAL {total - failed}/{total} vectors match")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
