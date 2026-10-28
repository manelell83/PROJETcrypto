"""Parser for the X-Wing test vectors printed in Appendix C of the draft text."""

from __future__ import annotations

import re
from pathlib import Path

DRAFT = Path(__file__).resolve().parents[2] / "vectors/xwing/draft-connolly-cfrg-xwing-kem-11.txt"


def load_xwing_vectors() -> list[dict[str, bytes]]:
    """Return the Appendix C vectors as dicts of bytes (seed, sk, pk, eseed, ct, ss)."""
    text = DRAFT.read_text(encoding="utf-8")
    start = re.search(r"^Appendix C\.\s+Test vectors", text, re.M)
    end = re.search(r"^Appendix D\.", text, re.M)
    assert start and end
    section = text[start.end() : end.start()]
    vecs: list[dict[str, str]] = []
    key = None
    for line in section.splitlines():
        if line.startswith(("Connolly, et al.", "Internet-Draft")):
            continue
        m = re.match(r"^([a-z]+)\s*([0-9a-f]*)\s*$", line)
        if m:
            key = m.group(1)
            if key == "seed":
                vecs.append({})
            vecs[-1][key] = m.group(2)
        elif key and re.match(r"^\s+[0-9a-f]+\s*$", line):
            vecs[-1][key] += line.strip()
    return [{k: bytes.fromhex(v) for k, v in vec.items()} for vec in vecs]
