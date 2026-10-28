"""E4 — empirical decryption-failure rate (DFR) of the toy parameter candidates.

A trial = KeyGen_internal (new key every KEY_EVERY trials), Encaps_internal,
Decaps_internal; it fails when the decapsulated key differs from the
encapsulated one (K-PKE decryption error -> implicit rejection).

DETERMINISTIC SEEDS (experiment only): d, z and m come from random.Random(seed),
never from os.urandom, so that reruns give identical failure counts (NFR-004).
This is NOT how keys are generated anywhere else in the project.

Output: experiments/results/e4/<UTC timestamp>/{config.yaml,raw.jsonl,env.json,summary.csv,fig.png}
Usage:  python tools/run.py exp e4 [trials_per_candidate]
"""

from __future__ import annotations

import csv
import json
import math
import platform
import random
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import yaml

from canary_qday.kem import kem
from canary_qday.kem.profiles import TOY_CANDIDATES

ROOT = Path(__file__).resolve().parents[2]
SEED = 20261028
KEY_EVERY = 100
NEGATIVE_CONTROLS = {"toy-n64-k1-du4dv2", "toy-n64-k2-du4dv2"}
DFR_THRESHOLD = 1e-3  # acceptance: 95 % upper bound on DFR below this (docs/calibration.md)


def upper95(failures: int, trials: int) -> float:
    """One-sided 95 % upper bound: rule of three for 0 failures, Wilson score otherwise."""
    if trials == 0:
        return 1.0
    if failures == 0:
        return 3.0 / trials
    z = 1.6449
    p = failures / trials
    centre = p + z * z / (2 * trials)
    margin = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))
    return min(1.0, (centre + margin) / (1 + z * z / trials))


def run(trials: int) -> Path:
    """Run E4 and return the result directory."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "experiments" / "results" / "e4" / stamp
    out.mkdir(parents=True, exist_ok=True)
    config = {
        "experiment": "E4",
        "seed": SEED,
        "trials_per_candidate": trials,
        "negative_control_trials": min(trials, 200),
        "key_every": KEY_EVERY,
        "dfr_threshold_upper95": DFR_THRESHOLD,
        "candidates": {
            name: {"n": p.n, "k": p.k, "eta1": p.eta1, "eta2": p.eta2, "du": p.du, "dv": p.dv,
                   "q": p.q}
            for name, p in TOY_CANDIDATES.items()
        },
    }
    (out / "config.yaml").write_text(yaml.safe_dump(config, sort_keys=True), encoding="utf-8")
    env = {
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "started_utc": stamp,
    }
    rows = []
    with (out / "raw.jsonl").open("w", encoding="utf-8") as raw:
        for name, p in TOY_CANDIDATES.items():
            n_trials = config["negative_control_trials"] if name in NEGATIVE_CONTROLS else trials
            rng = random.Random(f"{SEED}:{name}")  # deterministic, experiment only
            failures = 0
            t0 = time.perf_counter()
            ek = dk = b""
            for i in range(n_trials):
                if i % KEY_EVERY == 0:
                    ek, dk = kem.keygen_internal(p, rng.randbytes(32), rng.randbytes(32))
                key, ct = kem.encaps_internal(p, ek, rng.randbytes(p.msg_bytes))
                fail = kem.decaps_internal(p, dk, ct) != key
                failures += fail
                raw.write(json.dumps({"candidate": name, "trial": i, "fail": fail}) + "\n")
            elapsed = time.perf_counter() - t0
            row = {
                "candidate": name, "n": p.n, "k": p.k, "du": p.du, "dv": p.dv,
                "trials": n_trials, "failures": failures,
                "dfr_measured": failures / n_trials,
                "dfr_upper95": upper95(failures, n_trials),
                "meets_threshold": upper95(failures, n_trials) < DFR_THRESHOLD,
                "negative_control": name in NEGATIVE_CONTROLS,
                "wall_s": round(elapsed, 2),
            }
            rows.append(row)
            print(f"{name:20s} trials={n_trials:6d} failures={failures:6d} "
                  f"dfr={row['dfr_measured']:.4g} upper95={row['dfr_upper95']:.3g}")
    with (out / "summary.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    env["finished_utc"] = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    (out / "env.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
    _plot(rows, out / "fig.png")
    print(f"results: {out}")
    return out


def _plot(rows: list[dict[str, object]], path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    names = [str(r["candidate"]) for r in rows]
    ub = [float(r["dfr_upper95"]) for r in rows]  # type: ignore[arg-type]
    meas = [max(float(r["dfr_measured"]), 1e-6) for r in rows]  # type: ignore[arg-type]
    fig, ax = plt.subplots(figsize=(8, 4))
    x = range(len(names))
    ax.bar([i - 0.2 for i in x], meas, width=0.4, label="measured DFR (0 shown as 1e-6)")
    ax.bar([i + 0.2 for i in x], ub, width=0.4, label="95% upper bound")
    ax.axhline(DFR_THRESHOLD, linestyle="--", color="black", linewidth=1, label="threshold")
    ax.set_yscale("log")
    ax.set_xticks(list(x), names, rotation=30, ha="right")
    ax.set_ylabel("decryption failure rate")
    ax.set_title("E4: empirical DFR of toy candidates")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


if __name__ == "__main__":
    run(int(sys.argv[1]) if len(sys.argv) > 1 else 2000)
