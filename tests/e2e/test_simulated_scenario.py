"""FR-014 / M9: the simulated attacker scenario end to end (local processes, mock SIEM).

Starts real processes on 127.0.0.1 with ports shifted by 200 so that a running
demo lab is not disturbed. Takes about 30 s. No Docker, no cryptanalysis.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lab.scenario import simulated_attacker
from tools import lab

pytestmark = pytest.mark.e2e


def test_simulated_scenario_all_checks_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CQ_LAB", "1")
    data = (tmp_path / "lab").resolve()
    summary = simulated_attacker.run(data, lab.Ports.offset(200))
    failed = [c for c in summary.checks if not c["ok"]]
    assert not failed, failed
    assert len(summary.checks) == 21
    assert [s["step"] for s in summary.steps] == ["0", "1", "2", "3", "4a", "C", "4b", "5", "6"]
    assert (data / "scenario-summary.json").exists()
    # No synthetic credential or full trap token leaked into logs, events or reports.
    for path in [
        *(data / "logs").glob("*.log"),
        *(data / "siem").glob("*.jsonl"),
        *(data / "reports").glob("*"),
    ]:
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "FAKE-" not in text, path
        assert "/t/" not in text or "/t/<redacted>" in text, path
