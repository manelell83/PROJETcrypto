"""FR-009: the policy matrix of spec 7.4, case by case."""

from __future__ import annotations

import pytest

from canary_qday.response import policy

HEAVY = {"firewall_block", "service_stop"}


@pytest.mark.parametrize("profile", ["RED", "ORANGE"])
def test_toy_profiles_trusted_token(profile: str) -> None:
    d = policy.decide(profile, token_valid=True, allowlisted=False, auto_lab=False)
    assert {"classify", "switch_profile", "rotate_secrets", "report"} <= set(d.auto)
    assert set(d.approval) == HEAVY
    assert (profile == "ORANGE") == ("notify_analyst" in d.auto)


def test_green_is_human_only() -> None:
    d = policy.decide("GREEN", token_valid=True, allowlisted=False, auto_lab=True)
    assert set(d.auto) == {"create_incident", "report"}
    assert {"switch_profile", "rotate_secrets", *HEAVY} <= set(d.approval)


@pytest.mark.parametrize(("valid", "allow"), [(False, False), (True, True), (False, True)])
def test_untrusted_token_means_no_automatic_containment(valid: bool, allow: bool) -> None:
    d = policy.decide("RED", token_valid=valid, allowlisted=allow, auto_lab=True)
    assert set(d.auto) == {"create_incident", "report"}


def test_auto_lab_makes_heavy_actions_automatic_for_toy_only() -> None:
    d = policy.decide("RED", token_valid=True, allowlisted=False, auto_lab=True)
    assert set(d.auto) >= HEAVY
    assert not set(d.approval)


def test_unknown_profile_rejected() -> None:
    with pytest.raises(ValueError):
        policy.decide("BLUE", token_valid=True, allowlisted=False, auto_lab=False)


@pytest.mark.parametrize(
    ("broken", "expected"),
    [("RED", ["RED"]), ("ORANGE", ["RED", "ORANGE"]), ("GREEN", ["RED", "ORANGE", "GREEN"])],
)
def test_profiles_to_disable_includes_weaker(broken: str, expected: list[str]) -> None:
    assert policy.profiles_to_disable(broken) == expected
