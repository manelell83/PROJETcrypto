# Decisions and deviations

The project owner delegated the OPEN items of the spec (§2) on 2026-10-28 ("decide on data, document, present for final review"). Each entry gives the decision, the evidence, and its status.

## OPEN 1 — SIEM

- **Decision:** every event goes through the `SiemSink` interface (`siem/base.py`). Two sinks are implemented: a file sink and a Splunk HEC sink (`siem/splunk_hec.py`, buffering events on disk when the SIEM is down). CI and the demo use a **mock SIEM** (`siem/mock_hec.py`), which offers an HEC-compatible endpoint, one correlation rule and a signed webhook.
- **Status:** the mock path is tested end to end by the scenario. The Splunk HEC sink and the `siem/splunk/*` configuration are **not tested against a real Splunk instance**.

## OPEN 2 — webhook authentication

- **Evidence:** the Splunk documentation for the webhook alert action describes a JSON POST payload (search ID, results link, owner, app, first result row). The only header setting documented in `alert_actions.conf` is `param.user_agent`. We found no documented way to add a signature header. Sources: [Use a webhook alert action (9.4)](https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/9.4/configure-alert-actions/use-a-webhook-alert-action), [alert_actions.conf (9.4)](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/9.4/configuration-file-reference/9.4.7-configuration-file-reference/alert_actions.conf).
- **Decision:**
  - `HmacHeader` (HMAC-SHA256 over timestamp and body, ±120 s window, signature replay cache) for the mock SIEM, and for any sender that can set headers, such as a Splunk custom alert action.
  - `SharedSecretPath` (secret in the URL path, constant-time comparison, freshness from the alert timestamp) for the native Splunk webhook. It must be combined with network isolation and the Splunk webhook allow-list.
  - Both modes reject a duplicate `alert_id` (`E_REPLAY`).
- **Status:** `HmacHeader` is exercised by the scenario: a forged alert gets 401, a replayed alert gets 409. `SharedSecretPath` is implemented but not exercised.

## OPEN 3 — toy parameters (PROVISIONAL)

- **Current choice:** RED = `toy-n64-k1` and ORANGE = `toy-n64-k2`. Both use q = 3329, η1 = η2 = 2, du = 10, dv = 4. The ring degree n ≥ 64 keeps the K-PKE message at ≥ 64 bits, so brute-forcing the message is not a shortcut.
- **Evidence so far:** a smoke run of 200 encapsulations per candidate gave 0 decryption failures for the four du=10/dv=4 candidates. The `du4dv2` variants failed 200/200 and are kept as negative controls. This is a smoke check, not the E4 measurement.
- **Missing:**
  - the E4 DFR experiment at scale;
  - the lattice-estimator run (the SageMath image was pulled, but no estimator run was made);
  - E3 (depends on M8, see `docs/m8-status.md`).
- **The choice is therefore not calibrated** in the sense of spec §1 and M3, and must not be presented as such.

## OPEN 4 — versions

See `docs/versions.md`. Only installed versions are recorded there; nothing is pinned with hashes yet.

## OPEN 5 — deadline, language and format

- Deadline: 2026-10-28.
- Code, docstrings and technical docs are in English. The lab guide (`docs/guide/TP-canary-qday.md`) is in French.
- The deliverable is a reproducible practical lab, not a classical academic report (owner's instruction).

## Deviations from the spec

| Spec | Deviation | Reason |
|---|---|---|
| Python 3.12 | Developed with Python 3.13.4. `requires-python >= 3.12`, ruff and mypy target 3.12. | Version installed on the machine. Not re-tested on 3.12. |
| Differential tests vs liboqs (FR-002) | Differential check against OpenSSL via `cryptography` 50.0.2 (ML-KEM-768/1024 only). A 20-iteration script check passed. | liboqs-python is not available on Windows. `cryptography` has no ML-KEM-512, so 512 is covered by ACVP only. FR-002 (1000 runs per set) is not met. |
| Registry in `traffic/registry.py` | DAO in `common/store.py`; `traffic/registry.py` keeps the generator-side API | The response engine must depend only on `siem` and `common` (spec §8). |
| `response/` file list | Extra modules `engine.py` (orchestration) and `state.py` (incident DB) | The incident DB must be separate from the registry so that a dry-run leaves the registry byte-identical (SEC-002). |
| `make` targets | `tools/run.py` provides them; the `Makefile` wraps it | `make` is not installed on the target Windows machines. |
| Policy "switch to stronger profile" | Disables the broken profile **and every weaker profile**, revokes the key, bumps the epoch | A break of ORANGE implies RED is no safer. |
| Rate limiting (SEC-007) | One containment run per (action, params_id, dry/apply) per 300 s, plus 30 alerts/min at the endpoint | Dry-run and apply are separated so that a dry-run does not suppress a later real response. |
