# Splunk integration — status and manual checklist

**Status: not tested against a live Splunk instance.** Everything in this folder was written from the Splunk documentation and the project's own event schema. The tested path is the mock SIEM (`src/canary_qday/siem/mock_hec.py`).

## What exists

| Piece | File | Tested? |
|---|---|---|
| HEC sink (POST `/services/collector/event`, `Authorization: Splunk <token>`, disk buffer when down) | `src/canary_qday/siem/splunk_hec.py` | Unit-tested against an unreachable endpoint: buffering and redaction. Never against a live HEC. |
| Sourcetype definition | `props.conf` | No |
| Alert rule (trap_triggered, suppressed per token_id for 60 s, webhook) | `savedsearches.conf` | No |
| Response engine path-secret mode (`POST /v1/alerts/{path_secret}`) | `src/canary_qday/response/webhook.py` | Unit-tested with the project's `Alert` schema |

## Known gaps

1. **Payload format.** Splunk's native webhook posts `{sid, search_name, app, owner, results_link, result}`. The response engine expects the `Alert` schema (`src/canary_qday/siem/schemas.py`). An adapter mapping `result` to `Alert.event` (and building `alert_id` from `sid`) is **not implemented**. Without it, Splunk alerts are rejected with `422 E_SCHEMA`.
2. **No signature.** The native webhook cannot add custom headers: only `param.user_agent` is documented in `alert_actions.conf`. Hence the `SharedSecretPath` mode, which must be combined with network isolation and the webhook allow-list. A Splunk *custom alert action* could sign requests (`HmacHeader`); it is not implemented.
3. **License.** Alerting requires a trial, developer or enterprise license; the free license has no alerting (to verify for the version used).

## Manual checklist (for a future live test)

- [ ] Create index `canary` and a HEC token restricted to it. Store the token as a Docker secret or `CQ_HEC_TOKEN_FILE`; never commit it.
- [ ] Set `CQ_SIEM_SINK=hec` and `CQ_HEC_URL=https://<splunk>:8088` for the canary server and proxy. Run one stream and trigger a trap.
- [ ] Search `index=canary sourcetype="canary:event"`: check `trap_triggered` and `handshake` events, with no full token and no `FAKE-` value.
- [ ] Install `props.conf` and `savedsearches.conf`, and check the timestamp extraction.
- [ ] Implement and test the payload adapter (gap 1). Then set `CQ_WEBHOOK_AUTH=path` and the path secret, and check that the alert reaches `/v1/alerts/<secret>` within 60 s (FR-008).
- [ ] Stop Splunk, trigger a trap, and check that the event is buffered and later delivered by `flush()`.
