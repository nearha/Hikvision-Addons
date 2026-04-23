# Fork notes: unlock event + ring event + call event

This fork adds MQTT `event` entities focused on access and call history.

## What changed
- Keeps the **unlock** event only for **outdoor** devices.
- Adds a new **ring** event entity only for **outdoor** devices.
- Adds a new **call** event entity only for **outdoor** devices.
- Enables call-state polling for **all** devices (indoor and outdoor). If `call_state_poll` is not set, it now defaults to **1 second**.

## Unlock event
- Entity: `event.<doorbell_name>_unlock`
- Attributes:
  - `unlock_type`
  - `number`
  - `door_id`
  - `image_path` when the SDK delivers an unlock picture
- `door_id` is normalized as `wLockID + 1`
- `HOUSEHOLDER` is normalized by stripping the `1001011` prefix and leading zeroes
- `CENTER_PLATFORM` publishes `number: null`
- Unlock images from the SDK are saved under `/media/hikvision/<device>/unlock/`

## Ring event
- Entity: `event.<doorbell_name>_ring`
- Triggered from **call-state polling**, not only from the raw alarm callback
- On outdoor ring:
  - takes a fresh snapshot
  - saves it under `/media/hikvision/<device>/ring/`
  - tries to detect which linked indoor unit is ringing or on-call
- Attributes:
  - `caller` (derived from the matching indoor device name; if multiple are active, names are joined with commas)
  - `image_path`

## Call event
- Entity: `event.<doorbell_name>_call`
- Published when the outdoor call returns to `idle`
- Attributes:
  - `result` = `answered` or `not_answered`
  - `duration` (for example `8s`)
  - `duration_seconds`
  - `unlock_realizado` = `true` / `false`
  - `caller` when known
  - `image_path` from the ring snapshot when available
  - `unlock_type` and `unlock_number` when an unlock happened during the active call
- If the call reaches `onCall`, duration is measured from `onCall` to `idle`
- Otherwise, duration is measured from the first non-idle state to `idle`

## Linking indoor to outdoor
- Indoor units are matched to their outdoor unit using the linked outdoor IP resolved by the addon.
- The `caller` field is based on the configured indoor device name.

## Main code changes
- `hikvision-doorbell/src/mqtt.py`
