# Browser-driven credential rotation

`--features browser` enables `POST /browser/rotate`, which drives a Playwright browser session to log into a target site and change its password automatically. Vision-LLM analysis (LiteLLM + a vision model such as `gpt-4o` or local Qwen3-VL) is used to identify form fields and submit buttons on arbitrary login/change-password pages.

## Requirements

- `LITELLM_URL` set to your LiteLLM base URL (e.g. local MLbox endpoint)
- `VISION_MODEL` set to the name of a vision-capable model served by that LiteLLM deployment
- `playwright/agent.py` present at one of:
  - `/app/playwright/agent.py` (inside the published container)
  - `./playwright/agent.py` (relative to the working directory)
  - `$PLAYWRIGHT_AGENT_PATH` (explicit override)
- The endpoint is gated behind the internal bearer token (`Authorization: Bearer $(cat $CONFIG_DIR/internal-token)`)

If `playwright/agent.py` is not found, the endpoint returns **501** with an actionable error message rather than silently succeeding and failing in the background. If `LITELLM_URL` or `VISION_MODEL` is unset, the endpoint returns **400** before any browser is spawned.

## Security model

- Vision-LLM responses are sanitised by `sanitize_output` **before** JSON parsing — injection phrases, `<tool_call>` tags, and LLM control tokens are replaced with `[FILTERED]` before any field value can influence Playwright selectors or downstream tool calls. Adversarial text embedded in web-page screenshots cannot reach downstream tool decisions.
- Screenshots and LLM calls never leave the homelab network when `LITELLM_URL` points at a local LiteLLM (MLbox/Ollama/etc.).
- The endpoint is gated behind the internal bearer token; even on `127.0.0.1`, callers must present `$CONFIG_DIR/internal-token`.

See [SECURITY.md §Browser rotation subsystem](../../SECURITY.md#browser-rotation-subsystem---features-browser).

## Limits

Browser rotation is the user-facing endpoint. The generic `POST /rotate` endpoint (planned for arbitrary downstream services with no browser flow) is not part of v1.0 — see [../ROADMAP.md](../ROADMAP.md).
