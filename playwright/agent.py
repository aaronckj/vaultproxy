#!/usr/bin/env python3
import os
import sys
import json
import base64
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

# Only allow http/https navigation — block file://, javascript:, data:, etc.
ALLOWED_SCHEMES = {"http", "https"}


def is_safe_url(url: str) -> bool:
    """Reject URLs with dangerous schemes (file://, javascript:, data:, etc.)."""
    try:
        parsed = urlparse(url)
        return parsed.scheme.lower() in ALLOWED_SCHEMES
    except Exception:
        return False


def main():
    with sync_playwright() as p:
        launch_kwargs = {"headless": True}
        proxy_url = os.environ.get("MLBOX_AGENT_PROXY", "").strip()
        if proxy_url:
            launch_kwargs["proxy"] = {"server": proxy_url}
        browser = p.chromium.launch(**launch_kwargs)
        page = browser.new_page(
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
        )

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                cmd = json.loads(line)
                action = cmd.get("action")

                # Each action accepts an optional per-call `timeout` (ms)
                # so a hung page or detached element cannot consume the
                # Playwright default (30s) for every call. Rust caller
                # passes a budget derived from the step deadline.
                timeout = cmd.get("timeout", 15000)

                if action == "navigate":
                    url = cmd["url"]
                    if not is_safe_url(url):
                        print(json.dumps({"status": "error", "error": f"Blocked unsafe URL scheme: {url}"}), flush=True)
                        continue
                    page.goto(url, timeout=timeout)
                    print(json.dumps({"status": "ok", "url": page.url}), flush=True)

                elif action == "screenshot":
                    data = page.screenshot(timeout=timeout)
                    image_b64 = base64.b64encode(data).decode("utf-8")
                    print(json.dumps({"status": "ok", "image_b64": image_b64}), flush=True)

                elif action == "dom_excerpt":
                    # Returns page.content() (full DOM) capped to N chars so
                    # the LLM judge prompt stays under context. Caller can pass
                    # `max_chars` to override the default 8000.
                    max_chars = int(cmd.get("max_chars", 8000))
                    dom = page.content()[:max_chars]
                    print(json.dumps({"status": "ok", "dom": dom}), flush=True)

                elif action == "sleep":
                    import time as _t
                    _t.sleep(float(cmd.get("seconds", 1)))
                    print(json.dumps({"status": "ok"}), flush=True)

                elif action == "fill":
                    page.fill(cmd["selector"], cmd["value"], timeout=timeout)
                    print(json.dumps({"status": "ok"}), flush=True)

                elif action == "type_keys":
                    page.click(cmd["selector"], timeout=timeout)
                    for key in cmd["keys"]:
                        page.keyboard.press(key)
                    print(json.dumps({"status": "ok"}), flush=True)

                elif action == "click":
                    page.click(cmd["selector"], timeout=timeout)
                    print(json.dumps({"status": "ok"}), flush=True)

                elif action == "wait":
                    timeout = cmd.get("timeout", 10000)
                    page.wait_for_selector(cmd["selector"], timeout=timeout)
                    print(json.dumps({"status": "ok"}), flush=True)

                elif action == "get_url":
                    print(json.dumps({"status": "ok", "url": page.url}), flush=True)

                elif action == "close":
                    print(json.dumps({"status": "ok", "closing": True}), flush=True)
                    break

                else:
                    print(json.dumps({"status": "error", "error": f"Unknown action: {action}"}), flush=True)

            except Exception as e:
                print(json.dumps({"status": "error", "error": str(e)}), flush=True)

        browser.close()


if __name__ == "__main__":
    main()
