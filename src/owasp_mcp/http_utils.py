from __future__ import annotations

import logging
import time

import httpx

log = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_BASE = 2.0


def fetch_json(url: str, timeout: int = 30, headers: dict | None = None) -> dict | list:
    for attempt in range(_MAX_RETRIES):
        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=True, headers=headers or {})
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPStatusError, httpx.ConnectError, httpx.ReadTimeout) as exc:
            if attempt == _MAX_RETRIES - 1:
                raise
            wait = _BACKOFF_BASE ** attempt
            log.warning("HTTP request failed (attempt %d/%d), retrying in %.1fs: %s", attempt + 1, _MAX_RETRIES, wait, exc)
            time.sleep(wait)
    raise RuntimeError("unreachable")
