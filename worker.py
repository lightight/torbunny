"""
Build verification URLs for the Cloudflare Worker that fronts bunny.net
email confirmation (mode=bunny, origin + key query params).
"""
from __future__ import annotations

from urllib.parse import urlencode


DEFAULT_WORKER_BASE = "https://white-hat-fc21.ihatecamouflage.workers.dev"
DEFAULT_ORIGIN = "https://realvoid.xyz"


def build_worker_verify_url(
    key_url: str,
    *,
    origin: str = DEFAULT_ORIGIN,
    worker_base: str = DEFAULT_WORKER_BASE,
) -> str:
    """
    Return a GET URL like:
      {worker_base}/?mode=bunny&origin=<origin>&key=<confirm_email_url>

    `key_url` must be the full api.bunny.net/user/confirmemail?... URL from the email.
    """
    base = worker_base.strip().rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"
    qs = urlencode({"mode": "bunny", "origin": origin, "key": key_url})
    return f"{base}/?{qs}"
