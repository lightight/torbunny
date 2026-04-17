from __future__ import annotations

import secrets

import requests

BASE_URL = "https://api.bunny.net"

_CHROME_HEADERS = {
    "accept": "application/json, text/plain, */*",
    # accept-encoding is intentionally omitted — requests handles decompression
    # automatically only when it sets the header itself. Forcing it here causes
    # the raw compressed bytes to land in resp.text undecoded.
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": "https://dash.bunny.net",
    "referer": "https://dash.bunny.net/",
    "sec-ch-ua": '"Brave";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    "sec-gpc": "1",
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/147.0.0.0 Safari/537.36"
    ),
}


class BunnyAPIError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


_UTM_REFERRERS = [
    # Organic search / direct
    {"pk_buttonlocation": "header", "ref_domain": ""},
    {"pk_buttonlocation": "hero", "ref_domain": ""},
    {"pk_buttonlocation": "menu", "ref_domain": ""},
    # Inbound from common tech/dev sites
    {"pk_buttonlocation": "header", "ref_domain": "github.com"},
    {"pk_buttonlocation": "header", "ref_domain": "stackoverflow.com"},
    {"pk_buttonlocation": "header", "ref_domain": "dev.to"},
    {"pk_buttonlocation": "header", "ref_domain": "reddit.com"},
    {"pk_buttonlocation": "header", "ref_domain": "news.ycombinator.com"},
    {"pk_buttonlocation": "header", "ref_domain": "medium.com"},
    {"pk_buttonlocation": "header", "ref_domain": "digitalocean.com"},
    {"pk_buttonlocation": "header", "ref_domain": "cloudflare.com"},
    {"pk_buttonlocation": "hero", "ref_domain": "google.com"},
    {"pk_buttonlocation": "hero", "ref_domain": "google.co.uk"},
    {"pk_buttonlocation": "hero", "ref_domain": "bing.com"},
    {"pk_buttonlocation": "hero", "ref_domain": "duckduckgo.com"},
]


def register(
    session: requests.Session,
    email: str,
    password: str,
    first_name: str = "",
    last_name: str = "",
) -> str:
    """
    Register a new bunny.net account.
    Returns the .AspNet.ApplicationCookie value on success.
    Raises BunnyAPIError on failure.
    """
    url = f"{BASE_URL}/auth/register"
    utm = secrets.choice(_UTM_REFERRERS)
    payload: dict = {
        "PowToken": "",
        "Email": email,
        "Password": password,
        "Utm": utm,
    }
    if first_name:
        payload["FirstName"] = first_name
    if last_name:
        payload["LastName"] = last_name
    resp = session.post(url, json=payload, headers=_CHROME_HEADERS, timeout=60)

    if resp.status_code not in (200, 204):
        _raise_api_error("Registration failed", resp)

    cookie = resp.cookies.get(".AspNet.ApplicationCookie")
    if not cookie:
        # Some versions return it in Set-Cookie header directly
        for cookie_obj in resp.cookies:
            if "ApplicationCookie" in cookie_obj.name:
                cookie = cookie_obj.value
                break
    if not cookie:
        raise BunnyAPIError(
            f"Registration succeeded (HTTP {resp.status_code}) but no "
            "ApplicationCookie was returned. The account may still have been created.",
            resp.status_code,
        )
    return cookie


def get_jwt(session: requests.Session, email: str, password: str) -> str:
    """
    Exchange email/password for a JWT token.
    Returns the raw JWT string.
    """
    url = f"{BASE_URL}/auth/jwt"
    payload = {"Email": email, "Password": password}
    resp = session.post(url, json=payload, headers=_CHROME_HEADERS, timeout=60)

    if resp.status_code not in (200, 204):
        _raise_api_error("Login failed", resp)

    try:
        body = resp.json()
    except Exception as exc:
        raise BunnyAPIError(
            f"Login returned HTTP {resp.status_code} but response is not JSON: "
            f"{resp.text[:200]}"
        ) from exc

    # The JWT may be the raw string body or nested under a key
    if isinstance(body, str):
        return body
    for key in ("token", "Token", "jwt", "JWT", "accessToken", "access_token"):
        if key in body:
            return body[key]

    raise BunnyAPIError(
        f"Could not find JWT token in response: {body}", resp.status_code
    )


def get_user(session: requests.Session, jwt: str) -> dict:
    """
    Fetch the authenticated user's profile using the JWT token.
    Returns the parsed JSON dict.
    """
    url = f"{BASE_URL}/user"
    headers = {**_CHROME_HEADERS, "authorization": jwt}
    # /user uses Authorization header, not content-type
    headers.pop("content-type", None)
    resp = session.get(url, headers=headers, timeout=60)

    if resp.status_code != 200:
        _raise_api_error("Failed to fetch user", resp)

    try:
        return resp.json()
    except Exception as exc:
        raise BunnyAPIError(
            f"GET /user returned HTTP {resp.status_code} but response is not JSON: "
            f"{resp.text[:200]}"
        ) from exc


def get_api_key(session: requests.Session, jwt: str) -> str:
    """
    Fetch the account's master API key from /apikey.
    Returns the key as a plain string.
    """
    url = f"{BASE_URL}/apikey"
    headers = {**_CHROME_HEADERS, "authorization": jwt}
    headers.pop("content-type", None)
    resp = session.get(url, headers=headers, timeout=60)

    if resp.status_code != 200:
        _raise_api_error("Failed to fetch API key", resp)

    try:
        body = resp.json()
    except Exception as exc:
        raise BunnyAPIError(
            f"GET /apikey returned HTTP {resp.status_code} but response is not JSON: "
            f"{resp.text[:200]}"
        ) from exc

    if isinstance(body, str):
        return body

    # Paginated list response: {"Items": [{"Key": "...", ...}], ...}
    items = body.get("Items") or body.get("items")
    if items and isinstance(items, list) and len(items) > 0:
        item = items[0]
        for k in ("Key", "key", "ApiKey", "apiKey", "api_key"):
            if k in item:
                return str(item[k])

    # Flat object with a known key field
    for k in ("Key", "key", "ApiKey", "apiKey", "api_key", "value", "Value"):
        if k in body:
            return str(body[k])

    return str(body)


def create_pull_zone(
    session: requests.Session,
    access_key: str,
    name: str,
    origin_url: str | None = None,
) -> dict:
    """
    Create a CDN pull zone (POST /pullzone).
    Authenticates with the account API key via the AccessKey header.
    """
    url = f"{BASE_URL}/pullzone"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "AccessKey": access_key,
    }
    payload: dict = {"Name": name}
    if origin_url:
        payload["OriginUrl"] = origin_url

    resp = session.post(url, json=payload, headers=headers, timeout=60)

    if resp.status_code not in (200, 201):
        _raise_api_error("Create pull zone failed", resp)

    if not resp.content:
        return {}
    try:
        return resp.json()
    except Exception:
        return {}


def create_pull_zones_batch(
    session: requests.Session,
    access_key: str,
    origin_url: str,
    count: int,
    name_prefix: str = "torbunny",
) -> list[dict]:
    """
    Create `count` pull zones with the same OriginUrl and unique Names.
    Returns a list of API response dicts (may be empty body per zone).
    """
    out: list[dict] = []
    for i in range(count):
        suffix = secrets.token_hex(4)
        name = f"{name_prefix}-{suffix}-{i + 1}"
        out.append(
            create_pull_zone(session, access_key, name, origin_url=origin_url)
        )
    return out


def _raise_api_error(context: str, resp: requests.Response) -> None:
    try:
        body = resp.json()
        detail = body.get("Message") or body.get("message") or body.get("error") or str(body)
    except Exception:
        detail = resp.text[:300] or "(empty body)"
    raise BunnyAPIError(
        f"{context} — HTTP {resp.status_code}: {detail}", resp.status_code
    )
