"""
Disposable inbox (no API keys). Default is **mail.gw** only: many unrelated
domains and human-like local parts — not a single famous disposable hostname.

Optional fallbacks: ``--mail-tm-fallback``, ``--guerrilla-fallback`` (Guerrilla
is often blocklisted by registrars; off by default).

Uses the Tor session from ``tor.build_session()`` (browser User-Agent required).
"""
from __future__ import annotations

import html as html_lib
import random
import re
import secrets
import string
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import requests
from faker import Faker

_fake = Faker("en_US")

# ─── shared types ────────────────────────────────────────────────────────────


class MailboxError(Exception):
    pass


@dataclass
class TempMailbox:
    email: str
    provider: str  # "mail_gw" | "guerrilla" | "mail_tm"
    password: str = ""
    token: str = ""
    sid_token: str = ""
    domain: str = ""


@dataclass
class Message:
    id: str
    from_addr: str
    subject: str
    created_at: str
    body_html: str = ""
    body_text: str = ""


_JSON_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/ld+json, application/json, text/plain;q=0.9, */*;q=0.8",
}
_BROWSER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# api.mail.gw often returns 502/503 from upstream; retry before surfacing.
_TRANSIENT_HTTP = frozenset({502, 503, 504, 429})


# ─── mail.gw (same protocol as mail.tm, different domain pool) ───────────────

_MGW = "https://api.mail.gw"


def _mgw_post(session: requests.Session, path: str, payload: dict) -> dict:
    url = f"{_MGW}{path}"
    last: Exception | None = None
    for attempt in range(5):
        try:
            r = session.post(url, json=payload, headers=_JSON_HEADERS, timeout=45)
            r.raise_for_status()
            return r.json() if r.content else {}
        except requests.HTTPError as exc:
            last = exc
            code = exc.response.status_code if exc.response is not None else 0
            if code in _TRANSIENT_HTTP and attempt < 4:
                time.sleep(min(1.5 * (2**attempt), 12))
                continue
            raise
        except requests.RequestException as exc:
            last = exc
            if attempt < 4:
                time.sleep(min(1.5 * (2**attempt), 12))
                continue
            raise
    raise last if last else MailboxError("mail.gw POST failed")


def _mgw_get(
    session: requests.Session,
    path: str,
    token: str,
    params: dict | None = None,
) -> dict:
    h = {**_JSON_HEADERS, "Authorization": f"Bearer {token}"}
    url = f"{_MGW}{path}"
    last: Exception | None = None
    for attempt in range(6):
        try:
            r = session.get(url, headers=h, params=params or {}, timeout=45)
            r.raise_for_status()
            return r.json() if r.content else {}
        except requests.HTTPError as exc:
            last = exc
            code = exc.response.status_code if exc.response is not None else 0
            if code in _TRANSIENT_HTTP and attempt < 5:
                time.sleep(min(1.5 * (2**attempt), 15))
                continue
            raise
        except requests.RequestException as exc:
            last = exc
            if attempt < 5:
                time.sleep(min(1.5 * (2**attempt), 15))
                continue
            raise
    raise last if last else MailboxError("mail.gw GET failed")


def _mgw_domains(session: requests.Session) -> list[str]:
    """Public ``/domains`` GET — same upstream flakiness as other mail.gw calls."""
    url = f"{_MGW}/domains"
    last: Exception | None = None
    for attempt in range(6):
        try:
            r = session.get(url, headers=_JSON_HEADERS, timeout=45)
            r.raise_for_status()
            data = r.json()
            members = data if isinstance(data, list) else data.get("hydra:member", [])
            out: list[str] = []
            for d in members:
                if isinstance(d, dict):
                    dom = d.get("domain") or d.get("name") or ""
                    if dom:
                        out.append(dom)
                elif isinstance(d, str):
                    out.append(d)
            return out
        except requests.HTTPError as exc:
            last = exc
            code = exc.response.status_code if exc.response is not None else 0
            if code in _TRANSIENT_HTTP and attempt < 5:
                time.sleep(min(1.5 * (2**attempt), 15))
                continue
            raise
        except requests.RequestException as exc:
            last = exc
            if attempt < 5:
                time.sleep(min(1.5 * (2**attempt), 15))
                continue
            raise
    raise last if last else MailboxError("mail.gw: domains fetch failed")


def _create_mail_gw(
    session: requests.Session,
    max_attempts: int = 18,
    banned_domains: set[str] | None = None,
) -> TempMailbox:
    all_domains = _mgw_domains(session)
    domains = [d for d in all_domains if d not in (banned_domains or set())] or all_domains
    if not domains:
        raise MailboxError("mail.gw: no domains")
    last_err: Exception | None = None
    for _ in range(max_attempts):
        try:
            domain = random.choice(domains)
            local = _mail_gw_local_part()
            email = f"{local}@{domain}"
            password = _random_password()

            _mgw_post(session, "/accounts", {"address": email, "password": password})
            auth = _mgw_post(session, "/token", {"address": email, "password": password})
            token = auth.get("token", "")
            if not token:
                raise MailboxError("mail.gw: no token")
            return TempMailbox(
                email=email,
                provider="mail_gw",
                password=password,
                token=token,
                domain=domain,
            )
        except Exception as exc:
            last_err = exc
            time.sleep(0.4)
    raise last_err if last_err else MailboxError("mail.gw: failed")


def _hydra_members(data: object) -> list:
    """Hydra often uses hydra:member; key can be present with value null — broken []."""
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    raw = data.get("hydra:member")
    if raw is None:
        raw = data.get("member") or data.get("messages")
    if raw is None:
        return []
    return raw if isinstance(raw, list) else []


def _api_message_id(m: dict) -> str:
    """mail.gw / mail.tm may expose only JSON-LD @id for messages."""
    if m.get("id") is not None:
        return str(m["id"])
    aid = str(m.get("@id") or "")
    if "/messages/" in aid:
        return aid.split("/messages/")[-1].rstrip("/").split("?")[0]
    if aid:
        return aid.rstrip("/").split("/")[-1]
    return ""


def _list_mail_gw(session: requests.Session, mb: TempMailbox) -> list[Message]:
    """Hydra pagination; first page: try no query, then ``page=1``."""
    out: list[Message] = []
    seen_ids: set[str] = set()

    def _one_page(params: dict | None) -> list:
        data = _mgw_get(session, "/messages", mb.token, params=params)
        return _hydra_members(data)

    page = 1
    while page < 12:
        if page == 1:
            members = _one_page(None)
            if not members:
                members = _one_page({"page": 1})
        else:
            members = _one_page({"page": page})
        if not members:
            break
        for m in members:
            mid = _api_message_id(m)
            if not mid or mid in seen_ids:
                continue
            seen_ids.add(mid)
            frm = m.get("from", {})
            addr = frm.get("address", "") if isinstance(frm, dict) else str(frm or "")
            out.append(
                Message(
                    id=mid,
                    from_addr=addr,
                    subject=m.get("subject", "") or "",
                    created_at=m.get("createdAt", "") or m.get("created_at", ""),
                )
            )
        if len(members) < 20:
            break
        page += 1
    return out


def _body_from_mail_api(data: dict[str, Any]) -> tuple[str, str]:
    """Normalize html + text from mail.gw / mail.tm single-message JSON."""
    raw_html = data.get("html")
    if isinstance(raw_html, list) and raw_html:
        body_html = "\n".join(str(x) for x in raw_html if x)
    elif isinstance(raw_html, str):
        body_html = raw_html
    else:
        body_html = ""
    body_text = data.get("text", "") or ""
    if isinstance(body_text, list):
        body_text = "\n".join(str(x) for x in body_text)
    body_text = str(body_text)
    # Some APIs expose a short preview / intro line with the link
    for extra in ("intro", "body", "blurb", "content"):
        chunk = data.get(extra)
        if isinstance(chunk, str) and chunk.strip():
            if "bunny.net" in chunk.lower() or "confirmemail" in chunk.lower():
                body_html = (body_html + "\n" + chunk).strip()
    return body_html, body_text


def _read_mail_gw(session: requests.Session, mb: TempMailbox, msg_id: str) -> Message:
    data = _mgw_get(session, f"/messages/{msg_id}", mb.token)
    body_html, body_text = _body_from_mail_api(data)
    mid = str(data.get("id") or _api_message_id(data))
    return Message(
        id=mid,
        from_addr=data.get("from", {}).get("address", ""),
        subject=data.get("subject", ""),
        created_at=data.get("createdAt", ""),
        body_html=body_html,
        body_text=body_text,
    )


# ─── Guerrilla Mail ────────────────────────────────────────────────────────────

_GUERRILLA = "https://api.guerrillamail.com/ajax.php"


def _guerrilla(session: requests.Session, params: dict) -> dict:
    p = {"ip": "127.0.0.1", "agent": _BROWSER_AGENT, **params}
    r = session.get(_GUERRILLA, params=p, timeout=30)
    r.raise_for_status()
    return r.json()


def _create_guerrilla(session: requests.Session) -> TempMailbox:
    data = _guerrilla(session, {"f": "get_email_address"})
    email = data.get("email_addr", "")
    sid = data.get("sid_token", "")
    if not email or not sid:
        raise MailboxError("Guerrilla Mail: missing email_addr or sid_token")
    dom = email.split("@", 1)[1] if "@" in email else ""
    user = secrets.token_hex(5)
    try:
        data2 = _guerrilla(
            session,
            {"f": "set_email_user", "email_user": user, "sid_token": sid},
        )
        if data2.get("email_addr"):
            email = data2["email_addr"]
            sid = data2.get("sid_token", sid)
    except Exception:
        pass

    return TempMailbox(
        email=email,
        provider="guerrilla",
        sid_token=sid,
        domain=dom,
    )


def _create_guerrilla_with_retries(session: requests.Session, attempts: int = 4) -> TempMailbox:
    last: Exception | None = None
    for _ in range(attempts):
        try:
            return _create_guerrilla(session)
        except Exception as exc:
            last = exc
            time.sleep(1.0)
    raise last if last else MailboxError("Guerrilla Mail: failed")


def _list_guerrilla(session: requests.Session, mb: TempMailbox) -> list[Message]:
    data = _guerrilla(
        session,
        {"f": "check_email", "seq": "0", "sid_token": mb.sid_token},
    )
    out = []
    for m in data.get("list", []) or []:
        out.append(
            Message(
                id=str(m.get("mail_id", "")),
                from_addr=m.get("mail_from", ""),
                subject=m.get("mail_subject", ""),
                created_at=str(m.get("mail_timestamp", "")),
            )
        )
    return out


def _read_guerrilla(session: requests.Session, mb: TempMailbox, msg_id: str) -> Message:
    data = _guerrilla(
        session,
        {
            "f": "fetch_email",
            "email_id": msg_id,
            "sid_token": mb.sid_token,
        },
    )
    body = data.get("mail_body") or ""
    return Message(
        id=str(data.get("mail_id", msg_id)),
        from_addr=data.get("mail_from", ""),
        subject=data.get("mail_subject", ""),
        created_at=str(data.get("mail_timestamp", "")),
        body_html=body if "<" in body else "",
        body_text=body if "<" not in body else "",
    )


# ─── mail.tm fallback ──────────────────────────────────────────────────────────

_MT = "https://api.mail.tm"


def _mt_post(session: requests.Session, path: str, payload: dict) -> dict:
    r = session.post(f"{_MT}{path}", json=payload, headers=_JSON_HEADERS, timeout=30)
    r.raise_for_status()
    return r.json() if r.content else {}


def _mt_get(
    session: requests.Session,
    path: str,
    token: str,
    params: dict | None = None,
) -> dict:
    h = {**_JSON_HEADERS, "Authorization": f"Bearer {token}"}
    r = session.get(f"{_MT}{path}", headers=h, params=params or {}, timeout=30)
    r.raise_for_status()
    return r.json() if r.content else {}


def _mt_domains(session: requests.Session) -> list[str]:
    url = f"{_MT}/domains"
    last: Exception | None = None
    for attempt in range(6):
        try:
            r = session.get(url, headers=_JSON_HEADERS, timeout=45)
            r.raise_for_status()
            data = r.json()
            members = data if isinstance(data, list) else data.get("hydra:member", [])
            out: list[str] = []
            for d in members:
                if isinstance(d, dict):
                    dom = d.get("domain") or d.get("name") or ""
                    if dom:
                        out.append(dom)
                elif isinstance(d, str):
                    out.append(d)
            return out
        except requests.HTTPError as exc:
            last = exc
            code = exc.response.status_code if exc.response is not None else 0
            if code in _TRANSIENT_HTTP and attempt < 5:
                time.sleep(min(1.5 * (2**attempt), 15))
                continue
            raise
        except requests.RequestException as exc:
            last = exc
            if attempt < 5:
                time.sleep(min(1.5 * (2**attempt), 15))
                continue
            raise
    raise last if last else MailboxError("mail.tm: domains fetch failed")


def _create_mail_tm(
    session: requests.Session,
    banned_domains: set[str] | None = None,
) -> TempMailbox:
    all_domains = _mt_domains(session)
    domains = [d for d in all_domains if d not in (banned_domains or set())] or all_domains
    if not domains:
        raise MailboxError("mail.tm: no domains")
    domain = random.choice(domains)
    local = secrets.token_hex(6)
    email = f"{local}@{domain}"
    password = _random_password()
    _mt_post(session, "/accounts", {"address": email, "password": password})
    auth = _mt_post(session, "/token", {"address": email, "password": password})
    token = auth.get("token", "")
    if not token:
        raise MailboxError("mail.tm: no token")
    return TempMailbox(
        email=email,
        provider="mail_tm",
        password=password,
        token=token,
        domain=domain,
    )


def _list_mail_tm(session: requests.Session, mb: TempMailbox) -> list[Message]:
    out: list[Message] = []
    seen_ids: set[str] = set()

    def _one_page(params: dict | None) -> list:
        data = _mt_get(session, "/messages", mb.token, params=params)
        return _hydra_members(data)

    page = 1
    while page < 12:
        if page == 1:
            members = _one_page(None)
            if not members:
                members = _one_page({"page": 1})
        else:
            members = _one_page({"page": page})
        if not members:
            break
        for m in members:
            mid = _api_message_id(m)
            if not mid or mid in seen_ids:
                continue
            seen_ids.add(mid)
            frm = m.get("from", {})
            addr = frm.get("address", "") if isinstance(frm, dict) else str(frm or "")
            out.append(
                Message(
                    id=mid,
                    from_addr=addr,
                    subject=m.get("subject", ""),
                    created_at=m.get("createdAt", "") or m.get("created_at", ""),
                )
            )
        if len(members) < 20:
            break
        page += 1
    return out


def _read_mail_tm(session: requests.Session, mb: TempMailbox, msg_id: str) -> Message:
    data = _mt_get(session, f"/messages/{msg_id}", mb.token)
    body_html, body_text = _body_from_mail_api(data)
    mid = str(data.get("id") or _api_message_id(data))
    return Message(
        id=mid,
        from_addr=data.get("from", {}).get("address", ""),
        subject=data.get("subject", ""),
        created_at=data.get("createdAt", ""),
        body_html=body_html,
        body_text=body_text,
    )


def _random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _human_local_part() -> str:
    """Human-looking local part derived from a fake name."""
    styles = [
        lambda: f"{_fake.first_name().lower()}{_fake.last_name().lower()}{random.randint(1, 999)}",
        lambda: f"{_fake.user_name().lower()}{random.randint(10, 99)}",
        lambda: f"{_fake.first_name().lower()}.{_fake.last_name().lower()}{random.randint(1, 99)}",
        lambda: f"{_fake.first_name().lower()}_{_fake.last_name().lower()}",
        lambda: f"{_fake.last_name().lower()}{random.randint(1, 9999)}",
    ]
    raw = random.choice(styles)()
    safe = re.sub(r"[^a-z0-9._+-]", "", raw.lower())[:64]
    return safe or secrets.token_hex(6)


# alias kept for callers inside this module
_mail_gw_local_part = _human_local_part


# ─── 1secmail ─────────────────────────────────────────────────────────────────
# No account creation required; any local@domain receives mail instantly.
# API: https://www.1secmail.com/api/v1/

_ONESEC = "https://www.1secmail.com/api/v1/"
_ONESEC_FALLBACK_DOMAINS = [
    "1secmail.com", "1secmail.net", "1secmail.org",
    "wwjmp.com", "esiix.com", "xojxe.com", "yoggm.com",
    "dcctb.com", "kzccv.com", "qiott.com", "rhyta.com",
    "cebular.com", "txcct.com",
]


def _onesec_call(
    session: requests.Session,
    params: dict,
    attempts: int = 6,
) -> Any:
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            r = session.get(
                _ONESEC,
                params=params,
                headers={"Accept": "application/json"},
                timeout=40,
            )
            r.raise_for_status()
            return r.json() if r.content else []
        except requests.HTTPError as exc:
            last = exc
            code = exc.response.status_code if exc.response is not None else 0
            if code in _TRANSIENT_HTTP and attempt < attempts - 1:
                time.sleep(min(1.5 * (2**attempt), 15))
                continue
            raise
        except requests.RequestException as exc:
            last = exc
            if attempt < attempts - 1:
                time.sleep(min(1.5 * (2**attempt), 15))
                continue
            raise
    raise last if last else MailboxError("1secmail: request failed")


def _onesec_domains(session: requests.Session) -> list[str]:
    try:
        data = _onesec_call(session, {"action": "getDomainList"})
        if isinstance(data, list) and data:
            return [str(d) for d in data if d]
    except Exception:
        pass
    return _ONESEC_FALLBACK_DOMAINS


def _create_onesecmail(
    session: requests.Session,
    banned_domains: set[str] | None = None,
) -> TempMailbox:
    all_domains = _onesec_domains(session)
    domains = [d for d in all_domains if d not in (banned_domains or set())] or all_domains
    domain = random.choice(domains)
    local = _human_local_part()
    email = f"{local}@{domain}"
    return TempMailbox(email=email, provider="onesecmail", domain=domain)


def _list_onesecmail(session: requests.Session, mb: TempMailbox) -> list[Message]:
    local, domain = mb.email.split("@", 1)
    data = _onesec_call(session, {"action": "getMessages", "login": local, "domain": domain})
    if not isinstance(data, list):
        return []
    out: list[Message] = []
    for m in data:
        mid = str(m.get("id", ""))
        if not mid:
            continue
        out.append(
            Message(
                id=mid,
                from_addr=m.get("from", ""),
                subject=m.get("subject", ""),
                created_at=m.get("date", ""),
            )
        )
    return out


def _read_onesecmail(session: requests.Session, mb: TempMailbox, msg_id: str) -> Message:
    local, domain = mb.email.split("@", 1)
    data = _onesec_call(
        session,
        {"action": "readMessage", "login": local, "domain": domain, "id": msg_id},
    )
    body_html = data.get("htmlBody", "") or data.get("body", "") or ""
    body_text = data.get("textBody", "") or ""
    # Some messages embed the link only in attachments text — include it
    for att in data.get("attachments", []) or []:
        if isinstance(att, dict):
            chunk = att.get("body", "")
            if chunk and ("bunny.net" in chunk.lower() or "confirmemail" in chunk.lower()):
                body_html = (body_html + "\n" + chunk).strip()
    return Message(
        id=str(data.get("id", msg_id)),
        from_addr=data.get("from", ""),
        subject=data.get("subject", ""),
        created_at=data.get("date", ""),
        body_html=body_html,
        body_text=body_text,
    )


# ─── Inboxes (inboxes.com) ────────────────────────────────────────────────────
# Public read-only inboxes — no signup, no auth token.
# Domains are not on the major blocklists and vary by subdomain.

_INBOXES_BASE = "https://inboxes.com"
_INBOXES_DOMAINS = [
    "inboxes.com",
    "another.lol",
    "spam4.me",
    "yopmail.com",
    "yopmail.fr",
    "cool.fr.nf",
    "jetable.fr.nf",
    "nospam.ze.tc",
    "nomail.xl.cx",
    "mega.zik.dj",
    "speed.1s.fr",
    "courriel.fr.nf",
    "moncourrier.fr.nf",
    "monemail.fr.nf",
    "monmail.fr.nf",
]


def _create_inboxes(session: requests.Session) -> TempMailbox:
    """
    Yopmail-family: no account needed, poll by inbox name.
    We pick a random domain from the family and generate a realistic local part.
    """
    domain = random.choice(_INBOXES_DOMAINS)
    local = _human_local_part()
    email = f"{local}@{domain}"
    return TempMailbox(email=email, provider="inboxes", domain=domain)


def _yop_get(session: requests.Session, path: str, params: dict | None = None) -> requests.Response:
    """GET to the yopmail API, retrying transients."""
    url = f"https://yopmail.com{path}"
    last: Exception | None = None
    for attempt in range(5):
        try:
            r = session.get(url, params=params or {}, timeout=30,
                            headers={"Accept": "application/json, text/html,*/*"})
            r.raise_for_status()
            return r
        except requests.HTTPError as exc:
            last = exc
            code = exc.response.status_code if exc.response is not None else 0
            if code in _TRANSIENT_HTTP and attempt < 4:
                time.sleep(min(1.5 * (2**attempt), 12))
                continue
            raise
        except requests.RequestException as exc:
            last = exc
            if attempt < 4:
                time.sleep(min(1.5 * (2**attempt), 12))
                continue
            raise
    raise last if last else MailboxError("yopmail GET failed")


def _list_inboxes(session: requests.Session, mb: TempMailbox) -> list[Message]:
    """
    Yopmail exposes a JSON inbox API at /api/inboxes.
    Fall back gracefully to empty list on any error.
    """
    local = mb.email.split("@")[0]
    try:
        r = _yop_get(session, "/api/inboxes", {"login": local, "yp": local})
        data = r.json()
        msgs = data if isinstance(data, list) else data.get("mails") or data.get("messages") or []
        out: list[Message] = []
        for m in msgs:
            mid = str(m.get("id") or m.get("mid") or "")
            if not mid:
                continue
            out.append(
                Message(
                    id=mid,
                    from_addr=m.get("from", ""),
                    subject=m.get("subject", "") or m.get("subj", ""),
                    created_at=m.get("date", "") or m.get("timestamp", ""),
                )
            )
        return out
    except Exception:
        return []


def _read_inboxes(session: requests.Session, mb: TempMailbox, msg_id: str) -> Message:
    local = mb.email.split("@")[0]
    try:
        r = _yop_get(session, f"/api/inbox/{msg_id}", {"login": local})
        data = r.json()
        body_html = data.get("htmlBody", "") or data.get("html", "") or data.get("body", "") or ""
        body_text = data.get("textBody", "") or data.get("text", "") or ""
        return Message(
            id=str(data.get("id", msg_id)),
            from_addr=data.get("from", ""),
            subject=data.get("subject", "") or data.get("subj", ""),
            created_at=data.get("date", "") or data.get("timestamp", ""),
            body_html=body_html,
            body_text=body_text,
        )
    except Exception:
        return Message(id=msg_id, from_addr="", subject="", created_at="")


# ─── dispatch ─────────────────────────────────────────────────────────────────


def create(
    session: requests.Session,
    *,
    allow_mail_tm_fallback: bool = False,
    allow_guerrilla_fallback: bool = False,
    banned_domains: set[str] | None = None,
) -> TempMailbox:
    """
    Try providers in order, picking a fresh one each run.

    Auto (always tried, shuffled so no single provider dominates):
      1. 1secmail  — no-auth, 10+ domains, simple REST
      2. mail.gw  — Hydra/JWT, many rotating domains
      3. mail.tm  — same API as mail.gw, different domain pool

    ``banned_domains`` is forwarded to each provider so domains from
    previously-suspended accounts are avoided.

    Flag-gated:
      Guerrilla Mail  — only if ``--guerrilla-fallback``
    """
    errors: list[str] = []
    banned = banned_domains or set()

    # Always-tried pool — shuffle so the order varies per run.
    # 1secmail removed: they return 403 for automated access regardless of IP.
    auto_providers: list[tuple] = [
        (_create_mail_gw, "mail.gw"),
        (_create_mail_tm, "mail.tm"),
    ]
    random.shuffle(auto_providers)

    for factory, label in auto_providers:
        try:
            return factory(session, banned_domains=banned)
        except Exception as exc:
            errors.append(f"{label}: {exc}")

    if allow_guerrilla_fallback:
        try:
            return _create_guerrilla_with_retries(session)
        except Exception as exc:
            errors.append(f"Guerrilla Mail: {exc}")

    raise MailboxError(
        "; ".join(errors) if errors else "no provider available"
    )


def list_messages(session: requests.Session, mailbox: TempMailbox) -> list[Message]:
    if mailbox.provider == "mail_gw":
        return _list_mail_gw(session, mailbox)
    if mailbox.provider == "guerrilla":
        return _list_guerrilla(session, mailbox)
    if mailbox.provider == "mail_tm":
        return _list_mail_tm(session, mailbox)
    if mailbox.provider == "onesecmail":
        return _list_onesecmail(session, mailbox)
    if mailbox.provider == "inboxes":
        return _list_inboxes(session, mailbox)
    raise MailboxError(f"Unknown provider: {mailbox.provider}")


def read_message(session: requests.Session, mailbox: TempMailbox, msg_id: str) -> Message:
    if mailbox.provider == "mail_gw":
        return _read_mail_gw(session, mailbox, msg_id)
    if mailbox.provider == "guerrilla":
        return _read_guerrilla(session, mailbox, msg_id)
    if mailbox.provider == "mail_tm":
        return _read_mail_tm(session, mailbox, msg_id)
    if mailbox.provider == "onesecmail":
        return _read_onesecmail(session, mailbox, msg_id)
    if mailbox.provider == "inboxes":
        return _read_inboxes(session, mailbox, msg_id)
    raise MailboxError(f"Unknown provider: {mailbox.provider}")


def _is_candidate_verification(
    msg: Message,
    subject_hint: str,
    sender_hint: str,
) -> bool:
    """Match verification mail; bunny may use third-party From lines without the word 'bunny'."""
    subj = (msg.subject or "").lower()
    frm = (msg.from_addr or "").lower()

    if "guerrilla mail" in subj and "welcome" in subj:
        return False
    if (
        "welcome" in subj
        and "bunny" in subj
        and "verif" not in subj
        and "confirm" not in subj
        and "verify" not in subj
    ):
        return False

    if subject_hint:
        sh = subject_hint.lower()
        if sh in subj:
            return True
        if sh == "verif":
            if any(
                k in subj
                for k in ("verify", "confirm", "verification", "activate", "activation")
            ):
                return True

    if sender_hint:
        sh = sender_hint.lower()
        if sh in frm:
            return True
        if sh == "bunny":
            if any(
                x in frm
                for x in (
                    "bunny.net",
                    "bunnycdn",
                    "bunnycdn.com",
                    "@bunny",
                )
            ):
                return True

    return False


def wait_for_message(
    session: requests.Session,
    mailbox: TempMailbox,
    subject_hint: str = "",
    sender_hint: str = "bunny",
    timeout: float = 180.0,
    poll_interval: float = 6.0,
    tick_callback: Callable[[int, int], None] | None = None,
) -> Message:
    """
    Poll the inbox until a bunny.net confirmation link appears in a message body.

    **Do not** mark a message id as "done" until we know it is junk (welcome) or
    we return it. Otherwise a first failed parse (or empty body) would skip the
    verification mail forever on the next poll.
    """
    deadline = time.monotonic() + timeout
    junk_ids: set[str] = set()
    poll_pass = 0

    while time.monotonic() < deadline:
        try:
            batch = list_messages(session, mailbox)
        except requests.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else 0
            if code in _TRANSIENT_HTTP:
                time.sleep(poll_interval)
                continue
            # Non-transient HTTP error (e.g. 403 from a provider blocking
            # automated access) — surface as MailboxError so the caller can
            # handle it cleanly instead of crashing with an unhandled exception.
            raise MailboxError(
                f"{mailbox.provider} inbox fetch failed (HTTP {code}): {exc}"
            ) from exc
        except requests.RequestException:
            time.sleep(poll_interval)
            continue

        poll_pass += 1
        if tick_callback:
            tick_callback(poll_pass, len(batch))

        for msg in batch:
            if not msg.id or msg.id in junk_ids:
                continue
            subj = (msg.subject or "").lower()
            # Only skip obvious Guerrilla onboarding from list metadata.
            if "guerrilla mail" in subj and "welcome" in subj:
                junk_ids.add(msg.id)
                continue

            try:
                full = read_message(session, mailbox, msg.id)
            except Exception:
                # Transient read failure — leave id out of junk_ids so we retry.
                continue

            fs = (full.subject or "").lower()
            ff = (full.from_addr or "").lower()
            # Bunny sends a "Welcome" mail that has no verify link and no
            # confirm/verify keyword in the subject; skip it only when we are
            # sure it is the onboarding welcome and NOT the email-confirm mail.
            is_bunny_welcome = (
                ("welcome" in fs or "welcome" in ff)
                and ("bunny" in fs or "bunny" in ff or "bunny" in subj)
                and not any(x in fs for x in ("verify", "verif", "confirm", "activation"))
            )
            if is_bunny_welcome and not find_verification_link(full):
                junk_ids.add(msg.id)
                continue

            # Return any non-junk message — let main.py extract the link.
            # Do NOT require _is_candidate_verification here; the list-level
            # from_addr is often empty (mail.gw returns null/{}), causing false
            # negatives that loop forever.
            return full

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_interval, remaining))

    raise MailboxError(
        f"No matching email arrived within {timeout:.0f} s (inbox: {mailbox.email})"
    )


def extract_links(body: str) -> list[str]:
    if not body:
        return []
    body = html_lib.unescape(body)
    raw = re.findall(r"https?://[^\s<>\"'()]+", body)
    raw.extend(re.findall(r'href=["\'](https?://[^"\']+)["\']', body, flags=re.I))
    seen: set[str] = set()
    unique: list[str] = []
    for url in raw:
        url = url.rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


def find_verification_link(msg: Message) -> str | None:
    body = "\n".join(
        x for x in (msg.body_html or "", msg.body_text or "") if x
    )
    if not body.strip():
        return None
    body = html_lib.unescape(body)

    # Direct pattern (confirm link is long and may not match generic URL regexes)
    for pat in (
        r"https?://api\.bunny\.net/user/confirmemail\?[^\s\"'<>]+",
        r"https?://[^/\s\"'<>]+bunny\.net/user/confirmemail\?[^\s\"'<>]+",
    ):
        m = re.search(pat, body, flags=re.I)
        if m:
            return m.group(0).rstrip(".,;:!?")

    links = extract_links(body)
    for link in links:
        lower = link.lower()
        if ("bunny.net" in lower or "bunnycdn" in lower) and any(
            kw in lower for kw in ("verif", "confirm", "token", "activate", "confirmemail")
        ):
            return link
    for link in links:
        if "bunny.net" in link.lower():
            return link
    return None
