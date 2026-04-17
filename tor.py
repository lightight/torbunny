import time
import socket

import requests
from stem import Signal
from stem.control import Controller

SOCKS5_PROXY = "socks5h://127.0.0.1:9050"
TOR_CHECK_URL = "https://check.torproject.org/api/ip"
TOR_CONTROL_PORT = 9051
TOR_CONTROL_PASSWORD = ""  # set if your torrc uses HashedControlPassword

# Many public APIs (mail.gw, Guerrilla, etc.) block the default python-requests UA.
_BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def build_session() -> requests.Session:
    """Return a requests.Session that routes all traffic through Tor."""
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": _BROWSER_UA,
            "Accept-Language": "en-US,en;q=0.9",
        }
    )
    session.proxies = {
        "http": SOCKS5_PROXY,
        "https": SOCKS5_PROXY,
    }
    return session


def verify_tor(session: requests.Session) -> str:
    """
    Confirm traffic is flowing through Tor.
    Returns the Tor exit node IP on success, raises RuntimeError on failure.
    """
    try:
        resp = session.get(TOR_CHECK_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("IsTor", False):
            raise RuntimeError(
                "Connected to check.torproject.org but IsTor is False. "
                "Your traffic may not be routed through Tor."
            )
        return data["IP"]
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            "Cannot connect to Tor. Make sure the Tor service is running "
            "(e.g. `brew services start tor` or `tor &`)."
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise RuntimeError("Tor check timed out after 30 seconds.") from exc


def rotate_ip(session: requests.Session, old_ip: str | None = None) -> tuple[str, str | None]:
    """
    Send a NEWNYM signal to the Tor control port to request a new circuit,
    then poll until the exit IP differs from `old_ip` (or give up).

    Requires the Tor control port to be open (ControlPort 9051 in torrc).
    If the control port is unavailable, returns the current IP and a warning
    string explaining that rotation did not run.

    Returns (new_exit_ip, warning_or_none).
    Raises RuntimeError only if Tor connectivity check fails entirely.
    """
    before = old_ip if old_ip else verify_tor(session)
    rotated = False
    if _control_port_available():
        try:
            with Controller.from_port(port=TOR_CONTROL_PORT) as ctrl:
                if TOR_CONTROL_PASSWORD:
                    ctrl.authenticate(password=TOR_CONTROL_PASSWORD)
                else:
                    ctrl.authenticate()
                ctrl.signal(Signal.NEWNYM)
            rotated = True
        except Exception:
            rotated = False

    warn: str | None = None
    if not rotated:
        warn = (
            "Tor control port unavailable (add 'ControlPort 9051' to torrc and "
            "restart Tor) — exit IP was not rotated."
        )
        return verify_tor(session), warn

    # After NEWNYM, Tor needs time to build a new circuit; rate-limit is ~10s
    # between NEWNYM signals on the daemon side as well.
    time.sleep(10)

    # Poll until the visible exit changes (or we time out).
    for _ in range(30):
        after = verify_tor(session)
        if after != before:
            return after, None
        time.sleep(2)

    after = verify_tor(session)
    if after == before:
        warn = (
            "Exit IP did not change after NEWNYM (possible small exit pool or "
            "same relay re-selected)."
        )
    return after, warn


def _control_port_available() -> bool:
    """Return True if the Tor control port is listening."""
    try:
        with socket.create_connection(("127.0.0.1", TOR_CONTROL_PORT), timeout=1):
            return True
    except OSError:
        return False
