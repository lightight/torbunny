#!/usr/bin/env python3
"""
torbunny — Register and manage bunny.net accounts over Tor.
"""
from __future__ import annotations

import json
import sys
import textwrap

import click
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.prompt import Prompt

import tor as tor_module
import api as bunny_api
import mailbox as mb
import worker as worker_cfg
from banner import print_startup_banner
from api import BunnyAPIError
from mailbox import MailboxError, TempMailbox
from generator import generate_credentials

console = Console()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _step(n: int, label: str) -> None:
    console.print(f"\n[bold cyan][{n}][/bold cyan] {label}")


def _ok(msg: str) -> None:
    console.print(f"  [bold green]✓[/bold green] {msg}")


def _err(msg: str) -> None:
    console.print(f"  [bold red]✗[/bold red] {msg}")


def _render_user(data: dict) -> None:
    """Pretty-print the /user JSON response as a Rich table."""
    table = Table(
        title="bunny.net User Profile",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        min_width=60,
    )
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    # Fields to surface first, in order
    priority = [
        "Id", "Email", "FirstName", "LastName", "CompanyName",
        "BillingEmail", "Balance", "Roles", "DateJoined",
        "EmailVerified", "TwoFactorAuthEnabled", "AccountSuspended",
    ]
    shown: set[str] = set()
    for key in priority:
        if key in data:
            val = data[key]
            table.add_row(key, _fmt_value(val))
            shown.add(key)

    for key, val in data.items():
        if key not in shown:
            table.add_row(key, _fmt_value(val))

    console.print(table)


def _fmt_value(v) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, indent=2)
    if v is None:
        return "[dim]null[/dim]"
    if isinstance(v, bool):
        return "[green]true[/green]" if v else "[red]false[/red]"
    return str(v)


def _truncate(s: str, n: int = 40) -> str:
    return s[:n] + "…" if len(s) > n else s


_VERIFY_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/147.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def _verify_email_follow(
    session,
    verify_link: str,
    *,
    no_worker_verify: bool,
    worker_base: str,
    cdn_origin: str,
    no_clearnet_verify: bool,  # kept for CLI compat; clearnet is never used
) -> tuple[bool, str]:
    """
    Open the confirmation URL entirely through Tor (session already proxied).

    Strategy:
      1. Optional worker URL via the same Tor session.
      2. Direct bunny.net URL via Tor.
      3. Rotate Tor circuit and retry the direct URL once more.

    Clearnet is intentionally never used — all requests stay in the Tor session.
    """
    def _get(url: str) -> requests.Response:
        return session.get(
            url,
            timeout=60,
            allow_redirects=True,
            headers=_VERIFY_HEADERS,
        )

    # 1) Worker URL (optional) — still through Tor session
    if not no_worker_verify:
        wurl = worker_cfg.build_worker_verify_url(
            verify_link,
            origin=cdn_origin,
            worker_base=worker_base,
        )
        console.print(f"  [dim]Worker: {_truncate(wurl, 90)}[/dim]")
        try:
            r = _get(wurl)
            if r.status_code < 400:
                return True, f"worker / Tor (HTTP {r.status_code})"
            console.print(
                f"  [yellow]⚠[/yellow]  Worker returned HTTP {r.status_code}, trying direct URL…"
            )
        except Exception as exc:
            console.print(f"  [yellow]⚠[/yellow]  Worker error ({exc}), trying direct URL…")

    # 2) Direct bunny.net URL over Tor
    try:
        r2 = _get(verify_link)
        if r2.status_code < 400:
            return True, f"direct / Tor (HTTP {r2.status_code})"
        last_code = r2.status_code
    except Exception as exc:
        last_code = 0
        console.print(f"  [yellow]⚠[/yellow]  Direct Tor request error: {exc}")

    # 3) Rotate circuit and retry — still within Tor session, never clearnet
    console.print(
        f"  [yellow]⚠[/yellow]  Direct Tor returned HTTP {last_code}; "
        "rotating circuit and retrying…"
    )
    try:
        tor_module.rotate_ip(session)
    except Exception:
        pass
    try:
        r3 = _get(verify_link)
        if r3.status_code < 400:
            return True, f"direct / Tor (new circuit, HTTP {r3.status_code})"
        return False, f"direct / Tor (HTTP {r3.status_code} after circuit rotation)"
    except Exception as exc:
        return False, f"Tor request failed: {exc}"


# ─── Interactive shell helpers ──────────────────────────────────────────────────

def _render_pull_zone(i: int, row: dict) -> None:
    """Print a single pull-zone result in a clean, readable table row."""
    pid   = row.get("Id")   or row.get("id",   "")
    name  = row.get("Name") or row.get("name", "")
    origin = row.get("OriginUrl") or row.get("originUrl") or row.get("origin_url") or ""
    raw_hosts = row.get("Hostnames") or row.get("hostnames") or []

    # Extract only the .b-cdn.net system hostname values
    hostnames: list[str] = []
    for h in raw_hosts:
        if isinstance(h, dict):
            val = h.get("Value") or h.get("value") or ""
            if val:
                hostnames.append(val)
        elif isinstance(h, str) and h:
            hostnames.append(h)

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column(style="dim", no_wrap=True)
    t.add_column(style="white")
    if pid:
        t.add_row("id",      str(pid))
    if name:
        t.add_row("name",    name)
    if origin:
        t.add_row("origin",  origin)
    for h in hostnames:
        t.add_row("hostname", f"[bold cyan]{h}[/bold cyan]")
    console.print(f"\n  [bold][[{i}]][/bold]")
    console.print(t)


def _render_status(data: dict) -> None:
    """Print a compact account-status summary."""
    suspended       = data.get("Suspended", False)
    disabled        = data.get("AccountDisabled", False)
    email_verified  = data.get("EmailVerified", False)
    payments_off    = data.get("PaymentsDisabled", False)
    balance         = data.get("Balance", 0)
    trial_balance   = data.get("TrialBalance", 0)
    flags           = data.get("FeatureFlags") or []

    susp_str = "[bold red]SUSPENDED[/bold red]" if suspended else "[bold green]Active[/bold green]"
    dis_str  = " [red](AccountDisabled)[/red]" if disabled else ""
    ev_str   = "[green]✓ verified[/green]" if email_verified else "[red]✗ unverified[/red]"
    pay_str  = "[red]disabled[/red]" if payments_off else "[green]enabled[/green]"

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="dim", no_wrap=True)
    t.add_column()
    t.add_row("Status",   susp_str + dis_str)
    t.add_row("Email",    ev_str)
    t.add_row("Payments", pay_str)
    t.add_row("Balance",  f"${balance}  (trial ${trial_balance})")
    if flags:
        t.add_row("Flags", ", ".join(str(f) for f in flags))
    console.print(t)


# ─── Interactive shell ─────────────────────────────────────────────────────────

def _interactive_shell(
    session,
    jwt: str,
    email: str,
    mailbox: TempMailbox | None = None,
    *,
    inbox_session=None,
    api_key: str | None = None,
    cdn_origin: str | None = None,
) -> None:
    # Mutable origin — must be set before `cdn` will run
    _NO_ORIGIN = ""
    shell: dict = {
        "origin": (cdn_origin or _NO_ORIGIN).strip(),
        "api_key": api_key,
    }

    console.print(
        Panel(
            textwrap.dedent("""\
                [bold]Interactive commands[/bold] (type at the [bold]torbunny>[/bold] prompt)

                  [cyan]cdn[/cyan] [dim]N [URL][/dim]    — create N pull zones pointing at URL
                                  URL required; saves as current origin for this session
                  [cyan]origin[/cyan] [dim][URL][/dim]   — show or set the saved Origin URL
                  [cyan]status[/cyan]        — account suspension / payment / verification summary
                  [cyan]user[/cyan]          — full user profile table
                  [cyan]raw[/cyan]           — raw /user JSON
                  [cyan]apikey[/cyan]        — fetch and display the account API key
                  [cyan]inbox[/cyan]         — list emails in temp mailbox
                  [cyan]jwt[/cyan]           — print the current JWT token
                  [cyan]email[/cyan]         — print the registered email
                  [cyan]help[/cyan]          — show this help
                  [cyan]exit[/cyan]          — quit
            """),
            title="[bold green]torbunny shell[/bold green]",
            border_style="green",
        )
    )

    while True:
        try:
            cmd = Prompt.ask("[bold green]torbunny>[/bold green]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Bye.[/dim]")
            break

        if not cmd:
            continue

        parts = cmd.split()
        verb = parts[0].lower()

        if verb in ("exit", "quit", "q"):
            console.print("[dim]Bye.[/dim]")
            break

        elif verb == "status":
            with console.status("Fetching account status…"):
                try:
                    data = bunny_api.get_user(session, jwt)
                    _render_status(data)
                except BunnyAPIError as exc:
                    _err(str(exc))

        elif verb == "user":
            with console.status("Fetching user profile…"):
                try:
                    data = bunny_api.get_user(session, jwt)
                    _render_user(data)
                    # Always surface suspension inline
                    if data.get("Suspended"):
                        console.print("  [bold red]⚠  Account is SUSPENDED[/bold red]")
                    if data.get("AccountDisabled"):
                        console.print("  [bold red]⚠  Account is DISABLED[/bold red]")
                except BunnyAPIError as exc:
                    _err(str(exc))

        elif verb == "apikey":
            with console.status("Fetching API key…"):
                try:
                    key = bunny_api.get_api_key(session, jwt)
                    shell["api_key"] = key
                    console.print(f"  [bold]API Key:[/bold] [bold yellow]{key}[/bold yellow]")
                except BunnyAPIError as exc:
                    _err(str(exc))

        elif verb == "inbox":
            if not mailbox:
                _err("No temp mailbox attached to this session")
            else:
                _inbox_ses = inbox_session or session
                with console.status(f"Checking {mailbox.email}…"):
                    try:
                        msgs = mb.list_messages(_inbox_ses, mailbox)
                    except MailboxError as exc:
                        _err(str(exc))
                        msgs = []
                if not msgs:
                    console.print(f"  [dim]Inbox empty ({mailbox.email})[/dim]")
                else:
                    t = Table(
                        title=f"Inbox — {mailbox.email}",
                        box=box.SIMPLE,
                        header_style="bold magenta",
                    )
                    t.add_column("ID", style="dim", no_wrap=True)
                    t.add_column("From", style="cyan")
                    t.add_column("Subject", style="white")
                    t.add_column("Date", style="dim")
                    for m in msgs:
                        t.add_row(m.id, m.from_addr, m.subject, m.created_at)
                    console.print(t)

        elif verb == "raw":
            with console.status("Fetching user profile…"):
                try:
                    data = bunny_api.get_user(session, jwt)
                    console.print_json(json.dumps(data))
                except BunnyAPIError as exc:
                    _err(str(exc))

        elif verb == "jwt":
            console.print(f"[dim]{jwt}[/dim]")

        elif verb == "email":
            console.print(f"[cyan]{email}[/cyan]")

        elif verb == "origin":
            if len(parts) == 1:
                cur = shell["origin"] or "[dim](none set)[/dim]"
                console.print(f"  CDN origin: [cyan]{cur}[/cyan]")
            else:
                shell["origin"] = cmd.split(None, 1)[1].strip()
                _ok(f"Origin set → {shell['origin']}")

        elif verb == "cdn":
            # Syntax: cdn N [URL]  or  cdn [URL] (N=1 implied)
            # URL is required either inline or pre-set via `origin`.
            n = 1
            inline_url = ""

            # Parse args: first non-digit token (or after N) is the URL
            rest = parts[1:]
            if rest and rest[0].isdigit():
                n = max(1, int(rest[0]))
                rest = rest[1:]
            if rest:
                inline_url = rest[0]

            origin = inline_url or shell["origin"]

            if not origin or not origin.startswith("http"):
                _err(
                    "An origin URL is required.\n"
                    "  Usage: [bold]cdn N https://example.com[/bold]\n"
                    "  Or set it first: [bold]origin https://example.com[/bold]"
                )
                continue

            # Save for future `cdn` calls in this session
            if inline_url:
                shell["origin"] = inline_url

            # Resolve API key (cache it)
            key = shell["api_key"]
            if not key:
                with console.status("Fetching API key…"):
                    try:
                        key = bunny_api.get_api_key(session, jwt)
                        shell["api_key"] = key
                    except BunnyAPIError as exc:
                        _err(str(exc))

            if key:
                with console.status(f"Creating {n} pull zone(s) → {origin}…"):
                    try:
                        results = bunny_api.create_pull_zones_batch(
                            session, key, origin, n
                        )
                    except BunnyAPIError as exc:
                        _err(str(exc))
                        results = []
                for i, row in enumerate(results, start=1):
                    _render_pull_zone(i, row)

        elif verb in ("help", "?", "h"):
            console.print(
                "  [cyan]cdn N URL[/cyan] · [cyan]origin[/cyan] · [cyan]status[/cyan] · "
                "[cyan]user[/cyan] · [cyan]apikey[/cyan] · [cyan]inbox[/cyan] · "
                "[cyan]jwt[/cyan] · [cyan]email[/cyan] · [cyan]raw[/cyan] · [cyan]exit[/cyan]"
            )

        else:
            console.print(f"[yellow]Unknown command:[/yellow] {cmd!r}  (type [cyan]help[/cyan])")


# ─── Main flow ─────────────────────────────────────────────────────────────────

@click.command()
@click.option(
    "--no-verify-tor",
    is_flag=True,
    default=False,
    help="Skip the Tor connectivity check (useful for testing without Tor).",
)
@click.option(
    "--email",
    default=None,
    help="Use a specific email instead of a generated one.",
)
@click.option(
    "--password",
    default=None,
    help="Use a specific password instead of a generated one.",
)
@click.option(
    "--origin",
    "cdn_origin",
    default=worker_cfg.DEFAULT_ORIGIN,
    show_default=True,
    help="Origin URL for the worker email step and for CDN pull zones (same as dash ?origin=).",
)
@click.option(
    "--cdn-count",
    type=int,
    default=0,
    show_default=True,
    help="How many pull zones to create after login (0 = skip). Each gets this --origin.",
)
@click.option(
    "--worker-base",
    default=worker_cfg.DEFAULT_WORKER_BASE,
    show_default=True,
    help="Cloudflare Worker base URL for email verification (?mode=bunny&origin=&key=).",
)
@click.option(
    "--no-worker-verify",
    is_flag=True,
    default=False,
    help="Follow the raw confirmemail URL instead of wrapping it with --worker-base.",
)
@click.option(
    "--no-clearnet-verify",
    is_flag=True,
    default=False,
    help="(Legacy — all verification now goes through Tor; kept for backwards compat.)",
)
@click.option(
    "--mail-tm-fallback",
    "mail_tm_fallback",
    is_flag=True,
    default=False,
    hidden=True,  # mail.tm is now always tried automatically
    help="(Legacy — mail.tm is now tried automatically alongside 1secmail and mail.gw.)",
)
@click.option(
    "--guerrilla-fallback",
    "guerrilla_fallback",
    is_flag=True,
    default=False,
    help="Also try Guerrilla Mail (@guerrillamailblock.com etc.) — often blocked by signup forms.",
)
def main(
    no_verify_tor: bool,
    email: str | None,
    password: str | None,
    cdn_origin: str,
    cdn_count: int,
    worker_base: str,
    no_worker_verify: bool,
    no_clearnet_verify: bool,
    mail_tm_fallback: bool,
    guerrilla_fallback: bool,
) -> None:
    """Register a new bunny.net account over Tor and enter the interactive shell."""

    print_startup_banner(console)

    if cdn_count < 0:
        _err("--cdn-count must be >= 0")
        sys.exit(1)

    # ── 1 — Tor ────────────────────────────────────────────────────────────────
    _step(1, "Establishing Tor connection…")
    session = tor_module.build_session()

    # Separate clearnet session for inbox providers.
    # Mail services (1secmail, mail.gw, …) often block Tor exit nodes, but the
    # inbox address is randomly generated and has no link to the Tor/bunny identity.
    inbox_session = requests.Session()
    inbox_session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    })

    if no_verify_tor:
        console.print("  [yellow]⚠[/yellow]  Skipping Tor verification (--no-verify-tor)")
        exit_ip = "unknown"
    else:
        try:
            with console.status("Checking Tor exit node…"):
                exit_ip = tor_module.verify_tor(session)
            _ok(f"Tor is live  —  exit node [bold]{exit_ip}[/bold]")
        except RuntimeError as exc:
            _err(str(exc))
            sys.exit(1)

    # ── 2–8 retry loop ─────────────────────────────────────────────────────────
    # If the freshly-created account is suspended we rotate the Tor circuit,
    # ban the mailbox domain that was just used, and try again from step 2.
    MAX_ATTEMPTS = 5
    banned_domains: set[str] = set()
    jwt: str = ""
    creds = None
    mailbox = None
    user_data: dict = {}
    api_key: str | None = None
    attempt_no = 0

    while attempt_no < MAX_ATTEMPTS:
        attempt_no += 1
        if attempt_no > 1:
            console.print(
                f"\n[bold yellow]↻ Attempt {attempt_no}/{MAX_ATTEMPTS} "
                f"— rotating circuit, banned domains: {', '.join(sorted(banned_domains))}[/bold yellow]"
            )
            try:
                with console.status("Rotating Tor circuit…"):
                    new_ip, _ = tor_module.rotate_ip(session)
                _ok(f"New exit node  —  [bold]{new_ip}[/bold]")
            except Exception:
                pass

        # 2 — Temp mailbox (clearnet session — mail APIs often block Tor exits)
        _step(2, "Creating temporary inbox…")
        try:
            with console.status("Picking provider…"):
                mailbox = mb.create(
                    inbox_session,
                    allow_guerrilla_fallback=guerrilla_fallback,
                    banned_domains=banned_domains,
                )
            _ok(
                f"Inbox ready  —  [bold cyan]{mailbox.email}[/bold cyan] "
                f"[dim]({mailbox.provider})[/dim]"
            )
        except MailboxError as exc:
            _err(str(exc))
            sys.exit(1)

        # 3 — Credentials
        _step(3, "Generating credentials…")
        creds = generate_credentials()
        creds.email = email if email else mailbox.email
        if password:
            creds.password = password

        cred_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        cred_table.add_column(style="dim")
        cred_table.add_column(style="bold white")
        cred_table.add_row("Name",     f"{creds.first_name} {creds.last_name}")
        cred_table.add_row("Email",    creds.email)
        cred_table.add_row("Password", creds.password)
        console.print(cred_table)

        # 4 — Rotate Tor IP before first registration attempt
        if attempt_no == 1:
            _step(4, "Rotating Tor exit node…")
            try:
                with console.status("Requesting new Tor circuit (NEWNYM)…"):
                    old_for_rotate = exit_ip if not no_verify_tor else None
                    new_ip, rotate_warn = tor_module.rotate_ip(session, old_ip=old_for_rotate)
                _ok(f"New exit node  —  [bold]{new_ip}[/bold]")
                if rotate_warn:
                    console.print(f"  [yellow]⚠[/yellow]  {rotate_warn}")
            except RuntimeError as exc:
                _err(str(exc))
                sys.exit(1)

        # 5 — Register
        _step(5, "Registering account at api.bunny.net…")
        try:
            with console.status("Sending registration request…"):
                cookie = bunny_api.register(
                    session,
                    creds.email,
                    creds.password,
                    first_name=creds.first_name,
                    last_name=creds.last_name,
                )
            _ok("Account created")
            console.print(f"  [dim]Cookie: {_truncate(cookie, 60)}[/dim]")
        except BunnyAPIError as exc:
            _err(str(exc))
            sys.exit(1)

        # 6 — Email verification (clearnet session for inbox polling)
        _step(6, "Waiting for verification email…")
        try:
            with console.status(
                f"Polling [cyan]{mailbox.email}[/cyan] (up to 3 min)…"
            ) as poll_status:
                msg = mb.wait_for_message(
                    inbox_session,
                    mailbox,
                    subject_hint="verif",
                    sender_hint="bunny",
                    timeout=180.0,
                    poll_interval=6.0,
                    tick_callback=lambda p, n: poll_status.update(
                        f"Polling [cyan]{mailbox.email}[/cyan] — "
                        f"inbox check #{p} · {n} message(s) listed"
                    ),
                )
            _ok(f"Email received  —  subject: [italic]{msg.subject or '(no subject)'}[/italic]")

            verify_link = mb.find_verification_link(msg)
            if verify_link:
                console.print(f"  [dim]Link: {_truncate(verify_link, 80)}[/dim]")
                with console.status("Following verification link…"):
                    ok, detail = _verify_email_follow(
                        session,
                        verify_link,
                        no_worker_verify=no_worker_verify,
                        worker_base=worker_base,
                        cdn_origin=cdn_origin,
                        no_clearnet_verify=no_clearnet_verify,
                    )
                if ok:
                    _ok(f"Email verified  —  {detail}")
                else:
                    _err(f"Verification failed  —  {detail}")
            else:
                _err("Could not find a verification link in the email body")
                console.print(f"  [dim]Email subject: {msg.subject}[/dim]")
        except MailboxError as exc:
            _err(str(exc))
            console.print("  [yellow]⚠[/yellow]  Continuing without email verification")

        # 7 — Login / JWT
        _step(7, "Logging in — fetching JWT…")
        try:
            with console.status("Authenticating…"):
                jwt = bunny_api.get_jwt(session, creds.email, creds.password)
            _ok(f"JWT obtained  —  [dim]{_truncate(jwt, 50)}[/dim]")
        except BunnyAPIError as exc:
            _err(str(exc))
            sys.exit(1)

        # 8 — User info + suspension check
        _step(8, "Fetching user profile…")
        try:
            with console.status("GET /user…"):
                user_data = bunny_api.get_user(session, jwt)
            _render_user(user_data)
        except BunnyAPIError as exc:
            _err(str(exc))
            break  # can't determine suspension — proceed to shell anyway

        suspended = user_data.get("Suspended", False) or user_data.get("AccountDisabled", False)
        if suspended:
            domain_used = mailbox.domain if mailbox else ""
            console.print(
                f"  [bold red]⚠  Account suspended/disabled "
                f"(domain: [italic]{domain_used}[/italic])[/bold red]"
            )
            if domain_used:
                banned_domains.add(domain_used)
            if attempt_no < MAX_ATTEMPTS:
                console.print(
                    "  [yellow]↻  Automatically retrying with a fresh identity…[/yellow]"
                )
                continue  # back to top of while loop
            else:
                _err(f"All {MAX_ATTEMPTS} attempts resulted in suspension. Giving up.")
                sys.exit(1)
        else:
            _ok("Account is [bold green]active[/bold green]")
            _render_status(user_data)
            break  # success — exit retry loop

    # ── 9 — API key ────────────────────────────────────────────────────────────
    _step(9, "Fetching API key…")
    try:
        with console.status("GET /apikey…"):
            api_key = bunny_api.get_api_key(session, jwt)
        _ok(f"API Key: [bold yellow]{api_key}[/bold yellow]")
    except BunnyAPIError as exc:
        _err(str(exc))

    # ── 10 — CDN pull zones (optional batch) ───────────────────────────────────
    if cdn_count > 0:
        _step(10, f"Creating {cdn_count} CDN pull zone(s)…")
        if not api_key:
            _err("Cannot create pull zones without an API key")
        else:
            try:
                with console.status("POST /pullzone…"):
                    pz_results = bunny_api.create_pull_zones_batch(
                        session, api_key, cdn_origin, cdn_count
                    )
                _ok(f"Created {len(pz_results)} pull zone(s)")
                for i, row in enumerate(pz_results, start=1):
                    _render_pull_zone(i, row)
            except BunnyAPIError as exc:
                _err(str(exc))

    # ── 11 — Interactive shell ─────────────────────────────────────────────────
    console.print()
    _interactive_shell(
        session,
        jwt,
        creds.email if creds else "",
        mailbox,
        inbox_session=inbox_session,
        api_key=api_key,
        cdn_origin=cdn_origin,
    )


if __name__ == "__main__":
    main()
