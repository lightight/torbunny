"""
Credential generator for torbunny registrations.

Goals:
  - Email local-parts that look like real humans typed them (name-derived,
    with plausible separators and digits).
  - A large, varied domain pool — not just the five giants; includes regional
    providers, older ISP webmail, and newer privacy-focused services.
  - Passwords that resemble human-chosen passwords (two words + number +
    punctuation) rather than random hex strings.
"""
from __future__ import annotations

import random
import re
import secrets
import string
from dataclasses import dataclass

from faker import Faker

_fake = Faker("en_US")


# ─── domain pool ──────────────────────────────────────────────────────────────
# Roughly 80 providers; weights skew toward realistic distribution.
_DOMAINS_COMMON = [
    # Big US providers — heavy weight
    "gmail.com", "gmail.com", "gmail.com",
    "yahoo.com", "yahoo.com",
    "outlook.com", "outlook.com",
    "hotmail.com",
    "icloud.com",
    "me.com",
    "live.com",
    "msn.com",
]

_DOMAINS_MID = [
    # Mid-tier / privacy / alt
    "protonmail.com",
    "proton.me",
    "tutanota.com",
    "tutamail.com",
    "fastmail.com",
    "fastmail.fm",
    "hushmail.com",
    "zoho.com",
    "zohomail.com",
    "mail.com",
    "email.com",
    "usa.com",
    "post.com",
    "techie.com",
    "asia.com",
    "contractor.net",
    "consultant.com",
    "engineer.com",
    "writeme.com",
    "cheerful.com",
    "eml.cc",
    "gmx.com",
    "gmx.net",
    "gmx.us",
    "gmx.de",
    "web.de",
    "t-online.de",
    "freenet.de",
    "arcor.de",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "inbox.ru",
    "bk.ru",
    "list.ru",
]

_DOMAINS_REGIONAL = [
    # English-speaking regional / ISP webmail
    "comcast.net",
    "cox.net",
    "att.net",
    "sbcglobal.net",
    "verizon.net",
    "charter.net",
    "roadrunner.com",
    "rocketmail.com",
    "bellsouth.net",
    "earthlink.net",
    "optonline.net",
    "windstream.net",
    "centurylink.net",
    "frontier.com",
    "rogers.com",
    "shaw.ca",
    "bell.net",
    "sympatico.ca",
    "telus.net",
    "bigpond.com",
    "bigpond.net.au",
    "optusnet.com.au",
    "internode.on.net",
    "xtra.co.nz",
    "paradise.net.nz",
    "btinternet.com",
    "btopenworld.com",
    "virgin.net",
    "virginmedia.com",
    "sky.com",
    "talktalk.net",
    "ntlworld.com",
    "orange.fr",
    "sfr.fr",
    "free.fr",
    "laposte.net",
    "wanadoo.fr",
    "neuf.fr",
    "libero.it",
    "tiscali.it",
    "tin.it",
    "virgilio.it",
    "terra.es",
    "telefonica.net",
    "ono.com",
    "yahoo.es",
    "yahoo.co.uk",
    "yahoo.co.in",
    "yahoo.com.au",
    "yahoo.com.br",
    "yahoo.fr",
    "yahoo.de",
    "yahoo.it",
    "rediffmail.com",
]

# Combined pool with weights: common 45%, mid 35%, regional 20%
def _pick_domain() -> str:
    r = random.random()
    if r < 0.45:
        return random.choice(_DOMAINS_COMMON)
    if r < 0.80:
        return random.choice(_DOMAINS_MID)
    return random.choice(_DOMAINS_REGIONAL)


# ─── password ingredients ─────────────────────────────────────────────────────

_NOUNS = [
    "Anchor", "Arrow", "Amber", "Aspen", "Atlas",
    "Birch", "Blaze", "Brook", "Boulder", "Blade",
    "Canyon", "Cedar", "Cloud", "Clover", "Cobalt",
    "Dawn", "Delta", "Drift", "Dusk", "Dagger",
    "Eagle", "Ember", "Echo",
    "Falcon", "Flint", "Frost", "Fern",
    "Gale", "Glen", "Gravel",
    "Harbor", "Haven", "Hawk", "Hazel",
    "Iron", "Ivory",
    "Jade", "Jasper",
    "Kestrel", "Knoll",
    "Lance", "Lark", "Laurel",
    "Maple", "Marsh", "Mesa", "Mist",
    "Noble", "North",
    "Oak", "Ocean",
    "Pebble", "Pine", "Peak",
    "Quartz", "Quest",
    "Raven", "Reed", "Ridge", "River", "Rock",
    "Sable", "Sage", "Serra", "Silver", "Slate", "Storm",
    "Stone", "Summit", "Sparrow",
    "Thorn", "Timber", "Tide",
    "Vale", "Veil",
    "Willow", "Wave", "Wren",
]

_ADJECTIVES = [
    "Brave", "Bold", "Bright", "Brisk",
    "Calm", "Crisp", "Clear", "Clever",
    "Dark", "Deep", "Deft",
    "Fast", "Fierce", "Fine",
    "Grand", "Gray", "Green",
    "High", "Hard",
    "Iron", "Icy",
    "Kind",
    "Light", "Long", "Lean",
    "Mellow", "Mighty",
    "North", "Noble",
    "Old",
    "Quick", "Quiet",
    "Rapid", "Red", "Rough",
    "Sharp", "Slim", "Smart", "Soft", "Swift",
    "Tall", "True",
    "Warm", "Wild", "Wise",
]

_SPECIALS = "!@#$%&*?"


@dataclass
class Credentials:
    email: str
    password: str
    first_name: str
    last_name: str


# ─── email generation ─────────────────────────────────────────────────────────

def _clean(s: str) -> str:
    """Lower-case, strip non-alphanumeric except dot/underscore/hyphen."""
    return re.sub(r"[^a-z0-9._-]", "", s.lower())


def _generate_email(first: str, last: str) -> str:
    """
    Build a realistic email local-part derived from the person's name.
    Avoids hex strings — everything traces back to the name.
    """
    f, l = _clean(first), _clean(last)
    year = random.randint(1978, 2003)
    short_year = str(year)[2:]
    digits2 = str(random.randint(1, 99)).zfill(2)
    digits3 = str(random.randint(100, 999))

    patterns = [
        f"{f}.{l}",
        f"{f}{l}",
        f"{f[0]}{l}",
        f"{f}.{l}{digits2}",
        f"{f}{l}{digits2}",
        f"{f[0]}{l}{digits2}",
        f"{f}.{l}.{short_year}",
        f"{f}{l}{short_year}",
        f"{f}_{l}",
        f"{f}-{l}",
        f"{f[0]}.{l}",
        f"{f[0]}_{l}",
        f"{f}{digits3}",
        f"{f}.{digits2}{l}",
        f"{l}{f[0]}{digits2}",
        f"{l}.{f}",
        f"{l}{f}",
        f"{f[0]}{f[1:][:3]}{l[:4]}{digits2}",  # compact e.g. "jsmit42"
    ]

    local = random.choice(patterns)[:64]
    domain = _pick_domain()
    return f"{local}@{domain}"


# ─── password generation ──────────────────────────────────────────────────────

def _generate_password(first: str, last: str) -> str:
    """
    Human-chosen password style.  Several templates, all anchored partly in the
    person's name so the password looks like something they'd actually pick.
    Never a random hex string.
    """
    f = first.capitalize()
    l = last.capitalize()
    noun = random.choice(_NOUNS)
    adj = random.choice(_ADJECTIVES)
    yr = random.randint(1991, 2019)
    n2 = str(random.randint(10, 99))
    n3 = str(random.randint(100, 999))
    sp = random.choice(_SPECIALS)

    # 8 distinct templates
    templates = [
        f"{f}{noun}{n2}{sp}",           # JohnEagle42!
        f"{adj}{l}{n2}{sp}",            # BraveSmith73@
        f"{noun}{n2}{sp}{f[:3]}",       # Cedar27#Joh
        f"{f[:3]}{noun}{sp}{yr}",       # JohFalcon!2004
        f"{adj}{noun}{sp}{n2}",         # SwiftRaven@55
        f"{f}{n3}{sp}{noun[:4]}",       # John847!Eagl
        f"{noun}{l[:4]}{sp}{n2}",       # EagleSmit#31
        f"{adj}{yr}{sp}{f}",            # Bold2008@John
    ]
    pwd = random.choice(templates)

    # Enforce all four character classes
    has_up = any(c.isupper() for c in pwd)
    has_lo = any(c.islower() for c in pwd)
    has_di = any(c.isdigit() for c in pwd)
    has_sp = any(c in _SPECIALS for c in pwd)
    if not has_up:
        pwd = pwd[0].upper() + pwd[1:]
    if not has_lo:
        pwd += "x"
    if not has_di:
        pwd += "3"
    if not has_sp:
        pwd += "!"

    # Keep length sensible (10–20)
    if len(pwd) > 20:
        pwd = pwd[:19] + sp
    if len(pwd) < 10:
        pwd += n3

    return pwd


# ─── public API ───────────────────────────────────────────────────────────────

def generate_credentials() -> Credentials:
    first = _fake.first_name()
    last = _fake.last_name()
    email = _generate_email(first, last)
    password = _generate_password(first, last)
    return Credentials(email=email, password=password, first_name=first, last_name=last)
