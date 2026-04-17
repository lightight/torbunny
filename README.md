# torbunny

> **Warning:** this is one of my very few ai generated projects because i wanted to make this quick. do not use this if you
>
> A. Are against AI code use
>
> B. Prefer security, reliability, and safety
>
> C. Don't like to use unmonitored/unread code

Register and manage [bunny.net](https://bunny.net) CDN accounts over Tor from a Python CLI.  
All traffic to bunny.net is routed through Tor. Inbox polling uses a separate clearnet session (mail APIs block Tor exits).

---

## What it does


| Step | Action                                                                    |
| ---- | ------------------------------------------------------------------------- |
| 1    | Establish Tor connection, verify exit node                                |
| 2    | Create a disposable inbox (mail.gw or mail.tm, shuffled)                  |
| 3    | Generate realistic name / email / password credentials                    |
| 4    | Rotate Tor circuit (new exit IP before registering)                       |
| 5    | Register account at `api.bunny.net/auth/register`                         |
| 6    | Poll inbox for the verification email, follow the confirm link via Tor    |
| 7    | Log in via `api.bunny.net/auth/jwt` for a JWT token                       |
| 8    | Fetch `/user` — auto-detects suspension and retries with a fresh identity |
| 9    | Fetch API key from `/apikey`                                              |
| 10   | (Optional) Create CDN pull zones in batch                                 |
| 11   | Drop into an interactive shell                                            |


If the account comes back **suspended**, torbunny automatically bans that inbox domain, rotates the Tor circuit, and restarts from step 2 — up to 5 attempts.

---

## Requirements

- Python **3.10+**
- Tor running on `127.0.0.1:9050`
- (Optional) Tor control port on `127.0.0.1:9051` for circuit rotation

---

## Installation

### 1 — Install Tor

#### macOS (Homebrew)

```bash
brew install tor
```

Enable the control port (needed for IP rotation):

```
# /opt/homebrew/etc/tor/torrc
ControlPort 9051
CookieAuthentication 0
```

```bash
brew services restart tor
```

#### Linux (Debian / Ubuntu)

```bash
sudo apt update && sudo apt install tor
```

Enable the control port:

```
# /etc/tor/torrc
ControlPort 9051
CookieAuthentication 0
```

```bash
sudo systemctl restart tor
```

#### Windows

Download the **Tor Expert Bundle** (not Tor Browser) from [torproject.org/download/tor](https://www.torproject.org/download/tor/).  
Extract it, then create/edit `torrc` in the same folder as `tor.exe`:

```
# torrc
SocksPort 9050
ControlPort 9051
CookieAuthentication 0
```

Run Tor:

```cmd
tor.exe -f torrc
```

Or add it as a Windows service with `tor.exe --service install -options -f torrc`.

---

### 2 — Set up Python environment

#### macOS / Linux

```bash
git clone https://github.com/lightight/torbunny
cd torbunny
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### Windows (Command Prompt)

```cmd
git clone https://github.com/lightight/torbunny
cd torbunny
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

#### Windows (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> If you get an execution-policy error: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

---

### 3 — Run

```bash
python main.py
```

---

## CLI Options

```
Options:
  --email TEXT          Use a specific email instead of a generated one
  --password TEXT       Use a specific password instead of a generated one
  --origin URL          Origin URL for CDN pull zones (default: https://realvoid.xyz)
  --cdn-count N         Create N pull zones automatically after login (default: 0)
  --worker-base URL     Cloudflare Worker base URL for email verification
  --no-worker-verify    Follow the raw confirmemail URL instead of the worker
  --no-verify-tor       Skip the Tor connectivity check (testing only)
  --guerrilla-fallback  Also try Guerrilla Mail as a last-resort inbox provider
  --help                Show this message and exit
```

---

## Interactive Shell

After registration you enter the `torbunny>` shell:


| Command                    | Description                                                         |
| -------------------------- | ------------------------------------------------------------------- |
| `cdn N https://origin.com` | Create N CDN pull zones pointing at the given origin                |
| `origin [URL]`             | Show or set the saved CDN origin URL                                |
| `status`                   | Quick account status: suspended / active / payment / email verified |
| `user`                     | Full user profile table                                             |
| `raw`                      | Raw `/user` JSON                                                    |
| `apikey`                   | Fetch and print the account API key                                 |
| `inbox`                    | List messages in the temp inbox                                     |
| `jwt`                      | Print the current JWT token                                         |
| `email`                    | Print the registered email address                                  |
| `help`                     | Show available commands                                             |
| `exit`                     | Quit                                                                |


### Examples

```
torbunny> status
torbunny> cdn 3 https://mysite.com
torbunny> origin https://mysite.com
torbunny> cdn 2
torbunny> apikey
torbunny> inbox
```

### Pull zone output

```
  [[1]]
   id       5700011
   name     torbunny-c0c4c415-1
   origin   https://mysite.com
   hostname torbunny-c0c4c415-1.b-cdn.net
```

---

## Suspension retry

If bunny.net flags the account as suspended immediately after creation, torbunny:

1. Bans the inbox domain used (e.g. `teihu.com`)
2. Rotates the Tor exit circuit
3. Creates a fresh inbox from a different domain
4. Re-generates credentials and registers a new account
5. Repeats up to **5 times**

```
  ⚠  Account suspended/disabled (domain: teihu.com)
  ↻  Automatically retrying with a fresh identity…

↻ Attempt 2/5 — rotating circuit, banned domains: teihu.com
[2] Creating temporary inbox…
  ✓ Inbox ready — walters84@dcctb.com (mail.gw)
```

---

## Tips To Stop Getting Suspended Easily

bunny.net will often flag accounts automatically suspended upon suspicious behavior. This suspicious behavior may be

1. Using the same tor ip

2. Using the same email domain

3. Using the same domain for cdn url generation

Always double check these to ensure that you won't get suspended as quickly on their platform

---

## File structure

```
torbunny/
├── main.py          CLI entry point, registration flow, interactive shell
├── banner.py        PNG → ASCII banner (Pillow) + loads banner_logo.txt cache
├── assets/
│   ├── torbunny.png   Source logo (replace with your PNG)
│   └── banner_logo.txt  Optional pre-rendered ASCII (from tools/png_to_ascii.py)
├── tools/
│   └── png_to_ascii.py  Regenerate banner_logo.txt from the PNG
├── tor.py           Tor session builder, connectivity check, circuit rotation
├── api.py           bunny.net API (register, JWT, user, apikey, pull zones)
├── mailbox.py       Disposable inbox providers (mail.gw, mail.tm, Guerrilla)
├── generator.py     Realistic name / email / password generation (~80 domains)
├── worker.py        Cloudflare Worker URL builder for email verification
├── requirements.txt Python dependencies
├── LICENSE          Apache License 2.0
├── NOTICE           Copyright / Apache boilerplate
└── README.md
```

---

## Troubleshooting

### `Cannot connect to Tor`

Tor is not running. Start it:

- macOS: `brew services start tor`
- Linux: `sudo systemctl start tor`
- Windows: run `tor.exe -f torrc` in the Expert Bundle folder

### `Exit IP did not change after NEWNYM`

The control port is unavailable or the Tor exit pool is small.  
Add `ControlPort 9051` to `torrc` and restart Tor.

### `mail.gw: 502 Bad Gateway`

mail.gw has transient upstream errors — torbunny retries automatically (up to 6 times with backoff). If it persists, run again; the shuffled provider order may pick mail.tm instead.

### `MailboxError: … inbox fetch failed (HTTP 403)`

The inbox provider is blocking automated access. This is caught and torbunny continues without email verification (the account may still work for API operations).

### Windows — `No module named 'socks'`

PySocks was not installed. Run `pip install requests[socks]` inside your virtual environment.

### Windows — colours not rendering

Make sure you are using Windows Terminal, PowerShell 7+, or any modern terminal emulator. The legacy `cmd.exe` console has limited ANSI support; Rich handles it automatically where possible.

---

## License

Licensed under the **[Apache License, Version 2.0](LICENSE)**. See [`NOTICE`](NOTICE) for the copyright line and short boilerplate. Section 7 (*Disclaimer of Warranty*) and Section 8 (*Limitation of Liability*) describe how liability is limited; read the full license for complete terms.
