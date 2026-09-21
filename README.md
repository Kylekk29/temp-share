# temp-share

Drop a folder, an HTML file, or a `.zip` on it → get a public URL. Links can expire, can be
password-locked, and can be **one-time** (they destroy themselves after the first visit).

Built to answer one need: *"I want to hand someone a folder right now, without setting up hosting."*

```
$ tshare ./hkdse-notes chemistry-rev --days 0
https://temp.example.com/chemistry-rev/
  1 files · 135672 bytes · never expires
```

---

## Features

| | |
|---|---|
| **Publish** | a directory, a single file, or a `.zip` (auto-extracted; a lone top-level folder inside the zip is flattened) |
| **Give it a name** | `temp.example.com/<slug>/`, your choice of slug |
| **Expiry** | default 7 days, any number of days, or `0` = never |
| **One-time links** | served once, then deleted from disk; later hits 404 |
| **Passwords** | optional per-link password (`sha256` + per-share salt) |
| **Visitor log** | per share: IP, coarse device label, path, timestamp, unique-IP count |
| **Static hosting rules** | a single `.html` in a share is served at `/<slug>/`; a folder without `index.html` gets a generated file listing |
| **Auto-cleanup** | a 15-second sweeper deletes expired and burned shares, and their files |
| **Two front doors** | a control panel (password + optional TOTP 2FA) and a `tshare` CLI |
| **One-click download** | any share can be pulled down as a zip straight from the panel |
| **Admin settings** | change password, enable/disable 2FA, sign out everywhere |
| **Self-hosted fonts** | Lato + JetBrains Mono ship in `static/fonts/` — no CDN, works offline |

## UI design system ("Flat Design Corporativo")

The panel, the login screen and the public share pages share one flat corporate language.
Everything lives in `static/style.css` — change it there, never inline.

| Token | Value |
|---|---|
| Primary / accent | Corporate Blue `#007BFF` |
| Surface (dark chrome) | Dark Grey `#343A40` |
| Page background | Light Grey `#F8F9FA` |
| Semantic | green `#28A745` · amber `#FFC107` · red `#DC3545` · cyan `#17A2B8` |
| Corner radius | `4px` everywhere (sharp corners by design) |
| Type | Lato 400/700/900, JetBrains Mono for metadata |
| Elevation | flat; never heavier than `0 2px 8px rgba(0,0,0,.08)` |
| Motion | transform + opacity only; `prefers-reduced-motion` respected |
| z-index | nav `100` · overlay `200` · modal `300` · toast `500` |

Rules: solid colours only (no decorative gradients), no emoji in the UI — inline SVG icons only,
no pure black, no 3-equal-column feature rows. The seed tokens (CSS variables) are declared once in
`:root` and referenced everywhere else.

## Quick start (local, 60 seconds)

```bash
git clone <repo> && cd temp-share
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
PORT=19011 python server.py
# → http://127.0.0.1:19011
```

Sign in with the password **`12345678`** — then change it immediately under **Settings**.
The panel stores a `scrypt` hash in `./.admin-password` (mode 600), never the password itself.
A separate `./.api-token` still exists for the `tshare` CLI and automation.

## Publish something

```bash
./tshare ./my-site                       # folder  → slug "my-site", 7 days
./tshare index.html demo                 # one file → slug "demo"
./tshare ./bundle.zip site   --days 3    # zip is extracted
./tshare ./secret  drop     --days 0 --once --pw hunter2
./tshare --list                          # what's live, who opened it
./tshare --del drop                      # remove it now
```

`tshare` is a thin wrapper over the HTTP API, so anything it does you can do with `curl`:

```bash
TOKEN=$(cat .api-token)
curl -X POST localhost:19011/api/shares \
  -H "X-Token: $TOKEN" \
  -F slug=demo -F days=7 -F local_path=/abs/path/to/folder
```

## How it works

```
            https://temp.example.com/<slug>/…
                        │
                  ┌─────▼──────┐
                  │   nginx    │  TLS · body limit · X-Forwarded-For
                  └─────┬──────┘
                        │ 127.0.0.1:19011
                  ┌─────▼──────┐
                  │  FastAPI   │  auth · publish · serve · expire
                  └─────┬──────┘
                        │
        data/shares.json │ storage/<slug>/…
```

The app binds to loopback only. nginx terminates TLS and forwards the visitor IP, which is what
makes the per-share visitor log possible. Nothing is exposed except through nginx.

### One-time link semantics

The subtle part. A "single use" link that dies on the *first byte* would break every page that
loads its own CSS, JS, or images. So:

| Step | Result |
|---|---|
| first navigation request | served; `burn_at = now + 30s` |
| sub-resources of that page | served inside the grace window |
| sweeper (every 15s) | `burn_at` passed → files + metadata deleted |
| anything later | `404` |

Only **navigation** requests consume the link: `Sec-Fetch-Dest` is checked first, with an `Accept`
fallback, and anything unidentifiable (curl, bots, API clients) is treated as a visit — it fails
safe toward burning rather than leaking a file forever.

### Expiry, honestly

Expiry is enforced by a sweeper, not a filesystem TTL, so a share can outlive its deadline by up
to one sweep interval (15s) if nobody requests it. That is deliberate: a failed sweep never takes
the service down, and the deadline is still checked on every read path (`is_expired` / `is_burned`),
so an expired link never serves content even before the sweeper runs.

## HTTP API

Admin routes need `X-Token: <token>` or the panel cookie.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | liveness + `shares` + `sweeper` state (no auth) |
| `POST` | `/api/login` | form `password` + optional `code` (TOTP); sets the session cookie |
| `POST` | `/api/logout` | end this session |
| `GET` | `/api/session` | is this browser signed in? is 2FA on? |
| `POST` | `/api/password` | form `current`, `new` (min 8 chars) |
| `POST` | `/api/2fa/setup` | mint a TOTP secret (`otpauth://` URL) |
| `POST` | `/api/2fa/enable` | form `secret`, `code` — verifies then switches 2FA on |
| `POST` | `/api/2fa/disable` | switch 2FA off |
| `GET` | `/api/shares/{slug}/download` | zip the share (or the single file) |
| `GET` | `/api/shares` | list shares, visitors, storage used |
| `POST` | `/api/shares` | publish (`slug?`, `title?`, `days`, `password?`, `once?`, `local_path?` **or** `file`) |
| `DELETE` | `/api/shares/{slug}` | delete the share **and its files** |
| `POST` | `/api/shares/{slug}/extend` | form `days`; push the deadline out |
| `POST` | `/api/sweep` | run cleanup now |
| `GET` | `/{slug}/{path}` | public: serve a share (password-gated when set) |

`POST /api/shares` accepts either `local_path` (server-side path, used by the CLI) or a multipart
`file` upload (used by the panel). `local_path` is authenticated, not remote input.

## Security

- **Path traversal** blocked: the resolved target must sit inside `storage/<slug>/`.
- **Zip-slip** blocked: every archive member is resolved and checked before extraction.
- **Passwords** are `sha256(salt + ":" + password)` with a per-share random salt — never stored raw.
- **Unsafe slugs** rejected (`^[a-z0-9][a-z0-9._-]{0,63}$`), duplicates return `409`.
- **Admin password** is stored as `scrypt(password, per-install salt)` — never reversible, never logged.
- **Sessions** are random 32-byte ids in `data/sessions.json` with a 30-day expiry, sent as an
  HttpOnly cookie; changing the password or signing out everywhere drops them.
- **2FA (optional)** is standards-compliant TOTP (RFC 6238, SHA-1, 6 digits, 30s) verified against
  the RFC test vectors, with one step of clock-drift tolerance. Stdlib only — no extra dependency.
- The `tshare` CLI authenticates with `.api-token` (mode 600), so automation never needs the password.
- Uploads are capped (`MAX_UPLOAD_MB`, default 800).

Known limits, stated plainly: no rate limiting on the password endpoint, no per-share bandwidth
accounting, and the visitor log trusts `X-Forwarded-For` (fine behind your own nginx, wrong behind
an untrusted proxy). File-sharing sites are also hotbeds of abuse — if this ever faces the public
internet with an open publish path, add auth on publish and abuse monitoring *before* that.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `PORT` | `19011` | listen port (loopback) |
| `MAX_UPLOAD_MB` | `800` | per-upload cap |
| `ONCE_GRACE_SECONDS` | `30` | how long a one-time link keeps serving assets |

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

43 tests, no network needed. Covers storage helpers, expiry/burn logic, one-time semantics,
navigation-vs-asset classification, password hashing + change flow, TOTP (against the RFC
vectors), traversal guards, zip-slip, downloads, and the visitor log.

## Deploy (systemd + nginx)

```bash
sudo cp deploy/temp-share.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now temp-share

sudo cp deploy/nginx.conf /etc/nginx/sites-available/temp-share
sudo ln -s /etc/nginx/sites-available/temp-share /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Point a DNS `A` record at the box and drop your certificate paths into the nginx file.
Both templates live in [`deploy/`](deploy/).

## Lessons baked into the code

1. **A single-file share must open the document at `/<slug>/`.** The first version showed a
   one-item file listing instead — a listing is a failure for a "throw a file at it" tool.
2. **A background task needs a strong reference and a heartbeat.** The sweeper was
   `asyncio.create_task(loop())` with no reference held; asyncio keeps only a weak one, so it
   could be garbage-collected and expire nothing while `/healthz` still said "ok". It now lives in
   a module global, logs every prune, and reports itself in `/healthz`.

## License

MIT — see [LICENSE](LICENSE).
