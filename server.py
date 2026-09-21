#!/usr/bin/env python3
"""temp-share — throw a folder / HTML at it, get a temporary public URL.

Kyle's throwaway sharing host.  https://temp.kylekaihin.org/<slug>/
- publish a local folder, a zip, or loose files
- optional password + auto-expiry (default 7 days)
- auto-prunes expired shares, newest first listing in the panel
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import shutil
import struct
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
STORAGE = BASE / "storage"
TMP = BASE / "tmp"
SHARES_FILE = DATA / "shares.json"
TOKEN_FILE = BASE / ".api-token"
PORT = int(os.environ.get("PORT", "19011"))
HKT = timezone(timedelta(hours=8))
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "800"))
ONCE_GRACE_SECONDS = int(os.environ.get("ONCE_GRACE_SECONDS", "30"))
PASSWORD_FILE = BASE / ".admin-password"
TOTP_FILE = BASE / ".admin-2fa"
SESSION_FILE = DATA / "sessions.json"
SESSION_DAYS = 30
DEFAULT_PASSWORD = "12345678"
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
DEFAULT_DOCS = ["index.html", "index.htm", "Index.html"]

for d in (DATA, STORAGE, TMP):
    d.mkdir(parents=True, exist_ok=True)

if not TOKEN_FILE.exists():
    TOKEN_FILE.write_text(secrets.token_urlsafe(24), encoding="utf-8")
    TOKEN_FILE.chmod(0o600)
TOKEN = TOKEN_FILE.read_text(encoding="utf-8").strip()


# ---------------------------------------------------------------- storage ---
def _now() -> datetime:
    return datetime.now(HKT)


def load() -> dict:
    if not SHARES_FILE.exists():
        return {}
    try:
        return json.loads(SHARES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save(data: dict) -> None:
    tmp = SHARES_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(SHARES_FILE)


def hash_pw(password: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


def dir_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def is_expired(meta: dict) -> bool:
    exp = meta.get("expires_at")
    if not exp:
        return False
    return datetime.fromisoformat(exp) < _now()


def is_burned(meta: dict) -> bool:
    """True once a one-time link's grace window has passed."""
    burn = meta.get("burn_at")
    if not burn:
        return False
    return datetime.fromisoformat(burn) <= _now()


SUBRESOURCE_DESTS = {
    "style", "script", "image", "font", "audio", "video",
    "manifest", "object", "embed", "track", "empty",
}


def counts_as_visit(request: Request) -> bool:
    """Is this a top-level page view, or just an asset the page pulled in?

    A one-time link must survive long enough for the page's own css/img/js to
    load, so only navigation requests consume it.  Anything we cannot positively
    identify as a sub-resource (curl, bots, api clients) counts as a visit.
    """
    dest = request.headers.get("sec-fetch-dest")
    if dest:
        return dest not in SUBRESOURCE_DESTS
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return True
    # a concrete media type (image/png, */*;q=0.8 …) means a sub-resource;
    # a bare "*/*" is what curl and API clients send, so that counts as a visit
    for part in accept.split(","):
        mime = part.split(";")[0].strip()
        if "/" in mime and mime != "*/*":
            return False
    return True


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        ip = fwd.split(",")[0].strip()
    else:
        real = request.headers.get("x-real-ip")
        ip = real.strip() if real else (request.client.host if request.client else "?")
    # normalise IPv4-mapped IPv6 (::ffff:1.2.3.4) so the same visitor is one row
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip


def describe_ua(ua: str) -> str:
    """Short human label: 'Chrome · Android', 'Safari · iPhone', 'curl' ..."""
    if not ua:
        return "unknown"
    low = ua.lower()
    if "curl" in low:
        return "curl"
    if "wget" in low:
        return "wget"
    if "python" in low or "httpx" in low or "aiohttp" in low:
        return "script"
    if "postman" in low:
        return "Postman"
    if "iphone" in low and "safari" not in low and "crios" not in low:
        return "iPhone (app)"
    if "android" in low and "chrome" not in low and "firefox" not in low:
        return "Android (app)"
    if "bot" in low or "spider" in low or "crawler" in low or "facebookexternalhit" in low:
        return "bot"
    os_ = ""
    for key, name in (
        ("iphone", "iPhone"), ("ipad", "iPad"), ("android", "Android"),
        ("mac os", "macOS"), ("windows", "Windows"), ("linux", "Linux"),
    ):
        if key in low:
            os_ = name
            break
    browser = ""
    for key, name in (
        ("edg/", "Edge"), ("opr/", "Opera"), ("chrome/", "Chrome"),
        ("firefox/", "Firefox"), ("safari/", "Safari"),
    ):
        if key in low:
            browser = name
            break
    if browser and os_:
        return f"{browser} · {os_}"
    if browser:
        return browser
    if os_:
        return os_
    return "unknown"


def record_visit(meta: dict, request: Request, path: str) -> None:
    ip = client_ip(request)
    visits = meta.setdefault("visits", [])
    visits.append(
        {
            "t": _now().isoformat(timespec="seconds"),
            "ip": ip,
            "ua": describe_ua(request.headers.get("user-agent", "")),
            "path": "/" + path.strip("/"),
            "ref": (request.headers.get("referer") or "")[:120],
        }
    )
    del visits[:-30]  # keep the 30 most recent
    ips = meta.setdefault("ips", [])
    if ip not in ips:
        ips.append(ip)


def prune() -> list[str]:
    data = load()
    dead = [s for s, m in data.items() if is_expired(m) or is_burned(m)]
    if dead:
        for slug in dead:
            shutil.rmtree(STORAGE / slug, ignore_errors=True)
            data.pop(slug, None)
        save(data)
    return dead


# ------------------------------------------------------------------- app ----
app = FastAPI(title="temp-share")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


# ------------------------------------------------------------- credentials --
def hash_password(password: str, salt: str) -> str:
    """scrypt hash — deliberately slow, unlike a single-round sha256."""
    dk = hashlib.scrypt(password.encode(), salt=salt.encode(), n=2 ** 14, r=8, p=1, dklen=32)
    return dk.hex()


def load_password_hash() -> Optional[str]:
    if not PASSWORD_FILE.exists():
        set_password(DEFAULT_PASSWORD)
    return PASSWORD_FILE.read_text(encoding="utf-8").strip() or None


def set_password(new: str) -> None:
    salt = secrets.token_hex(16)
    PASSWORD_FILE.write_text(f"scrypt${salt}${hash_password(new, salt)}", encoding="utf-8")
    PASSWORD_FILE.chmod(0o600)


def check_password(password: str) -> bool:
    stored = load_password_hash()
    if not stored:
        return False
    try:
        _algo, salt, digest = stored.split("$")
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt), digest)


# ------------------------------------------------------------------- 2fa ----
def totp_secret() -> Optional[str]:
    if not TOTP_FILE.exists():
        return None
    return TOTP_FILE.read_text(encoding="utf-8").strip() or None


def totp_now(secret: str, at: Optional[int] = None) -> str:
    """RFC 6238 TOTP: base32 secret, 6 digits, 30s step. Stdlib only."""
    if at is None:
        at = int(time.time())
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8), casefold=True)
    counter = struct.pack(">Q", at // 30)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def check_totp(code: str) -> bool:
    secret = totp_secret()
    if not secret:
        return True  # 2FA not enabled
    now = int(time.time())
    return any(
        hmac.compare_digest(totp_now(secret, now + drift), code.strip())
        for drift in (-30, 0, 30)  # tolerate one step of clock drift
    )


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


# ---------------------------------------------------------------- sessions --
def _load_sessions() -> dict:
    if not SESSION_FILE.exists():
        return {}
    try:
        return json.loads(SESSION_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_sessions(data: dict) -> None:
    now = _now()
    data = {k: v for k, v in data.items() if datetime.fromisoformat(v) > now}
    tmp = SESSION_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(SESSION_FILE)


def make_session(username: str) -> str:
    sid = secrets.token_urlsafe(24)
    sessions = _load_sessions()
    sessions[f"{username}:{sid}"] = (_now() + timedelta(days=SESSION_DAYS)).isoformat(timespec="seconds")
    _save_sessions(sessions)
    return sid


def session_user(request: Request) -> Optional[str]:
    raw = request.cookies.get("ts_session")
    if not raw:
        return None
    for key, expiry in _load_sessions().items():
        user, _sep, sid = key.partition(":")
        if sid == raw and datetime.fromisoformat(expiry) > _now():
            return user
    return None


def drop_session(request: Request) -> None:
    raw = request.cookies.get("ts_session")
    sessions = _load_sessions()
    for key in [k for k in sessions if k.endswith(f":{raw}")]:
        sessions.pop(key, None)
    _save_sessions(sessions)


def authed(request: Request, token: Optional[str]) -> bool:
    """The CLI/token path still works; the panel uses a session cookie."""
    if request.headers.get("x-token") == TOKEN:
        return True
    if request.headers.get("authorization") == f"Bearer {TOKEN}":
        return True
    return session_user(request) is not None


def require_auth(request: Request) -> None:
    if not authed(request, request.query_params.get("token")):
        raise HTTPException(status_code=401, detail="auth required")


_sweeper: asyncio.Task | None = None


@app.on_event("startup")
async def _startup() -> None:
    global _sweeper
    prune()

    async def loop() -> None:
        while True:
            await asyncio.sleep(15)
            try:
                dead = prune()
                if dead:
                    print(f"[temp-share] pruned {len(dead)} share(s): {', '.join(dead)}", flush=True)
            except Exception as exc:  # never let the sweeper die
                print(f"[temp-share] sweep error: {exc!r}", flush=True)

    # hold a strong reference — the loop only keeps a weak one, so a bare
    # create_task() can be garbage-collected and silently stop running
    _sweeper = asyncio.create_task(loop())


@app.get("/healthz")
def healthz() -> dict:
    return {
        "ok": True,
        "shares": len(load()),
        "sweeper": bool(_sweeper and not _sweeper.done()),
        "time": _now().isoformat(),
    }


@app.post("/api/sweep")
def force_sweep(request: Request) -> JSONResponse:
    """Run the expiry/burn sweep now (auth required)."""
    require_auth(request)
    dead = prune()
    return JSONResponse({"ok": True, "pruned": dead})


# ------------------------------------------------------------------ admin ---
@app.post("/api/login")
def login(
    username: str = Form("admin"),
    password: str = Form(...),
    code: str = Form(""),
) -> JSONResponse:
    if not check_password(password):
        raise HTTPException(status_code=401, detail="wrong password")
    if not check_totp(code):
        raise HTTPException(status_code=401, detail="wrong 2FA code")
    sid = make_session("admin")
    resp = JSONResponse({"ok": True, "twofa": bool(totp_secret())})
    resp.set_cookie("ts_session", sid, max_age=86400 * SESSION_DAYS, httponly=True, samesite="lax")
    return resp


@app.post("/api/logout")
def logout(request: Request) -> JSONResponse:
    drop_session(request)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("ts_session")
    return resp


@app.get("/api/session")
def session_info(request: Request) -> JSONResponse:
    user = session_user(request)
    return JSONResponse(
        {
            "ok": True,
            "authenticated": user is not None,
            "user": user,
            "twofa": bool(totp_secret()),
        }
    )


@app.post("/api/password")
def change_password(
    request: Request,
    current: str = Form(...),
    new: str = Form(...),
) -> JSONResponse:
    require_auth(request)
    if not check_password(current):
        raise HTTPException(403, "current password is wrong")
    if len(new) < 8:
        raise HTTPException(400, "new password must be at least 8 characters")
    set_password(new)
    return JSONResponse({"ok": True, "message": "password updated"})


@app.post("/api/2fa/setup")
def twofa_setup(request: Request) -> JSONResponse:
    require_auth(request)
    secret = new_totp_secret()
    url = f"otpauth://totp/temp-share:admin?secret={secret}&issuer=temp-share&digits=6&period=30"
    return JSONResponse({"ok": True, "secret": secret, "otpauth_url": url})


@app.post("/api/2fa/enable")
def twofa_enable(request: Request, secret: str = Form(...), code: str = Form(...)) -> JSONResponse:
    require_auth(request)
    if not hmac.compare_digest(totp_now(secret), code.strip()):
        raise HTTPException(400, "code does not match the secret")
    TOTP_FILE.write_text(secret, encoding="utf-8")
    TOTP_FILE.chmod(0o600)
    return JSONResponse({"ok": True, "message": "2FA enabled"})


@app.post("/api/2fa/disable")
def twofa_disable(request: Request) -> JSONResponse:
    require_auth(request)
    TOTP_FILE.unlink(missing_ok=True)
    return JSONResponse({"ok": True, "message": "2FA disabled"})


@app.get("/api/shares")
def list_shares(request: Request) -> JSONResponse:
    require_auth(request)
    data = load()
    items = []
    for slug, m in data.items():
        items.append(
            {
                "slug": slug,
                "title": m.get("title", slug),
                "url": f"https://temp.kylekaihin.org/{slug}/",
                "created_at": m.get("created_at"),
                "expires_at": m.get("expires_at"),
                "size": m.get("size", 0),
                "size_human": human(m.get("size", 0)),
                "files": m.get("files", 0),
                "password": bool(m.get("pw_hash")),
                "once": bool(m.get("once")),
                "burned": is_burned(m),
                "hits": m.get("hits", 0),
                "unique_ips": len(m.get("ips", [])),
                "visits": m.get("visits", [])[-10:],
                "kind": m.get("kind", "folder"),
                "download_url": f"/api/shares/{slug}/download",
            }
        )
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return JSONResponse({"ok": True, "shares": items, "storage": human(dir_size(STORAGE))})


@app.post("/api/shares")
def create_share(
    request: Request,
    slug: Optional[str] = Form(None),
    title: Optional[str] = Form(None),
    days: int = Form(7),
    password: Optional[str] = Form(None),
    once: bool = Form(False),
    local_path: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
) -> JSONResponse:
    require_auth(request)
    data = load()

    raw = (slug or "").strip().lower() or f"share-{secrets.token_hex(3)}"
    if not SLUG_RE.match(raw):
        raise HTTPException(400, "slug must be a-z0-9._- (max 64)")
    if raw in data:
        raise HTTPException(409, f"slug '{raw}' already exists")

    dest = STORAGE / raw
    dest.mkdir(parents=True, exist_ok=True)
    kind = "folder"

    if file is not None and getattr(file, "filename", ""):
        safe = Path(file.filename or "upload.bin").name
        tmpf = TMP / f"{secrets.token_hex(8)}-{safe}"
        size = 0
        with tmpf.open("wb") as fh:
            while chunk := file.file.read(1 << 20):
                size += len(chunk)
                if size > MAX_UPLOAD_MB << 20:
                    fh.close()
                    tmpf.unlink(missing_ok=True)
                    shutil.rmtree(dest, ignore_errors=True)
                    raise HTTPException(413, f"upload exceeds {MAX_UPLOAD_MB}MB")
                fh.write(chunk)
        if safe.lower().endswith(".zip"):
            kind = "zip"
            with zipfile.ZipFile(tmpf) as zf:
                for member in zf.namelist():
                    target = (dest / member).resolve()
                    if not str(target).startswith(str(dest.resolve())):
                        raise HTTPException(400, "unsafe zip member path")
                zf.extractall(dest)
            tmpf.unlink(missing_ok=True)
            # single top folder in zip -> flatten so the URL is clean
            entries = [p for p in dest.iterdir() if not p.name.startswith("__MACOSX")]
            if len(entries) == 1 and entries[0].is_dir():
                inner = entries[0]
                for child in inner.iterdir():
                    child.rename(dest / child.name)
                inner.rmdir()
        else:
            kind = "file"
            tmpf.replace(dest / safe)
    elif local_path:
        src = Path(local_path).expanduser().resolve()
        if not src.exists():
            raise HTTPException(404, f"local_path not found: {src}")
        if src.is_file():
            kind = "file"
            shutil.copy2(src, dest / src.name)
        else:
            kind = "folder"
            shutil.copytree(src, dest, dirs_exist_ok=True)
    else:
        raise HTTPException(400, "provide file or local_path")

    meta = {
        "slug": raw,
        "title": title or raw,
        "kind": kind,
        "created_at": _now().isoformat(timespec="seconds"),
        "expires_at": (_now() + timedelta(days=max(days, 0))).isoformat(timespec="seconds") if days else None,
        "size": dir_size(dest),
        "files": sum(1 for p in dest.rglob("*") if p.is_file()),
        "pw_hash": None,
        "pw_salt": None,
        "once": bool(once),
        "burn_at": None,
        "hits": 0,
    }
    if password:
        salt = secrets.token_hex(8)
        meta["pw_salt"] = salt
        meta["pw_hash"] = hash_pw(password, salt)
    data[raw] = meta
    save(data)
    return JSONResponse({"ok": True, "url": f"https://temp.kylekaihin.org/{raw}/", "meta": meta})


@app.delete("/api/shares/{slug}")
def delete_share(slug: str, request: Request) -> JSONResponse:
    require_auth(request)
    data = load()
    if slug not in data:
        raise HTTPException(404, "no such slug")
    shutil.rmtree(STORAGE / slug, ignore_errors=True)
    data.pop(slug)
    save(data)
    return JSONResponse({"ok": True, "deleted": slug})


@app.get("/api/shares/{slug}/download")
def download_share(slug: str, request: Request) -> Response:
    """One-click download: stream the share out, as a zip when it is a folder."""
    require_auth(request)
    data = load()
    meta = data.get(slug)
    if not meta:
        raise HTTPException(404, "no such slug")
    root = STORAGE / slug
    if not root.exists():
        raise HTTPException(404, "files are gone")

    files = [p for p in sorted(root.rglob("*")) if p.is_file()]
    if len(files) == 1:
        only = files[0]
        return Response(
            content=only.read_bytes(),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{only.name}"'},
        )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in files:
            zf.write(p, p.relative_to(root))
    stamp = _now().strftime("%Y%m%d-%H%M")
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{slug}-{stamp}.zip"'},
    )


@app.post("/api/shares/{slug}/extend")
def extend_share(slug: str, request: Request, days: int = Form(7)) -> JSONResponse:
    require_auth(request)
    data = load()
    if slug not in data:
        raise HTTPException(404, "no such slug")
    base = _now()
    cur = data[slug].get("expires_at")
    if cur:
        cur_dt = datetime.fromisoformat(cur)
        if cur_dt > base:
            base = cur_dt
    data[slug]["expires_at"] = (base + timedelta(days=days)).isoformat(timespec="seconds")
    save(data)
    return JSONResponse({"ok": True, "expires_at": data[slug]["expires_at"]})


# --------------------------------------------------------------- browsing ---
# Inline SVG icons for the server-rendered pages (flat corporate set, 24x24 grid).
_ICON_FOLDER = ('<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
                'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/></svg>')
_ICON_FILE = ('<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
              'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/></svg>')
_ICON_BACK = ('<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
              'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 19-7-7 7-7"/><path d="M19 12H5"/></svg>')
_ICON_LOCK = ('<svg class="i lg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
              'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>')
_PAGE_HEAD = ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="robots" content="noindex,nofollow">
<title>{title}</title><link rel="stylesheet" href="/static/style.css"></head>""")


def listing(path: Path, slug: str, rel: str) -> str:
    rows = []
    entries = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    if rel:
        parent = "/".join(rel.strip("/").split("/")[:-1])
        href = f"/{slug}/{parent + '/' if parent else ''}"
        rows.append(f'<li class="up"><a href="{html.escape(href)}">{_ICON_BACK}Back</a></li>')
    for p in entries:
        if p.name.startswith("."):
            continue
        name = p.name + ("/" if p.is_dir() else "")
        href = f"/{slug}/{(rel + '/' if rel else '')}{p.name}" + ("/" if p.is_dir() else "")
        icon = _ICON_FOLDER if p.is_dir() else _ICON_FILE
        size = "" if p.is_dir() else f'<span class="sz">{human(p.stat().st_size)}</span>'
        rows.append(f'<li><a href="{html.escape(href)}">{icon}{html.escape(name)}</a>{size}</li>')
    body = "\n".join(rows) or '<li class="up">This folder is empty.</li>'
    head = _PAGE_HEAD.format(title=html.escape(slug))
    return f"""{head}
<body class="listing"><main class="wrap"><div class="card">
<p class="crumb">temp.kylekaihin.org / <b>{html.escape(slug)}</b>/{html.escape(rel)}</p>
<ul class="files">{body}</ul></div></main></body></html>"""


def gate(slug: str, error: bool = False) -> HTMLResponse:
    msg = '<p class="err">Wrong password — try again.</p>' if error else ""
    head = _PAGE_HEAD.format(title="Password required")
    return HTMLResponse(
        f"""{head}
<body><main class="gate-page"><div class="gate">
<div class="glyph">{_ICON_LOCK}</div>
<h1>Password required</h1>
<p class="sub">This link is protected. Enter the password to continue.</p>
{msg}
<form method="post" action="/{html.escape(slug)}/__auth">
<input type="password" name="password" placeholder="••••••••" autofocus aria-label="Password">
<button type="submit" class="primary">Unlock</button></form></div></main></body></html>""",
        status_code=401,
    )


@app.post("/{slug}/__auth")
async def auth_share(slug: str, password: str = Form(...)) -> Response:
    data = load()
    meta = data.get(slug)
    if not meta:
        raise HTTPException(404, "no such share")
    if hash_pw(password, meta.get("pw_salt") or "") != meta.get("pw_hash"):
        return gate(slug, error=True)
    resp = RedirectResponse(url=f"/{slug}/", status_code=303)
    resp.set_cookie(f"ts_pw_{slug}", meta["pw_hash"][:24], max_age=86400, httponly=True, samesite="lax")
    return resp


@app.get("/{slug}")
def share_root_redirect(slug: str) -> Response:
    return RedirectResponse(url=f"/{slug}/", status_code=308)


@app.get("/{slug}/{path:path}")
def serve(slug: str, path: str, request: Request) -> Response:
    data = load()
    meta = data.get(slug)
    if not meta:
        head = _PAGE_HEAD.format(title="Link not found")
        return HTMLResponse(
            head + '<body><main class="gate-page"><div class="gate">'
            '<div class="glyph" style="background:var(--danger-red-soft);color:var(--danger-red)">'
            '<svg class="i lg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            '<circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg></div>'
            '<h1>Link not found</h1>'
            '<p class="sub">Nothing is published at <b>' + html.escape(slug) + '</b>. '
            'It may have expired, been deleted, or been a one-time link that was already opened.</p>'
            '<a class="btn primary" href="/" style="width:100%">Go to the control panel</a>'
            '</div></main></body></html>',
            status_code=404,
        )
    if meta.get("pw_hash") and request.cookies.get(f"ts_pw_{slug}") != meta["pw_hash"][:24]:
        return gate(slug)

    root = (STORAGE / slug).resolve()
    target = (root / path).resolve()
    if not str(target).startswith(str(root)):
        raise HTTPException(403, "forbidden")
    if not target.exists():
        raise HTTPException(404, "not found")

    if target.is_dir():
        for doc in DEFAULT_DOCS:
            if (target / doc).is_file():
                target = target / doc
                break
        else:
            visible = [p for p in target.iterdir() if not p.name.startswith(".")]
            if len(visible) == 1 and visible[0].is_file():
                # single-document share: serve the file itself at /slug/ rather
                # than a one-item listing, whatever its type (.html, .pdf, …)
                target = visible[0]
            else:
                return HTMLResponse(listing(target, slug, path.strip("/")))

    rel = path.strip("/")
    if meta.get("pw_hash"):
        rel_web = (rel.rsplit("/", 1)[0] + "/") if "/" in rel else ""
        # keep the password cookie scoped by just serving through this route
        meta["_pw_last"] = rel_web

    data[slug]["hits"] = meta.get("hits", 0) + 1
    visit = counts_as_visit(request)
    burned_now = False
    if visit:
        record_visit(data[slug], request, path)
        if meta.get("once") and not meta.get("burn_at"):
            # serve this request, then let the sweeper delete the share shortly after
            data[slug]["burn_at"] = (_now() + timedelta(seconds=ONCE_GRACE_SECONDS)).isoformat(timespec="seconds")
            burned_now = True
    if burned_now or visit or data[slug]["hits"] % 5 == 0:
        save(data)

    media = {
        ".html": "text/html", ".htm": "text/html", ".css": "text/css", ".js": "text/javascript",
        ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png",
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
        ".mp4": "video/mp4", ".webm": "video/webm", ".mp3": "audio/mpeg", ".pdf": "application/pdf",
        ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
        ".woff2": "font/woff2", ".ico": "image/x-icon", ".csv": "text/csv",
    }.get(target.suffix.lower(), "application/octet-stream")
    return Response(content=target.read_bytes(), media_type=media)


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse((BASE / "static" / "index.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=PORT)
