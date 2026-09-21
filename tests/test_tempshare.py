"""temp-share test suite.

Run with:  pytest -q
"""
import json
import zipfile
from datetime import timedelta
from types import SimpleNamespace

import pytest


# ----------------------------------------------------------------- helpers ---
def make_share(client, auth, **form):
    form.setdefault("slug", "demo")
    form.setdefault("days", 7)
    upload = None
    if "file" in form:
        upload = {"file": form.pop("file")}
    return client.post("/api/shares", headers=auth, data=form, files=upload)


@pytest.fixture()
def site(tmp_path):
    d = tmp_path / "site"
    d.mkdir()
    (d / "index.html").write_text("<h1>hello</h1>", encoding="utf-8")
    (d / "note.txt").write_text("asset", encoding="utf-8")
    return d


# ---------------------------------------------------------------- pure fns ---
def test_human(app):
    assert app.human(0) == "0B"
    assert app.human(999) == "999B"
    assert app.human(1024) == "1.0KB"
    assert app.human(1024 * 1024 * 3) == "3.0MB"


def test_hash_pw_is_salted(app):
    a = app.hash_pw("hunter2", "saltA")
    b = app.hash_pw("hunter2", "saltB")
    assert a != b, "same password + different salt must hash differently"
    assert a == app.hash_pw("hunter2", "saltA"), "must be deterministic"
    assert "hunter2" not in a


def test_describe_ua(app):
    assert app.describe_ua("") == "unknown"
    assert app.describe_ua("curl/8.5.0") == "curl"
    ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"
    assert app.describe_ua(ua) == "Safari · iPhone"
    assert app.describe_ua("Mozilla/5.0 (Linux; Android 14) Chrome/120") == "Chrome · Android"
    assert app.describe_ua("Googlebot/2.1 (+http://www.google.com/bot.html)") == "bot"
    assert app.describe_ua("python-httpx/0.28.1") == "script"
    assert app.describe_ua("Instagram 300.0 (iPhone14,2; iOS 17_0)") == "iPhone (app)"


def test_client_ip_normalises_ipv4_mapped_ipv6(app):
    req = SimpleNamespace(
        headers={"x-forwarded-for": "::ffff:203.0.113.7"},
        client=SimpleNamespace(host="10.0.0.9"),
    )
    assert app.client_ip(req) == "203.0.113.7"


def test_counts_as_visit_distinguishes_assets_from_pages(app):
    def req(dest=None, accept=None):
        headers = {}
        if dest:
            headers["sec-fetch-dest"] = dest
        if accept:
            headers["accept"] = accept
        return SimpleNamespace(headers=headers)

    assert app.counts_as_visit(req("document")) is True
    assert app.counts_as_visit(req("iframe")) is True
    assert app.counts_as_visit(req("image")) is False
    assert app.counts_as_visit(req("script")) is False
    assert app.counts_as_visit(req("style")) is False
    # no sec-fetch-dest -> fall back to Accept
    assert app.counts_as_visit(req(accept="text/html,application/xhtml+xml")) is True
    assert app.counts_as_visit(req(accept="image/avif,image/webp,*/*")) is False
    # unidentifiable clients burn the link: fail safe, not leak
    assert app.counts_as_visit(req()) is True


def test_client_ip_prefers_forwarded_for(app):
    def req(fwd=None, real=None, host="10.0.0.9"):
        headers = {}
        if fwd:
            headers["x-forwarded-for"] = fwd
        if real:
            headers["x-real-ip"] = real
        return SimpleNamespace(headers=headers, client=SimpleNamespace(host=host))

    assert app.client_ip(req(fwd="203.0.113.7, 10.0.0.1")) == "203.0.113.7"
    assert app.client_ip(req(real="198.51.100.4")) == "198.51.100.4"
    assert app.client_ip(req()) == "10.0.0.9"


# ------------------------------------------------------------------- auth ----
def test_admin_routes_require_token(client):
    assert client.get("/api/shares").status_code == 401
    assert client.delete("/api/shares/x").status_code == 401
    assert client.post("/api/sweep").status_code == 401


def test_healthz_is_open(client):
    body = client.get("/healthz").json()
    assert body["ok"] is True
    assert body["sweeper"] is True


def test_login_sets_cookie_and_rejects_wrong_password(client, app):
    assert client.post("/api/login", data={"password": "nope"}).status_code == 401
    r = client.post("/api/login", data={"password": app.DEFAULT_PASSWORD})
    assert r.status_code == 200
    assert client.get("/api/shares").status_code == 200  # session cookie now carried


def test_logout_ends_the_session(client, app):
    client.post("/api/login", data={"password": app.DEFAULT_PASSWORD})
    assert client.get("/api/shares").status_code == 200
    assert client.post("/api/logout").status_code == 200
    assert client.get("/api/shares").status_code == 401


# ---------------------------------------------------------------- publish ----
def test_publish_folder_from_local_path(client, auth, site, app):
    r = make_share(client, auth, slug="notes", local_path=str(site))
    assert r.status_code == 200, r.text
    meta = r.json()["meta"]
    assert meta["files"] == 2
    assert meta["expires_at"]

    assert client.get("/notes/").text == "<h1>hello</h1>"
    assert client.get("/notes/note.txt").text == "asset"


def test_publish_file_and_zip(client, auth, site, tmp_path):
    # a single loose file
    r = make_share(client, auth, slug="one", file=("d.txt", b"data", "text/plain"))
    assert r.status_code == 200
    assert r.json()["meta"]["kind"] == "file"
    assert client.get("/one/").text == "data"

    # a zip with a single top-level folder -> flattened
    z = tmp_path / "b.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("inside/index.html", "<b>zip</b>")
        zf.writestr("inside/extra.txt", "x")
    with z.open("rb") as fh:
        r = make_share(client, auth, slug="zz", file=("b.zip", fh.read(), "application/zip"))
    assert r.status_code == 200, r.text
    assert r.json()["meta"]["kind"] == "zip"
    assert client.get("/zz/").text == "<b>zip</b>"  # flattened, index served


def test_single_html_is_served_at_slug_root(client, auth):
    """Regression: a one-file share must open the document at /<slug>/, not list it."""
    r = make_share(client, auth, slug="doc", file=("report.html", b"<p>report</p>", "text/html"))
    assert r.status_code == 200
    body = client.get("/doc/").text
    assert "<p>report</p>" in body
    assert "report.html</a>" not in body, "should not render a file listing"


def test_multi_file_folder_still_gets_a_listing(client, auth, tmp_path):
    d = tmp_path / "many"
    d.mkdir()
    (d / "a.txt").write_text("a", encoding="utf-8")
    (d / "b.txt").write_text("b", encoding="utf-8")
    make_share(client, auth, slug="many", local_path=str(d))
    body = client.get("/many/").text
    assert "a.txt" in body and "b.txt" in body


def test_slug_validation(client, auth, site):
    assert make_share(client, auth, slug="Bad Slug", local_path=str(site)).status_code == 400
    assert make_share(client, auth, slug="", local_path=str(site)).status_code == 200  # auto slug
    r = make_share(client, auth, slug="demo", local_path=str(site))
    assert r.status_code == 200
    assert make_share(client, auth, slug="demo", local_path=str(site)).status_code == 409


def test_publish_requires_a_source(client, auth):
    r = client.post("/api/shares", headers=auth, data={"slug": "z", "days": 1})
    assert r.status_code == 400


def test_missing_local_path_is_404(client, auth):
    r = make_share(client, auth, slug="gone", local_path="/nope/nope")
    assert r.status_code == 404


# ---------------------------------------------------------------- expiry -----
def test_days_zero_means_never_expires(client, auth, site):
    r = make_share(client, auth, slug="forever", days=0, local_path=str(site))
    assert r.json()["meta"]["expires_at"] is None
    assert client.get("/forever/").status_code == 200


def test_expired_share_is_pruned_and_removed(client, auth, site, app):
    make_share(client, auth, slug="old", local_path=str(site))
    data = app.load()
    data["old"]["expires_at"] = (app._now() - timedelta(minutes=1)).isoformat(timespec="seconds")
    app.save(data)

    assert app.prune() == ["old"]
    assert not (app.STORAGE / "old").exists()
    assert client.get("/old/").status_code == 404
    assert "old" not in app.load()


# ------------------------------------------------------------------- once ----
def test_once_link_burns_and_deletes(client, auth, site, app, monkeypatch):
    make_share(client, auth, slug="once", days=0, once="true", local_path=str(site))
    assert app.load()["once"]["once"] is True

    assert client.get("/once/").status_code == 200
    assert app.load()["once"]["burn_at"], "a visit must schedule the burn"

    # assets of that page still load inside the grace window
    assert client.get("/once/note.txt").status_code == 200

    monkeypatch.setattr(app, "ONCE_GRACE_SECONDS", 0, raising=False)
    data = app.load()
    data["once"]["burn_at"] = (app._now() - timedelta(seconds=1)).isoformat(timespec="seconds")
    app.save(data)

    assert app.prune() == ["once"]
    assert not (app.STORAGE / "once").exists()
    assert client.get("/once/").status_code == 404


def test_once_asset_requests_do_not_consume_the_link(client, auth, site, app):
    make_share(client, auth, slug="once2", days=0, once="true", local_path=str(site))
    client.get("/once2/note.txt", headers={"sec-fetch-dest": "script"})
    assert not app.load()["once2"].get("burn_at"), "sub-resource loads must not burn the link"


# -------------------------------------------------------------- passwords ----
def test_password_gate_flow(client, auth, site):
    make_share(client, auth, slug="locked", password="hunter2", local_path=str(site))

    first = client.get("/locked/")
    assert first.status_code == 401  # gate page

    assert client.get("/locked/", follow_redirects=False).status_code == 401
    assert client.post("/locked/__auth", data={"password": "wrong"}).status_code == 401
    ok = client.post("/locked/__auth", data={"password": "hunter2"}, follow_redirects=False)
    assert ok.status_code == 303
    assert client.get("/locked/").text == "<h1>hello</h1>"


# ------------------------------------------------------------------ visits ---
def test_visitor_log_records_ip_and_ua(client, auth, site, app):
    make_share(client, auth, slug="log", days=0, local_path=str(site))
    client.get("/log/", headers={"X-Forwarded-For": "203.0.113.7", "User-Agent": "curl/8"})
    client.get("/log/", headers={"X-Forwarded-For": "198.51.100.22", "User-Agent": "curl/8"})

    row = [s for s in client.get("/api/shares", headers=auth).json()["shares"] if s["slug"] == "log"][0]
    assert row["hits"] == 2
    assert row["unique_ips"] == 2
    assert {v["ip"] for v in row["visits"]} == {"203.0.113.7", "198.51.100.22"}
    assert app.load()["log"]["ips"] == ["203.0.113.7", "198.51.100.22"]


# ---------------------------------------------------------------- security ---
def test_traversal_is_blocked(client, auth, site):
    make_share(client, auth, slug="t", local_path=str(site))
    for attack in ("/t/../../../../etc/passwd", "/t/..%2f..%2f..%2fetc%2fpasswd"):
        r = client.get(attack)
        assert r.status_code in (403, 404), attack
        assert "root:" not in r.text


def test_zip_slip_is_rejected(client, auth, tmp_path):
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../escaped.txt", "pwned")
        zf.writestr("ok.txt", "fine")
    r = make_share(client, auth, slug="slip", file=("evil.zip", evil.read_bytes(), "application/zip"))
    assert r.status_code == 400
    assert not (tmp_path / "escaped.txt").exists()
    assert client.get("/slip/").status_code == 404


# ----------------------------------------------------------------- delete ---
def test_delete_removes_record_and_files(client, auth, site, app):
    make_share(client, auth, slug="bye", local_path=str(site))
    assert client.delete("/api/shares/bye", headers=auth).status_code == 200
    assert not (app.STORAGE / "bye").exists()
    assert client.get("/bye/").status_code == 404
    assert client.delete("/api/shares/bye", headers=auth).status_code == 404


def test_extend_pushes_the_deadline(client, auth, site, app):
    make_share(client, auth, slug="ext", days=1, local_path=str(site))
    before = app.load()["ext"]["expires_at"]
    r = client.post("/api/shares/ext/extend", headers=auth, data={"days": 7})
    assert r.status_code == 200
    assert app.load()["ext"]["expires_at"] > before


# ------------------------------------------------------------------ panel ----
def test_panel_index_serves(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "temp-share" in r.text


def test_unknown_slug_is_a_friendly_404(client):
    r = client.get("/nothing-here/")
    assert r.status_code == 404
    assert "nothing-here" in r.text


def test_slug_redirects_to_trailing_slash(client, auth, site):
    make_share(client, auth, slug="redir", local_path=str(site))
    r = client.get("/redir", follow_redirects=False)
    assert r.status_code == 308
    assert r.headers["location"] == "/redir/"


# -------------------------------------------------------- password change ----
def test_change_password_requires_current(client, auth, app):
    r = client.post("/api/password", headers=auth, data={"current": "wrong", "new": "newpassword1"})
    assert r.status_code == 403
    assert client.post("/api/login", data={"password": app.DEFAULT_PASSWORD}).status_code == 200


def test_change_password_then_login(client, auth, app):
    r = client.post("/api/password", headers=auth, data={"current": app.DEFAULT_PASSWORD, "new": "newpassword1"})
    assert r.status_code == 200, r.text
    assert client.post("/api/login", data={"password": app.DEFAULT_PASSWORD}).status_code == 401
    assert client.post("/api/login", data={"password": "newpassword1"}).status_code == 200


def test_change_password_rejects_short(client, auth, app):
    r = client.post("/api/password", headers=auth, data={"current": app.DEFAULT_PASSWORD, "new": "short"})
    assert r.status_code == 400


def test_password_is_stored_hashed_not_plaintext(app):
    app.set_password("supersecret1")
    raw = app.PASSWORD_FILE.read_text()
    assert "supersecret1" not in raw
    assert raw.startswith("scrypt$")


def test_change_password_changes_hash(client, auth, app):
    before = app.load_password_hash()
    client.post("/api/password", headers=auth, data={"current": app.DEFAULT_PASSWORD, "new": "anotherpass1"})
    assert app.load_password_hash() != before
    assert app.check_password("anotherpass1") is True
    assert app.check_password(app.DEFAULT_PASSWORD) is False


def test_password_endpoints_need_auth(client, app):
    assert client.post("/api/password", data={"current": app.DEFAULT_PASSWORD, "new": "whatever12"}).status_code == 401
    assert client.post("/api/2fa/setup").status_code == 401
    assert client.post("/api/2fa/enable", data={"secret": "X", "code": "1"}).status_code == 401
    assert client.post("/api/2fa/disable").status_code == 401


# ------------------------------------------------------------------- 2fa -----
def test_totp_matches_rfc_vector(app):
    """RFC 6238 appendix B test vector (secret '12345678901234567890')."""
    import base64 as b64

    secret = b64.b32encode(b"12345678901234567890").decode()
    assert app.totp_now(secret, at=59) == "287082"   # T=0x0000000000000001
    assert app.totp_now(secret, at=1111111109) == "081804"


def test_totp_accepts_one_step_of_clock_drift(app, monkeypatch):
    secret = app.new_totp_secret()
    app.TOTP_FILE.write_text(secret)
    now = 1_700_000_000
    monkeypatch.setattr(app.time, "time", lambda: now)
    assert app.check_totp(app.totp_now(secret, at=now - 30)) is True
    assert app.check_totp(app.totp_now(secret, at=now + 30)) is True
    assert app.check_totp("000000") is False


def test_2fa_setup_enable_login_disable(client, auth, app, monkeypatch):
    now = 1_700_000_000
    monkeypatch.setattr(app.time, "time", lambda: now)

    setup = client.post("/api/2fa/setup", headers=auth).json()
    secret = setup["secret"]
    assert setup["otpauth_url"].startswith("otpauth://totp/")

    # enabling needs proof of the secret
    assert client.post("/api/2fa/enable", headers=auth,
                       data={"secret": secret, "code": "000000"}).status_code == 400
    code = app.totp_now(secret, at=now)
    assert client.post("/api/2fa/enable", headers=auth,
                       data={"secret": secret, "code": code}).status_code == 200

    # now a password alone is not enough
    assert client.post("/api/login", data={"password": app.DEFAULT_PASSWORD}).status_code == 401
    ok = client.post("/api/login", data={"password": app.DEFAULT_PASSWORD, "code": code})
    assert ok.status_code == 200

    assert client.post("/api/2fa/disable", headers=auth).status_code == 200
    assert client.post("/api/login", data={"password": app.DEFAULT_PASSWORD}).status_code == 200


def test_session_endpoint(client, app):
    assert client.get("/api/session").json()["authenticated"] is False
    client.post("/api/login", data={"password": app.DEFAULT_PASSWORD})
    body = client.get("/api/session").json()
    assert body["authenticated"] is True and body["user"] == "admin"


# --------------------------------------------------------------- download ----
def test_download_folder_returns_zip(client, auth, site):
    make_share(client, auth, slug="dl", local_path=str(site))
    r = client.get("/api/shares/dl/download", headers=auth)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert r.headers["content-disposition"].startswith("attachment;")
    import io as _io
    with zipfile.ZipFile(_io.BytesIO(r.content)) as zf:
        assert sorted(zf.namelist()) == ["index.html", "note.txt"]


def test_download_single_file_returns_the_file(client, auth):
    make_share(client, auth, slug="one2", file=("note.txt", b"hello", "text/plain"))
    r = client.get("/api/shares/one2/download", headers=auth)
    assert r.status_code == 200
    assert r.content == b"hello"
    assert 'filename="note.txt"' in r.headers["content-disposition"]


def test_download_requires_auth(client, auth, site):
    make_share(client, auth, slug="dl2", local_path=str(site))
    assert client.get("/api/shares/dl2/download").status_code == 401
    assert client.get("/api/shares/nope/download", headers=auth).status_code == 404
