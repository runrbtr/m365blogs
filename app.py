#!/usr/bin/env python3
"""Post Stream web app: a public reading page, with optional accounts to keep favorites.

    python3 app.py serve [--host 127.0.0.1] [--port 8766] [--interval 30]
    python3 app.py adduser NAME        create a user (prompts for the password)
    python3 app.py passwd NAME         change a password (signs that user out everywhere)
    python3 app.py deluser NAME        delete a user and their favorites
    python3 app.py users               list users

Environment:
    DATA_DIR         where archive.json, the generated page and poststream.db live (default ./data)
    TRUST_PROXY=1    you run behind exactly one reverse proxy that sets X-Forwarded-For/-Proto/-Host
    PUBLIC_URL       the address people use, e.g. https://stream.example.com (accepted as a same-origin host)
    ALLOW_SIGNUP     1 (default) lets anyone create an account; 0 closes sign-up (you can still adduser)
    MAX_USERS        stop accepting sign-ups beyond this many accounts (default 1000)
    ADMIN_USER / ADMIN_PASSWORD   create this user on startup if there are no users yet
    REFRESH_MINUTES  how often to check the blogs (default 30)
"""
from __future__ import annotations

import argparse
import getpass
import gzip
import html
import json
import os
import sys
import threading
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit

import build
from store import MAX_PASSWORD, MIN_PASSWORD, Store, UserExists, password_problem, valid_username

COOKIE = "ps_session"
SESSION_SECONDS = 30 * 86400
MAX_JSON = 8 * 1024
MAX_FORM = 4 * 1024
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
STATIC = {"style.css": "text/css; charset=utf-8", "app.js": "application/javascript; charset=utf-8",
          "icon.svg": "image/svg+xml"}

REASONS = {200: "OK", 303: "See Other", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
           405: "Method Not Allowed", 409: "Conflict", 413: "Payload Too Large", 415: "Unsupported Media Type",
           429: "Too Many Requests", 500: "Internal Server Error", 503: "Service Unavailable"}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------- brute-force protection

class RateLimiter:
    """Counts failed logins per client address and per username inside a sliding window."""

    def __init__(self, ip_max: int = 8, user_max: int = 30, window: int = 600):
        self.ip_max, self.user_max, self.window = ip_max, user_max, window
        self.hits: dict = {}
        self.lock = threading.Lock()

    def _live(self, key: str, now: float) -> list:
        hits = [t for t in self.hits.get(key, []) if now - t < self.window]
        if hits:
            self.hits[key] = hits
        else:
            self.hits.pop(key, None)
        return hits

    def retry_after(self, ip: str, user: str) -> int:
        now = time.time()
        with self.lock:
            waits = []
            for key, limit in (("ip:" + ip, self.ip_max), ("user:" + user.lower(), self.user_max)):
                hits = self._live(key, now)
                if len(hits) >= limit:
                    waits.append(int(hits[0] + self.window - now) + 1)
            return max(waits, default=0)

    def failed(self, ip: str, user: str) -> None:
        now = time.time()
        with self.lock:
            if len(self.hits) > 5000:                      # bound memory against floods of random usernames
                for key in list(self.hits):
                    self._live(key, now)
            for key in ("ip:" + ip, "user:" + user.lower()):
                self.hits.setdefault(key, []).append(now)

    def hit(self, ip: str) -> None:
        """Count one attempt from this address (used for sign-ups, where every attempt costs CPU)."""
        self.failed(ip, "-")

    def succeeded(self, ip: str) -> None:
        with self.lock:
            self.hits.pop("ip:" + ip, None)


# ---------------------------------------------------------------- request / response helpers

class Request:
    def __init__(self, environ: dict):
        self.env = environ
        self.method = environ["REQUEST_METHOD"].upper()
        self.path = environ.get("PATH_INFO", "/") or "/"
        self.query = environ.get("QUERY_STRING", "")
        self.ip = environ.get("REMOTE_ADDR", "?")
        self.secure = environ.get("wsgi.url_scheme") == "https"

    def header(self, name: str) -> str:
        key = name.upper().replace("-", "_")
        if key in ("CONTENT_TYPE", "CONTENT_LENGTH"):     # WSGI does not prefix these two with HTTP_
            return self.env.get(key, "")
        return self.env.get("HTTP_" + key, "")

    def cookie(self, name: str) -> str:
        jar = SimpleCookie()
        try:
            jar.load(self.header("Cookie"))
        except Exception:  # noqa: BLE001 - malformed cookie header
            return ""
        return jar[name].value if name in jar else ""

    def body(self, limit: int) -> bytes:
        try:
            length = int(self.env.get("CONTENT_LENGTH") or 0)
        except ValueError:
            raise HttpError(400, "Bad Content-Length")
        if length < 0 or length > limit:
            raise HttpError(413, "Request too large")
        return self.env["wsgi.input"].read(length) if length else b""


class HttpError(Exception):
    def __init__(self, status: int, message: str = ""):
        super().__init__(message)
        self.status, self.message = status, message


class Response:
    def __init__(self, status: int = 200, body: bytes = b"", ctype: str = "text/plain; charset=utf-8", headers=None):
        self.status, self.body = status, body
        self.headers = [("Content-Type", ctype)] + list(headers or [])

    def add(self, key: str, value: str) -> "Response":
        self.headers.append((key, value))
        return self


def text_response(text: str, status: int = 200) -> Response:
    return Response(status, text.encode(), "text/plain; charset=utf-8")


def json_response(data, status: int = 200) -> Response:
    return Response(status, json.dumps(data).encode(), "application/json").add("Cache-Control", "no-store")


def redirect(location: str) -> Response:
    return Response(303, b"", "text/plain; charset=utf-8", [("Location", location)])


def render_auth(mode: str, error: str = "", username: str = "", allow_signup: bool = True) -> bytes:
    """The sign-in and create-account pages share one layout."""
    signup = mode == "signup"
    e = html.escape
    err = f'<p class="err" role="alert">{e(error)}</p>' if error else ""
    if signup:
        intro = "Create an account to keep your favorites across browsers and devices. You can read everything without one."
        fields = (f'<label>Username <input name="username" value="{e(username)}" autocomplete="username" autocapitalize="none" '
                  f'spellcheck="false" required autofocus minlength="3" maxlength="32" pattern="[A-Za-z0-9._-]+"></label>'
                  f'<p class="hint">3 to 32 characters: letters, digits, dot, dash or underscore.</p>'
                  f'<label>Password <input name="password" type="password" autocomplete="new-password" required minlength="{MIN_PASSWORD}" maxlength="{MAX_PASSWORD}"></label>'
                  f'<label>Repeat password <input name="repeat" type="password" autocomplete="new-password" required minlength="{MIN_PASSWORD}" maxlength="{MAX_PASSWORD}"></label>'
                  f'<p class="hint">At least {MIN_PASSWORD} characters. There is no email, so a forgotten password can only be reset by the site owner.</p>'
                  f'<div class="hp" aria-hidden="true"><label>Leave this empty <input name="homepage" tabindex="-1" autocomplete="off"></label></div>')
        button, action = "Create account", "signup"
        other = '<a href="login">Already have an account? Sign in</a>'
    else:
        intro = "Sign in to save favorites. You can read everything without an account."
        fields = (f'<label>Username <input name="username" value="{e(username)}" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus maxlength="32"></label>'
                  f'<label>Password <input name="password" type="password" autocomplete="current-password" required maxlength="{MAX_PASSWORD}"></label>')
        button, action = "Sign in", "login"
        other = '<a href="signup">No account? Create one</a>' if allow_signup else ""
    title = "Create account" if signup else "Sign in"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{title} · M365Blogs</title>
<link rel="icon" type="image/svg+xml" href="{build.asset_url("icon.svg")}">
<link rel="stylesheet" href="{build.asset_url("style.css")}">
</head><body>
<main class="login">
<h1>M365Blogs</h1>
<p class="sub">{intro}</p>
<form method="post" action="{action}">
{err}{fields}
<button type="submit">{button}</button>
</form>
<p class="altlinks">{other}{" · " if other else ""}<a href="./">Back to the posts</a></p>
</main></body></html>""".encode()


# ---------------------------------------------------------------- the app

class App:
    def __init__(self, store: Store, public_url: str = "", allow_signup: bool = True, max_users: int = 1000):
        self.store = store
        self.allow_signup, self.max_users = allow_signup, max_users
        self.limiter = RateLimiter()
        self.signup_limiter = RateLimiter(ip_max=5, user_max=10 ** 9, window=3600)   # 5 sign-ups per address per hour
        self.public_host = urlsplit(public_url).netloc.lower() if public_url else ""
        self.known: frozenset = frozenset()          # URLs that exist in the archive; only these can be favorited
        self._cache_key = None
        self._cache = (b"", b"")
        self._lock = threading.Lock()

    def set_known(self, urls) -> None:
        self.known = frozenset(urls)

    # -- WSGI entry point
    def __call__(self, environ, start_response):
        req = Request(environ)
        try:
            resp = self.dispatch(req)
        except HttpError as e:
            resp = json_response({"error": e.message}, e.status) if req.path.startswith("/api/") else text_response(e.message or REASONS.get(e.status, ""), e.status)
        except Exception as e:  # noqa: BLE001
            log(f"error handling {req.method} {req.path}: {type(e).__name__}: {e}")
            resp = text_response("Internal error", 500)
        self.secure_headers(resp, req)
        start_response(f"{resp.status} {REASONS.get(resp.status, 'Status')}", resp.headers)
        return [resp.body]

    def secure_headers(self, resp: Response, req: Request) -> None:
        resp.add("X-Content-Type-Options", "nosniff")
        resp.add("Referrer-Policy", "same-origin")
        resp.add("Content-Security-Policy", CSP)
        resp.add("X-Frame-Options", "DENY")
        resp.add("X-Robots-Tag", "noindex, nofollow")
        if req.secure:
            resp.add("Strict-Transport-Security", "max-age=31536000")

    # -- routing
    def dispatch(self, req: Request) -> Response:
        path, method = req.path, req.method
        if path == "/healthz":
            return text_response("ok")
        if path.startswith("/static/"):
            return self.static(req, path[len("/static/"):])
        if path == "/login":
            return self.login(req)

        if path == "/signup":
            return self.signup(req)
        if path == "/robots.txt":
            return text_response("User-agent: *\nDisallow: /\n")

        user = self.current_user(req)              # reading is public; a session only adds favorites
        if path.startswith("/api/"):
            return self.api(req, user)
        if path == "/logout":
            if method != "POST":
                raise HttpError(405)
            self.require_same_origin(req)
            token = req.cookie(COOKIE)
            if token:
                self.store.delete_session(token)
            return redirect("./").add("Set-Cookie", self.cookie_header("", 0, req))
        if path == "/":
            if method not in ("GET", "HEAD"):
                raise HttpError(405)
            return self.index(req)
        raise HttpError(404, "Not found")

    # -- authentication
    def current_user(self, req: Request):
        return self.store.session_user(req.cookie(COOKIE))

    def cookie_header(self, token: str, max_age: int, req: Request) -> str:
        parts = [f"{COOKIE}={token}", "Path=/", f"Max-Age={max_age}", "HttpOnly", "SameSite=Lax"]
        if req.secure:
            parts.append("Secure")
        return "; ".join(parts)

    def require_same_origin(self, req: Request) -> None:
        """Reject cross-site form posts. Browsers send Origin on POST; SameSite=Lax on the cookie backs this up."""
        origin = req.header("Origin")
        if not origin:
            return
        host = urlsplit(origin).netloc.lower()
        allowed = {req.header("Host").lower(), self.public_host} - {""}
        if host not in allowed:
            raise HttpError(403, "Cross-origin request blocked")

    def login(self, req: Request) -> Response:
        if req.method in ("GET", "HEAD"):
            if self.current_user(req):
                return redirect("./")
            return Response(200, render_auth("login", allow_signup=self.allow_signup), "text/html; charset=utf-8").add("Cache-Control", "no-store")
        if req.method != "POST":
            raise HttpError(405)
        self.require_same_origin(req)
        if not req.header("Content-Type").startswith("application/x-www-form-urlencoded"):
            raise HttpError(415, "Unsupported content type")
        form = parse_qs(req.body(MAX_FORM).decode("utf-8", "replace"), keep_blank_values=True)
        username = (form.get("username") or [""])[0].strip()[:64]
        password = (form.get("password") or [""])[0][:MAX_PASSWORD + 1]

        wait = self.limiter.retry_after(req.ip, username)
        if wait:
            log(f"login blocked ip={req.ip} user={username!r} retry_in={wait}s")
            minutes = max(1, (wait + 59) // 60)
            return Response(429, render_auth("login", f"Too many attempts. Try again in {minutes} minute{'s' if minutes > 1 else ''}.", username, self.allow_signup),
                            "text/html; charset=utf-8", [("Retry-After", str(wait)), ("Cache-Control", "no-store")])

        found = self.store.verify(username, password)
        if not found:
            self.limiter.failed(req.ip, username)
            log(f"login failed ip={req.ip} user={username!r}")
            return Response(401, render_auth("login", "Wrong username or password.", username, self.allow_signup), "text/html; charset=utf-8",
                            [("Cache-Control", "no-store")])
        self.limiter.succeeded(req.ip)
        token = self.store.create_session(found[0], SESSION_SECONDS)
        log(f"login ok ip={req.ip} user={found[1]!r}")
        return redirect("./").add("Set-Cookie", self.cookie_header(token, SESSION_SECONDS, req)).add("Cache-Control", "no-store")

    def signup(self, req: Request) -> Response:
        if not self.allow_signup:
            raise HttpError(403, "Sign-ups are closed.")
        page = lambda status, error="", name="": Response(  # noqa: E731
            status, render_auth("signup", error, name), "text/html; charset=utf-8", [("Cache-Control", "no-store")])
        if req.method in ("GET", "HEAD"):
            return redirect("./") if self.current_user(req) else page(200)
        if req.method != "POST":
            raise HttpError(405)
        self.require_same_origin(req)
        if not req.header("Content-Type").startswith("application/x-www-form-urlencoded"):
            raise HttpError(415, "Unsupported content type")
        form = parse_qs(req.body(MAX_FORM).decode("utf-8", "replace"), keep_blank_values=True)
        field = lambda k, n=MAX_PASSWORD + 1: (form.get(k) or [""])[0][:n]  # noqa: E731
        username, password, repeat = field("username", 64).strip(), field("password"), field("repeat")

        if field("homepage"):                                   # hidden field that only bots fill in
            log(f"signup blocked (honeypot) ip={req.ip}")
            return page(400, "Could not create the account.")
        if not valid_username(username):
            return page(400, "Username must be 3 to 32 characters: letters, digits, dot, dash or underscore.", username)
        problem = password_problem(password)
        if problem:
            return page(400, problem, username)
        if password != repeat:
            return page(400, "The two passwords do not match.", username)
        if password.lower() == username.lower():
            return page(400, "The password can't be the same as the username.", username)

        wait = self.signup_limiter.retry_after(req.ip, "-")
        if wait:
            log(f"signup blocked ip={req.ip} retry_in={wait}s")
            minutes = max(1, (wait + 59) // 60)
            return Response(429, render_auth("signup", f"Too many sign-ups from your address. Try again in {minutes} minute{'s' if minutes > 1 else ''}.", username),
                            "text/html; charset=utf-8", [("Retry-After", str(wait)), ("Cache-Control", "no-store")])
        if self.store.user_count() >= self.max_users:
            log("signup refused: user limit reached")
            return page(403, "Sign-ups are closed for now.", username)

        self.signup_limiter.hit(req.ip)                         # counted before hashing: every attempt costs CPU
        try:
            self.store.add_user(username, password)
        except UserExists:
            return page(409, "That username is taken. Pick another.", username)
        found = self.store.verify(username, password)
        token = self.store.create_session(found[0], SESSION_SECONDS)
        log(f"signup ok ip={req.ip} user={username!r}")
        return redirect("./").add("Set-Cookie", self.cookie_header(token, SESSION_SECONDS, req)).add("Cache-Control", "no-store")

    # -- pages and assets
    def static(self, req: Request, name: str) -> Response:
        if req.method not in ("GET", "HEAD"):
            raise HttpError(405)
        ctype = STATIC.get(name)
        if not ctype:
            raise HttpError(404, "Not found")
        cache = "public, max-age=31536000, immutable" if "v=" in req.query else "no-cache"
        return Response(200, (build.ASSETS / name).read_bytes(), ctype).add("Cache-Control", cache)

    def index(self, req: Request) -> Response:
        path = build.SITE / "index.html"
        try:
            st = path.stat()
        except FileNotFoundError:
            return text_response("The first build is still running. Reload in a moment.", 503).add("Retry-After", "10")
        key = (st.st_mtime_ns, st.st_size)
        with self._lock:
            if self._cache_key != key:
                raw = path.read_bytes()
                self._cache, self._cache_key = (raw, gzip.compress(raw, 6)), key
            raw, gz = self._cache
        resp = Response(200, raw, "text/html; charset=utf-8", [("Cache-Control", "no-cache"), ("Vary", "Accept-Encoding")])
        if "gzip" in req.header("Accept-Encoding").lower():
            resp.body = gz
            resp.add("Content-Encoding", "gzip")
        return resp

    # -- JSON API (favorites and read marker, per user)
    def read_json(self, req: Request) -> dict:
        self.require_same_origin(req)
        if not req.header("Content-Type").lower().startswith("application/json"):
            raise HttpError(415, "Content-Type must be application/json")
        try:
            data = json.loads(req.body(MAX_JSON) or b"null")
        except ValueError:
            raise HttpError(400, "Invalid JSON")
        if not isinstance(data, dict):
            raise HttpError(400, "Expected a JSON object")
        return data

    def api(self, req: Request, user) -> Response:
        if req.path == "/api/state" and req.method == "GET":
            if not user:                                        # guests can read; the page just hides account features
                return json_response({"user": None, "favorites": [], "last_read": None})
            return json_response({"user": user[1], "favorites": self.store.favorites(user[0]), "last_read": self.store.last_read(user[0])})
        if not user and req.path in ("/api/favorite", "/api/last-read"):
            raise HttpError(401, "Sign in to do that")
        uid = user[0] if user else None

        if req.path == "/api/favorite" and req.method == "POST":
            data = self.read_json(req)
            url, on = data.get("url"), data.get("on")
            if not isinstance(url, str) or not url or len(url) > 2048 or not isinstance(on, bool):
                raise HttpError(400, "Expected {url: string, on: boolean}")
            if on and url not in self.known:
                raise HttpError(404, "Unknown post")
            if not self.store.set_favorite(uid, url, on):
                raise HttpError(409, "Favorites limit reached")
            return json_response({"ok": True})

        if req.path == "/api/last-read" and req.method == "POST":
            value = self.read_json(req).get("value")
            parsed = build.parse_date(value) if isinstance(value, str) and len(value) <= 40 else None
            if not parsed:
                raise HttpError(400, "Expected {value: ISO date}")
            self.store.set_last_read(uid, parsed.isoformat())
            return json_response({"ok": True})

        if req.path in ("/api/state", "/api/favorite", "/api/last-read"):
            raise HttpError(405)
        raise HttpError(404, "Not found")


# ---------------------------------------------------------------- server and CLI

def data_store() -> Store:
    return Store(build.DATA / "poststream.db")


def known_urls() -> list:
    try:
        return list(json.loads(build.ARCHIVE.read_text())["posts"])
    except (OSError, ValueError, KeyError):
        return []


def refresher(app: App, interval: int, first_delay: float) -> None:
    time.sleep(first_delay)
    while True:
        try:
            app.set_known(build.build()["posts"])
        except Exception as e:  # noqa: BLE001 - keep serving the last good page
            log(f"refresh failed: {type(e).__name__}: {e}")
        time.sleep(interval * 60)


def serve(host: str, port: int, interval: int) -> None:
    store = data_store()
    admin, admin_pw = os.environ.get("ADMIN_USER", ""), os.environ.get("ADMIN_PASSWORD", "")
    if store.user_count() == 0 and admin and admin_pw:
        try:
            store.add_user(admin, admin_pw)
            log(f"created initial user {admin!r} from ADMIN_USER/ADMIN_PASSWORD. Remove those variables now.")
        except ValueError as e:
            log(f"could not create initial user: {e}")
    log(f"sign-up is {'open' if os.environ.get('ALLOW_SIGNUP', '1') != '0' else 'closed'}; {store.user_count()} account(s)")

    app = App(store, os.environ.get("PUBLIC_URL", ""), os.environ.get("ALLOW_SIGNUP", "1") != "0",
              int(os.environ.get("MAX_USERS", "1000")))
    app.set_known(known_urls())
    index = build.SITE / "index.html"
    if not index.exists():
        log("building the first page (this fetches about 100 posts per blog)...")
        app.set_known(build.build()["posts"])
    age_min = (time.time() - index.stat().st_mtime) / 60
    threading.Thread(target=refresher, args=(app, interval, max(0.0, (interval - age_min) * 60)), daemon=True).start()

    trust_proxy = os.environ.get("TRUST_PROXY", "0") == "1"
    try:
        import waitress
    except ImportError:
        from socketserver import ThreadingMixIn
        from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

        class Threaded(ThreadingMixIn, WSGIServer):
            daemon_threads = True

        class Quiet(WSGIRequestHandler):
            def log_message(self, *args):
                pass

        if trust_proxy:
            log("TRUST_PROXY needs waitress (pip install waitress); ignoring it with the built-in server.")
        log("waitress is not installed: using Python's built-in server. Fine for trying it locally, not for hosting.")
        log(f"Serving http://{host}:{port}  (checking for new posts every {interval} min)")
        make_server(host, port, app, server_class=Threaded, handler_class=Quiet).serve_forever()
        return

    extra = {"trusted_proxy": "*", "trusted_proxy_count": 1,
             "trusted_proxy_headers": {"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"}} if trust_proxy else {}
    log(f"Serving http://{host}:{port} with waitress (checking for new posts every {interval} min; "
        f"proxy headers {'trusted' if trust_proxy else 'ignored'})")
    waitress.serve(app, host=host, port=port, threads=6, ident="poststream", max_request_body_size=64 * 1024,
                   connection_limit=200, channel_timeout=60, **extra)


def ask_password(name: str) -> str:
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    while True:
        first = getpass.getpass(f"Password for {name}: ")
        problem = password_problem(first)
        if problem:
            print(problem)
            continue
        if getpass.getpass("Repeat password: ") != first:
            print("Passwords did not match.")
            continue
        return first


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8766)
    s.add_argument("--interval", type=int, default=int(os.environ.get("REFRESH_MINUTES", "30")))
    for cmd in ("adduser", "passwd", "deluser"):
        sub.add_parser(cmd).add_argument("name")
    sub.add_parser("users")
    args = ap.parse_args()

    if args.cmd == "serve":
        serve(args.host, args.port, args.interval)
        return
    store = data_store()
    try:
        if args.cmd == "adduser":
            if not valid_username(args.name):
                raise ValueError("Username must be 3-32 characters: letters, digits, '.', '_' or '-'.")
            store.add_user(args.name, ask_password(args.name))
            print(f"Created user {args.name}.")
        elif args.cmd == "passwd":
            store.set_password(args.name, ask_password(args.name))
            print(f"Password changed for {args.name}. They were signed out everywhere.")
        elif args.cmd == "deluser":
            store.delete_user(args.name)
            print(f"Deleted {args.name} and their favorites.")
        elif args.cmd == "users":
            rows = store.list_users()
            for name, created, favs in rows:
                print(f"{name:<24} {favs:>4} favorites   created {created[:10]}")
            if not rows:
                print("No users.")
    except ValueError as e:
        raise SystemExit(str(e))


if __name__ == "__main__":
    main()
