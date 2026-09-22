"""Run with:  python3 -m unittest discover -s tests -v"""
import io
import json
import os
import sys
import tempfile
import unittest
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode

DATA = tempfile.mkdtemp(prefix="poststream-test-")
os.environ["DATA_DIR"] = DATA
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as appmod  # noqa: E402
import build  # noqa: E402
import store as storemod  # noqa: E402

appmod.log = lambda *_: None      # keep test output quiet

POST_A = "https://example.com/post-a/"
POST_B = "https://example.com/post-b/"


def call(app, method, path, body=b"", headers=None, cookie=None, https=False, ip="203.0.113.5"):
    """Invoke the WSGI app directly. Returns (status_int, headers dict (lowercase), body bytes)."""
    if isinstance(body, dict):
        body = json.dumps(body).encode()
    env = {"REQUEST_METHOD": method, "PATH_INFO": path.split("?")[0], "QUERY_STRING": path.partition("?")[2],
           "REMOTE_ADDR": ip, "HTTP_HOST": "stream.test", "wsgi.url_scheme": "https" if https else "http",
           "wsgi.input": io.BytesIO(body), "CONTENT_LENGTH": str(len(body))}
    for k, v in (headers or {}).items():
        env["CONTENT_TYPE" if k.lower() == "content-type" else "HTTP_" + k.upper().replace("-", "_")] = v
    if cookie:
        env["HTTP_COOKIE"] = f"{appmod.COOKIE}={cookie}"
    out = {}

    def start(status, hdrs):
        out["status"] = int(status.split()[0])
        out["headers"] = hdrs

    payload = b"".join(app(env, start))
    multi = {}
    for k, v in out["headers"]:
        multi.setdefault(k.lower(), []).append(v)
    return out["status"], multi, payload


FORM = {"Content-Type": "application/x-www-form-urlencoded"}
JSON = {"Content-Type": "application/json"}


class Base(unittest.TestCase):
    def setUp(self):
        self.db = Path(DATA) / f"{self.id()}.db"
        self.store = storemod.Store(self.db)
        self.store.add_user("alice", "correct horse battery")
        self.store.add_user("bob", "another long password")
        (Path(DATA) / "site").mkdir(exist_ok=True)
        (Path(DATA) / "site" / "index.html").write_text("<html>hello</html>")
        self.app = appmod.App(self.store, "")
        self.app.set_known([POST_A, POST_B])

    def login(self, user="alice", password=None, **kw):
        password = password or {"alice": "correct horse battery", "bob": "another long password"}[user]
        status, headers, _ = call(self.app, "POST", "/login", urlencode({"username": user, "password": password}).encode(), FORM, **kw)
        self.assertEqual(status, 303, "login should succeed")
        return SimpleCookie(headers["set-cookie"][0])[appmod.COOKIE].value


class TestAccess(Base):
    def test_reading_is_public_saving_needs_an_account(self):
        self.assertEqual(call(self.app, "GET", "/healthz")[0], 200)
        status, _, body = call(self.app, "GET", "/")
        self.assertEqual((status, body), (200, b"<html>hello</html>"))
        status, _, body = call(self.app, "GET", "/api/state")
        self.assertEqual((status, json.loads(body)), (200, {"user": None, "favorites": [], "last_read": None}))
        self.assertEqual(call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": True}, JSON)[0], 401)
        self.assertEqual(call(self.app, "POST", "/api/last-read", {"value": "2026-09-21T17:45:00+00:00"}, JSON)[0], 401)
        self.assertEqual(call(self.app, "GET", "/nothing-here")[0], 404)

    def test_not_indexed_by_search_engines(self):
        _, h, _ = call(self.app, "GET", "/")
        self.assertEqual(h["x-robots-tag"], ["noindex, nofollow"])
        status, _, body = call(self.app, "GET", "/robots.txt")
        self.assertEqual((status, body), (200, b"User-agent: *\nDisallow: /\n"))

    def test_static_whitelist_and_no_traversal(self):
        self.assertEqual(call(self.app, "GET", "/static/style.css")[0], 200)
        self.assertIn("immutable", call(self.app, "GET", "/static/app.js?v=abc")[1]["cache-control"][0])
        for bad in ("/static/../store.py", "/static/store.py", "/static/..%2fstore.py", "/static/"):
            self.assertEqual(call(self.app, "GET", bad)[0], 404, bad)

    def test_security_headers(self):
        _, h, _ = call(self.app, "GET", "/login")
        self.assertIn("default-src 'none'", h["content-security-policy"][0])
        self.assertNotIn("unsafe-inline", h["content-security-policy"][0])
        self.assertEqual(h["x-content-type-options"], ["nosniff"])
        self.assertEqual(h["x-frame-options"], ["DENY"])
        self.assertNotIn("strict-transport-security", h)
        _, h, _ = call(self.app, "GET", "/login", https=True)
        self.assertIn("strict-transport-security", h)


class TestLogin(Base):
    def test_wrong_password_and_unknown_user_look_identical(self):
        a = call(self.app, "POST", "/login", urlencode({"username": "alice", "password": "nope-nope-nope"}).encode(), FORM)
        b = call(self.app, "POST", "/login", urlencode({"username": "ghost", "password": "nope-nope-nope"}).encode(), FORM)
        self.assertEqual((a[0], b[0]), (401, 401))
        strip = lambda page: __import__("re").sub(rb'value="[^"]*"', b"", page)    # the typed name is echoed back; ignore it
        self.assertEqual(strip(a[2]), strip(b[2]), "same page either way, so usernames can't be probed")
        self.assertIn(b"Wrong username or password.", a[2])
        self.assertNotIn("set-cookie", a[1])

    def test_session_cookie_flags_and_hashed_storage(self):
        _, headers, _ = call(self.app, "POST", "/login", urlencode({"username": "alice", "password": "correct horse battery"}).encode(), FORM)
        cookie = headers["set-cookie"][0]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertNotIn("Secure", cookie)                 # plain http on a LAN must still work
        token = SimpleCookie(cookie)[appmod.COOKIE].value
        self.assertGreaterEqual(len(token), 40)
        self.assertNotIn(token.encode(), self.db.read_bytes())    # only a hash is stored
        _, headers, _ = call(self.app, "POST", "/login", urlencode({"username": "alice", "password": "correct horse battery"}).encode(), FORM, https=True)
        self.assertIn("Secure", headers["set-cookie"][0])

    def test_usernames_are_case_insensitive(self):
        self.login("ALICE", "correct horse battery")

    def test_signed_in_user_gets_the_page_gzipped_on_request(self):
        token = self.login()
        status, h, body = call(self.app, "GET", "/", cookie=token)
        self.assertEqual((status, body), (200, b"<html>hello</html>"))
        status, h, body = call(self.app, "GET", "/", headers={"Accept-Encoding": "gzip"}, cookie=token)
        self.assertEqual(h["content-encoding"], ["gzip"])

    def test_logout_ends_the_session(self):
        token = self.login()
        status, h, _ = call(self.app, "POST", "/logout", b"", FORM, cookie=token)
        self.assertEqual(status, 303)
        self.assertIn("Max-Age=0", h["set-cookie"][0])
        self.assertIsNone(json.loads(call(self.app, "GET", "/api/state", cookie=token)[2])["user"])
        self.assertEqual(call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": True}, JSON, cookie=token)[0], 401)
        self.assertEqual(call(self.app, "POST", "/logout", b"", FORM)[0], 303)          # signing out as a guest is harmless

    def test_expired_and_forged_sessions_are_rejected(self):
        uid = self.store.verify("alice", "correct horse battery")[0]
        expired = self.store.create_session(uid, -10)
        for bad in (expired, "forged-token"):
            self.assertIsNone(json.loads(call(self.app, "GET", "/api/state", cookie=bad)[2])["user"])
            self.assertEqual(call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": True}, JSON, cookie=bad)[0], 401)

    def test_changing_a_password_signs_the_user_out(self):
        token = self.login()
        self.store.set_password("alice", "a brand new password")
        self.assertIsNone(json.loads(call(self.app, "GET", "/api/state", cookie=token)[2])["user"])
        self.login("alice", "a brand new password")


def signup_form(username="carol", password="a fine long password", repeat=None, **extra):
    data = {"username": username, "password": password, "repeat": password if repeat is None else repeat, **extra}
    return urlencode(data).encode()


class TestSignup(Base):
    def test_anyone_can_create_an_account_and_is_signed_in(self):
        status, _, body = call(self.app, "GET", "/signup")
        self.assertEqual(status, 200)
        self.assertIn(b"Create account", body)
        status, h, _ = call(self.app, "POST", "/signup", signup_form(), FORM)
        self.assertEqual((status, h["location"]), (303, ["./"]))
        cookie = SimpleCookie(h["set-cookie"][0])
        self.assertIn("HttpOnly", h["set-cookie"][0])
        token = cookie[appmod.COOKIE].value
        state = json.loads(call(self.app, "GET", "/api/state", cookie=token)[2])
        self.assertEqual(state["user"], "carol")
        self.assertEqual(call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": True}, JSON, cookie=token)[0], 200)
        self.login_as("carol", "a fine long password")             # and can sign in again later

    def login_as(self, user, password):
        status, _, _ = call(self.app, "POST", "/login", urlencode({"username": user, "password": password}).encode(), FORM, ip="192.0.2.99")
        self.assertEqual(status, 303)

    def test_username_taken_ignoring_case(self):
        status, _, body = call(self.app, "POST", "/signup", signup_form("ALICE"), FORM)
        self.assertEqual(status, 409)
        self.assertIn(b"That username is taken", body)
        self.assertIn(b'value="ALICE"', body)                        # the form keeps what was typed...
        self.assertNotIn(b"a fine long password", body)              # ...but never the password

    def test_bad_input_is_explained_and_creates_nothing(self):
        cases = [(signup_form("ab"), b"Username must be"), (signup_form("bad name!"), b"Username must be"),
                 (signup_form(password="short"), b"at least 10"), (signup_form(repeat="different password"), b"do not match"),
                 (signup_form("samename1234", "samename1234"), b"same as the username"),
                 (signup_form(homepage="http://spam.example"), b"Could not create")]
        for body, expected in cases:
            status, _, page = call(self.app, "POST", "/signup", body, FORM)
            self.assertEqual(status, 400)
            self.assertIn(expected, page)
        self.assertEqual(self.store.user_count(), 2)                 # only alice and bob

    def test_sign_up_can_be_switched_off(self):
        app = appmod.App(self.store, "", allow_signup=False)
        self.assertEqual(call(app, "GET", "/signup")[0], 403)
        self.assertEqual(call(app, "POST", "/signup", signup_form(), FORM)[0], 403)
        self.assertNotIn(b"Create one", call(app, "GET", "/login")[2])       # no dangling link
        self.assertIn(b"Create one", call(self.app, "GET", "/login")[2])

    def test_user_limit(self):
        app = appmod.App(self.store, "", max_users=2)
        status, _, body = call(app, "POST", "/signup", signup_form(), FORM)
        self.assertEqual(status, 403)
        self.assertIn(b"closed for now", body)

    def test_limited_to_five_sign_ups_per_address_per_hour(self):
        for i in range(5):
            self.assertEqual(call(self.app, "POST", "/signup", signup_form(f"newuser{i}"), FORM, ip="198.51.100.30")[0], 303)
        status, h, _ = call(self.app, "POST", "/signup", signup_form("newuser5"), FORM, ip="198.51.100.30")
        self.assertEqual(status, 429)
        self.assertIn("retry-after", h)
        self.assertEqual(call(self.app, "POST", "/signup", signup_form("newuser6"), FORM, ip="192.0.2.31")[0], 303)   # other address is fine

    def test_typos_in_the_form_do_not_use_up_the_limit(self):
        for _ in range(10):
            self.assertEqual(call(self.app, "POST", "/signup", signup_form(password="short"), FORM, ip="198.51.100.40")[0], 400)
        self.assertEqual(call(self.app, "POST", "/signup", signup_form(), FORM, ip="198.51.100.40")[0], 303)

    def test_cross_site_sign_up_is_blocked(self):
        self.assertEqual(call(self.app, "POST", "/signup", signup_form(), {**FORM, "Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.store.user_count(), 2)

    def test_signed_in_users_are_sent_home(self):
        token = self.login()
        self.assertEqual(call(self.app, "GET", "/signup", cookie=token)[0], 303)
        self.assertEqual(call(self.app, "GET", "/login", cookie=token)[0], 303)


class TestBruteForce(Base):
    def test_lockout_by_address_then_recovery_elsewhere(self):
        bad = urlencode({"username": "alice", "password": "wrong-wrong-wrong"}).encode()
        good = urlencode({"username": "alice", "password": "correct horse battery"}).encode()
        for _ in range(8):
            self.assertEqual(call(self.app, "POST", "/login", bad, FORM, ip="198.51.100.9")[0], 401)
        status, h, _ = call(self.app, "POST", "/login", good, FORM, ip="198.51.100.9")
        self.assertEqual(status, 429, "even the right password is refused while locked")
        self.assertIn("retry-after", h)
        self.assertEqual(call(self.app, "POST", "/login", good, FORM, ip="192.0.2.77")[0], 303)

    def test_success_resets_the_address_counter(self):
        bad = urlencode({"username": "alice", "password": "wrong-wrong-wrong"}).encode()
        for _ in range(5):
            call(self.app, "POST", "/login", bad, FORM, ip="198.51.100.20")
        self.login(ip="198.51.100.20")
        for _ in range(5):
            self.assertEqual(call(self.app, "POST", "/login", bad, FORM, ip="198.51.100.20")[0], 401)


class TestCrossSite(Base):
    def test_login_and_api_reject_foreign_origins(self):
        form = urlencode({"username": "alice", "password": "correct horse battery"}).encode()
        self.assertEqual(call(self.app, "POST", "/login", form, {**FORM, "Origin": "https://evil.example"})[0], 403)
        self.assertEqual(call(self.app, "POST", "/login", form, {**FORM, "Origin": "http://stream.test"})[0], 303)
        token = self.login()
        r = call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": True}, {**JSON, "Origin": "https://evil.example"}, cookie=token)
        self.assertEqual(r[0], 403)
        self.assertEqual(call(self.app, "POST", "/logout", b"", {**FORM, "Origin": "https://evil.example"}, cookie=token)[0], 403)

    def test_public_url_host_is_accepted(self):
        app = appmod.App(self.store, "https://stream.example.org")
        form = urlencode({"username": "alice", "password": "correct horse battery"}).encode()
        self.assertEqual(call(app, "POST", "/login", form, {**FORM, "Origin": "https://stream.example.org"})[0], 303)

    def test_api_requires_json_content_type(self):
        token = self.login()
        for ctype in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data"):
            r = call(self.app, "POST", "/api/favorite", b'{"url":"x","on":true}', {"Content-Type": ctype}, cookie=token)
            self.assertEqual(r[0], 415, ctype)


class TestFavorites(Base):
    def test_add_remove_and_state(self):
        t = self.login()
        self.assertEqual(json.loads(call(self.app, "GET", "/api/state", cookie=t)[2]),
                         {"user": "alice", "favorites": [], "last_read": None})
        self.assertEqual(call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": True}, JSON, cookie=t)[0], 200)
        self.assertEqual(call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": True}, JSON, cookie=t)[0], 200)   # idempotent
        self.assertEqual(json.loads(call(self.app, "GET", "/api/state", cookie=t)[2])["favorites"], [POST_A])
        self.assertEqual(call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": False}, JSON, cookie=t)[0], 200)
        self.assertEqual(json.loads(call(self.app, "GET", "/api/state", cookie=t)[2])["favorites"], [])

    def test_favorites_follow_the_account_across_sessions(self):
        first = self.login()
        call(self.app, "POST", "/api/favorite", {"url": POST_B, "on": True}, JSON, cookie=first)
        second = self.login(ip="192.0.2.50")               # "another browser"
        self.assertNotEqual(first, second)
        self.assertEqual(json.loads(call(self.app, "GET", "/api/state", cookie=second)[2])["favorites"], [POST_B])

    def test_users_do_not_see_each_others_favorites(self):
        a, b = self.login("alice"), self.login("bob")
        call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": True}, JSON, cookie=a)
        self.assertEqual(json.loads(call(self.app, "GET", "/api/state", cookie=b)[2])["favorites"], [])
        call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": False}, JSON, cookie=b)     # bob "removing" changes nothing for alice
        self.assertEqual(json.loads(call(self.app, "GET", "/api/state", cookie=a)[2])["favorites"], [POST_A])

    def test_validation(self):
        t = self.login()
        cases = [({"url": "https://elsewhere.example/x", "on": True}, 404),   # not a post in the archive
                 ({"url": POST_A}, 400), ({"url": 5, "on": True}, 400), ({"url": POST_A, "on": "yes"}, 400),
                 ({"url": "x" * 3000, "on": True}, 400)]
        for body, status in cases:
            self.assertEqual(call(self.app, "POST", "/api/favorite", body, JSON, cookie=t)[0], status, body)
        self.assertEqual(call(self.app, "POST", "/api/favorite", b"not json", JSON, cookie=t)[0], 400)
        self.assertEqual(call(self.app, "POST", "/api/favorite", b"[1,2]", JSON, cookie=t)[0], 400)
        self.assertEqual(call(self.app, "POST", "/api/favorite", b"x" * 20000, JSON, cookie=t)[0], 413)
        self.assertEqual(call(self.app, "GET", "/api/favorite", cookie=t)[0], 405)
        self.assertEqual(call(self.app, "GET", "/api/nothing", cookie=t)[0], 404)

    def test_per_user_limit(self):
        old = storemod.MAX_FAVORITES
        storemod.MAX_FAVORITES = 1
        try:
            t = self.login()
            self.assertEqual(call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": True}, JSON, cookie=t)[0], 200)
            self.assertEqual(call(self.app, "POST", "/api/favorite", {"url": POST_B, "on": True}, JSON, cookie=t)[0], 409)
        finally:
            storemod.MAX_FAVORITES = old

    def test_last_read_marker_is_per_user_and_validated(self):
        a, b = self.login("alice"), self.login("bob")
        self.assertEqual(call(self.app, "POST", "/api/last-read", {"value": "2026-09-21T17:45:00+00:00"}, JSON, cookie=a)[0], 200)
        self.assertEqual(json.loads(call(self.app, "GET", "/api/state", cookie=a)[2])["last_read"], "2026-09-21T17:45:00+00:00")
        self.assertIsNone(json.loads(call(self.app, "GET", "/api/state", cookie=b)[2])["last_read"])
        for bad in ("yesterday", "", 5, None, "9" * 60):
            self.assertEqual(call(self.app, "POST", "/api/last-read", {"value": bad}, JSON, cookie=a)[0], 400, bad)

    def test_deleting_a_user_removes_their_data_and_sessions(self):
        t = self.login()
        call(self.app, "POST", "/api/favorite", {"url": POST_A, "on": True}, JSON, cookie=t)
        self.store.delete_user("alice")
        self.assertIsNone(json.loads(call(self.app, "GET", "/api/state", cookie=t)[2])["user"])
        self.store.add_user("alice", "correct horse battery")      # a new account starts empty
        uid = self.store.verify("alice", "correct horse battery")[0]
        self.assertEqual(self.store.favorites(uid), [])


class TestStore(unittest.TestCase):
    def test_password_and_username_rules(self):
        s = storemod.Store(Path(DATA) / "rules.db")
        with self.assertRaises(ValueError):
            s.add_user("ab", "long enough password")            # username too short
        with self.assertRaises(ValueError):
            s.add_user("bad name!", "long enough password")
        with self.assertRaises(ValueError):
            s.add_user("carol", "short")                        # password too short
        s.add_user("carol", "long enough password")
        with self.assertRaises(ValueError):
            s.add_user("CAROL", "long enough password")         # duplicate ignoring case

    def test_hash_format_and_verification(self):
        h = storemod.hash_password("secret-secret")
        self.assertTrue(h.startswith("pbkdf2_sha256$600000$"))
        self.assertNotEqual(h, storemod.hash_password("secret-secret"))     # random salt
        self.assertTrue(storemod.check_password("secret-secret", h))
        self.assertFalse(storemod.check_password("secret-secreT", h))
        self.assertFalse(storemod.check_password("x", "garbage"))


if __name__ == "__main__":
    unittest.main()
