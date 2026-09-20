"""Test della policy di accesso:  GW_DB=/tmp/t.sqlite ETHERCALC_KEY=<64 hex> python -m pytest -q"""
import os, tempfile, time
os.environ["GW_DB"] = os.path.join(tempfile.mkdtemp(), "t.sqlite")
os.environ["ETHERCALC_KEY"] = "k" * 64
os.environ["GW_PREFIX"] = os.environ.get("GW_PREFIX", "")
from fastapi.testclient import TestClient
import app as gw, db

con = db.connect()
for name in ("anna", "bruno"):
    con.execute("INSERT INTO users(username,pw_hash,role,must_change,created_at) VALUES(?,?,?,0,?)",
                (name, db.hash_pw("password-lunga-1"), "user", int(time.time())))
con.execute("INSERT INTO sheets(id,owner_id,title,public_export,created_at) VALUES('pub1',1,'t',1,0),('priv1',1,'t',0,0)")


def client(user=None):
    c = TestClient(gw.app, follow_redirects=False)
    if user:
        assert c.post("/gw/login", data={"username": user, "password": "password-lunga-1"}).status_code == 303
        # nginx toglie il prefisso: il cookie e' emesso su PREFIX+"/" ma qui si
        # chiama l'app direttamente, quindi lo si ripubblica senza prefisso.
        if gw.PREFIX:
            token = c.cookies.get(gw.COOKIE)
            c.cookies.clear()
            c.cookies.set(gw.COOKIE, token, path="/")
    return c


def chk(c, method, uri):
    return c.get("/internal/check", headers={"x-original-method": method, "x-original-uri": gw.PREFIX + uri}).status_code


def test_anonymous():
    c = client()
    for uri in ("/pub1.csv", "/pub1.csv.json", "/pub1.xlsx", "/pub1.html", "/_/pub1/csv", "/pub1.2.csv", "/=pub1.xlsx"):
        assert chk(c, "GET", uri) == 204, uri
    # 401 -> nginx reindirizza al login: solo per la navigazione del browser.
    for uri in ("/pub1", "/pub1/edit", "/priv1.csv"):
        assert chk(c, "GET", uri) == 401, uri
    # API e WebSocket: 403 secco, nessun redirect.
    for method, uri in (("GET", "/_ws/pub1?auth=x"), ("POST", "/_/pub1"), ("PUT", "/_/pub1"),
                        ("DELETE", "/_/pub1"), ("GET", "/_/pub1"), ("PUT", "/pub1")):
        assert chk(c, method, uri) == 403, (method, uri)
    for uri in ("/_new", "/=_new", "/_rooms", "/_roomlinks", "/_exists/pub1",
                "/_from/pub1", "/_migrate/seed/pub1", "/_auth/whoami", "/socket.io/1/", "/_timetrigger", "/_/private",
                "/unknown.csv", "/unknown", "/%70ub1", "/pub1/../_rooms", "/_", "/internal/check", "/_health"):
        assert chk(c, "GET", uri) == 403, uri
    assert chk(c, "POST", "/_") == 403
    assert chk(c, "POST", "/pub1.csv") == 403


def test_owner_and_other_user():
    anna, bruno = client("anna"), client("bruno")
    for method, uri in (("GET", "/pub1?auth=abc"), ("GET", "/_ws/pub1?user=a&auth=abc"), ("POST", "/_/pub1"),
                        ("GET", "/priv1.csv"), ("GET", "/_ws/pub1.3"), ("PUT", "/_/priv1/xlsx")):
        assert chk(anna, method, uri) == 204, (method, uri)
        assert chk(bruno, method, uri) == 403, (method, uri)
    assert chk(bruno, "GET", "/pub1.csv") == 204
    # /edit consegna il token di scrittura: consentito al proprietario, negato agli altri.
    for uri in ("/pub1/edit", "/pub1/view", "/pub1/app"):
        assert chk(anna, "GET", uri) == 204, uri
        assert chk(bruno, "GET", uri) == 403, uri


def test_open_delivers_hmac_only_to_owner():
    anna, bruno = client("anna"), client("bruno")
    loc = anna.get("/gw/open/pub1").headers["location"]
    assert loc == gw.PREFIX + "/pub1?auth=" + db.room_hmac("pub1") and len(loc.split("=")[1]) == 64
    assert "auth=" not in bruno.get("/gw/open/pub1").headers["location"]
    assert client().get("/gw/open/pub1").headers["location"] == gw.PREFIX + "/gw/login"


def test_prefix_isolation():
    if not gw.PREFIX:
        return
    c = client()
    assert c.get("/internal/check", headers={"x-original-method": "GET", "x-original-uri": "/pub1.csv"}).status_code == 403


def test_csrf_and_lockout():
    anna = client("anna")
    assert "e_csrf" in anna.post("/gw/sheets/new", data={"title": "x", "csrf": "bad"}).headers["location"]
    assert anna.get("/gw/admin/users").status_code == 403
    c = client()
    for _ in range(5):
        assert c.post("/gw/login", data={"username": "bruno", "password": "sbagliata"}).status_code == 401
    assert c.post("/gw/login", data={"username": "bruno", "password": "password-lunga-1"}).status_code == 401
