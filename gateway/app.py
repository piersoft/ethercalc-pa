"""Gateway di autenticazione e autorizzazione per EtherCalc (uso PA).

- /internal/check : interrogato da nginx (auth_request) per OGNI richiesta diretta a EtherCalc.
                    Policy "default deny": passa solo cio' che e' esplicitamente previsto.
- /gw/*           : login, dashboard dei fogli, amministrazione utenti, registro attivita'.
"""
import csv, io, os, re, secrets, time, urllib.error, urllib.request
from datetime import datetime

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates

import db

ETHERCALC_URL = os.environ.get("ETHERCALC_URL", "http://ethercalc:8000")
# Prefisso pubblico quando l'applicazione e' servita sotto un percorso
# (es. https://ckan.example.it/sheet). Vuoto se sta alla radice del dominio.
PREFIX = "/" + os.environ.get("GW_PREFIX", "").strip("/") if os.environ.get("GW_PREFIX", "").strip("/") else ""
COOKIE = "gw_session"
COOKIE_SECURE = os.environ.get("GW_COOKIE_SECURE", "0") == "1"
IDLE_TIMEOUT = int(os.environ.get("GW_IDLE_TIMEOUT", 8 * 3600))
ABS_TIMEOUT = int(os.environ.get("GW_ABS_TIMEOUT", 24 * 3600))
MAX_FAILED, LOCK_SECONDS = 5, 15 * 60
MAX_IMPORT_BYTES = 10 * 1024 * 1024

if len(db.ETHERCALC_KEY) < 32:
    raise SystemExit("ETHERCALC_KEY assente o troppo corta: il gateway non parte senza chiave.")

db.init()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
tpl = Jinja2Templates(directory="templates")
tpl.env.globals["p"] = PREFIX
tpl.env.filters["dt"] = lambda ts: datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M")

MESSAGES = {
    "created": "Foglio creato.", "deleted": "Foglio eliminato.", "updated": "Modifica salvata.",
    "pw_ok": "Password aggiornata.", "user_ok": "Utente salvato.", "adopted": "Foglio esistente acquisito.",
    "e_csrf": "Richiesta non valida, riprova.", "e_pw": "Password non valida: minimo 12 caratteri e conferma identica.",
    "e_pw_old": "La password attuale non e' corretta.", "e_user": "Username non valido o gia' esistente.",
    "e_notfound": "Foglio non trovato.", "e_exists": "Il foglio e' gia' registrato.",
    "e_backend": "EtherCalc non ha completato l'operazione, riprova.", "e_self": "Non puoi disattivare te stesso.",
    "must_change": "Al primo accesso e' obbligatorio cambiare la password.",
    "imported": "CSV importato: il contenuto del foglio e' stato sostituito.",
    "e_file": "File non valido: serve un CSV non vuoto, al massimo 10 MB.",
    "e_encoding": "Il file non e' leggibile come testo: salvalo in UTF-8 o in Windows-1252.",
}

# --------------------------------------------------------------------------- policy
ROOM = r"=?[A-Za-z0-9][A-Za-z0-9_-]*(?:\.\d+)?"
EXT = r"(?:csv\.json|csv|html|md|xlsx|ods|fods)"
RE_EXPORT = re.compile(rf"^/(?:({ROOM})\.{EXT}|_/({ROOM})/{EXT})$")
RE_WS = re.compile(rf"^/_ws/({ROOM})$")
RE_API = re.compile(rf"^/_/({ROOM})(?:/[A-Za-z0-9_./-]*)?$")
RE_UI = re.compile(rf"^/({ROOM})(?:/(?:edit|view|app))?$")
RE_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
RE_SHEET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def base_id(room):
    """'=abc.2' -> 'abc': i sotto-fogli ereditano i permessi del foglio principale."""
    return re.sub(r"\.\d+$", "", room.lstrip("="))


def client_ip(request):
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "")


def current_session(con, request):
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    row = con.execute(
        "SELECT s.token_hash, s.csrf, s.created_at, s.last_seen, u.id AS uid, u.username, u.full_name, "
        "u.role, u.must_change FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.token_hash=? AND u.active=1", (db.token_hash(token),)).fetchone()
    now = int(time.time())
    if not row:
        return None
    if now - row["last_seen"] > IDLE_TIMEOUT or now - row["created_at"] > ABS_TIMEOUT:
        con.execute("DELETE FROM sessions WHERE token_hash=?", (row["token_hash"],))
        return None
    if now - row["last_seen"] > 60:
        con.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, row["token_hash"]))
    return row


@app.get("/internal/check")
def check(request: Request):
    """204 = consenti, 401 = serve il login, 403 = vietato. Tutto cio' che non e' previsto e' vietato."""
    method = request.headers.get("x-original-method", "GET").upper()
    path = request.headers.get("x-original-uri", "/").split("?", 1)[0]
    if PREFIX:
        if not path.startswith(PREFIX):
            return Response(status_code=403)
        path = path[len(PREFIX):] or "/"
    if "%" in path or "//" in path or ".." in path:  # nessuna ambiguita' di decodifica tra gateway e backend
        return Response(status_code=403)

    m = RE_EXPORT.match(path)
    is_export = bool(m) and method in ("GET", "HEAD")
    if m and not is_export:
        m = None
    room = (m.group(1) or m.group(2)) if m else None
    if room is None:
        for rx in (RE_WS, RE_API, RE_UI):
            mm = rx.match(path)
            if mm:
                room = mm.group(1)
                break
    if room is None:
        return Response(status_code=403)

    con = db.connect()
    try:
        sheet = con.execute("SELECT owner_id, public_export FROM sheets WHERE id=?", (base_id(room),)).fetchone()
        if not sheet:
            return Response(status_code=403)  # fogli non registrati nel gateway: inesistenti per l'esterno
        if is_export and sheet["public_export"]:
            return Response(status_code=204)
        sess = current_session(con, request)
        if not sess:
            # 401 (che nginx trasforma in redirect al login) solo dove una
            # pagina di login ha senso: navigazione del browser. Le chiamate
            # API e il WebSocket ricevono 403, non un redirect.
            wants_login = method in ("GET", "HEAD") and (is_export or RE_UI.match(path) is not None)
            return Response(status_code=401 if wants_login else 403)
        if sess["uid"] == sheet["owner_id"] and not sess["must_change"]:
            return Response(status_code=204, headers={"X-GW-User": sess["username"]})
        return Response(status_code=403)
    finally:
        con.close()


# --------------------------------------------------------------------------- helpers UI
def go(url, msg=None):
    return RedirectResponse(PREFIX + url + (f"?msg={msg}" if msg else ""), status_code=303)


def page(request, name, sess, **ctx):
    msg = request.query_params.get("msg", "")
    ctx.update(request=request, sess=sess, message=MESSAGES.get(msg, ""), is_error=msg.startswith("e_"))
    resp = tpl.TemplateResponse(request, name, ctx)
    resp.headers.update({
        "Cache-Control": "no-store", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin",
        "Content-Security-Policy": "default-src 'none'; style-src 'self' 'unsafe-inline'; form-action 'self'; "
                                   "base-uri 'none'; frame-ancestors 'none'",
    })
    return resp


def guard(con, request, csrf=None, admin=False):
    """Ritorna (sessione, None) oppure (None, risposta di redirect/errore)."""
    sess = current_session(con, request)
    if not sess:
        return None, go("/gw/login")
    if csrf is not None and not secrets.compare_digest(csrf, sess["csrf"]):
        return None, go("/gw/", "e_csrf")
    if sess["must_change"] and not request.url.path.endswith("/gw/password"):
        return None, go("/gw/password", "must_change")
    if admin and sess["role"] != "admin":
        return None, Response(status_code=403)
    return sess, None


def backend(method, path, body=None, content_type=None):
    headers = {"Content-Type": content_type} if content_type else {}
    req = urllib.request.Request(ETHERCALC_URL + path, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:
        return 0


def decode_csv(raw):
    """I CSV della PA arrivano spesso da Excel: prova UTF-8, poi Windows-1252."""
    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def public_base(request):
    proto = request.headers.get("x-forwarded-proto", "http")
    return f"{proto}://{request.headers.get('host', '')}{PREFIX}"


# --------------------------------------------------------------------------- login / logout / password
@app.get("/gw/login")
def login_form(request: Request):
    return page(request, "login.html", None, error=False)


@app.post("/gw/login")
def login(request: Request, username: str = Form(""), password: str = Form("")):
    username, ip, now = username.strip().lower(), client_ip(request), int(time.time())
    con = db.connect()
    try:
        user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        ok = False
        if user and user["active"] and user["locked_until"] <= now:
            ok = db.verify_pw(user["pw_hash"], password)
        elif not user:
            db.verify_pw(db.hash_pw("tempo-costante"), password)  # niente oracolo sull'esistenza dell'utente
        if not ok:
            if user:
                failed = user["failed"] + 1
                lock = now + LOCK_SECONDS if failed >= MAX_FAILED else 0
                con.execute("UPDATE users SET failed=?, locked_until=? WHERE id=?",
                            (0 if lock else failed, lock or user["locked_until"], user["id"]))
            db.audit(con, username if RE_USERNAME.match(username) else "(non valido)", ip, "login.fail")
            resp = page(request, "login.html", None, error=True)
            resp.status_code = 401
            return resp
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        con.execute("UPDATE users SET failed=0, locked_until=0 WHERE id=?", (user["id"],))
        con.execute("DELETE FROM sessions WHERE created_at<?", (now - ABS_TIMEOUT,))
        con.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)", (db.token_hash(token), user["id"], csrf, now, now, ip))
        db.audit(con, username, ip, "login.ok")
        resp = go("/gw/")
        resp.set_cookie(COOKIE, token, httponly=True, secure=COOKIE_SECURE, samesite="lax", path=PREFIX + "/")
        return resp
    finally:
        con.close()


@app.post("/gw/logout")
def logout(request: Request, csrf: str = Form("")):
    con = db.connect()
    try:
        sess = current_session(con, request)
        if sess and secrets.compare_digest(csrf, sess["csrf"]):
            con.execute("DELETE FROM sessions WHERE token_hash=?", (sess["token_hash"],))
            db.audit(con, sess["username"], client_ip(request), "logout")
        resp = go("/gw/login")
        resp.delete_cookie(COOKIE, path=PREFIX + "/")
        return resp
    finally:
        con.close()


@app.get("/gw/password")
def password_form(request: Request):
    con = db.connect()
    try:
        sess, err = guard(con, request)
        return err or page(request, "password.html", sess)
    finally:
        con.close()


@app.post("/gw/password")
def password_change(request: Request, csrf: str = Form(""), old: str = Form(""),
                    new: str = Form(""), new2: str = Form("")):
    con = db.connect()
    try:
        sess, err = guard(con, request, csrf)
        if err:
            return err
        user = con.execute("SELECT pw_hash FROM users WHERE id=?", (sess["uid"],)).fetchone()
        if not db.verify_pw(user["pw_hash"], old):
            return go("/gw/password", "e_pw_old")
        if len(new) < db.MIN_PW or new != new2 or new == old:
            return go("/gw/password", "e_pw")
        con.execute("UPDATE users SET pw_hash=?, must_change=0 WHERE id=?", (db.hash_pw(new), sess["uid"]))
        con.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (sess["uid"], sess["token_hash"]))
        db.audit(con, sess["username"], client_ip(request), "password.change")
        return go("/gw/", "pw_ok")
    finally:
        con.close()


@app.get("/gw/guida")
def guida(request: Request):
    con = db.connect()
    try:
        sess, err = guard(con, request)
        return err or page(request, "guida.html", sess)
    finally:
        con.close()


# --------------------------------------------------------------------------- fogli dell'utente
@app.get("/gw/")
def dashboard(request: Request):
    con = db.connect()
    try:
        sess, err = guard(con, request)
        if err:
            return err
        sheets = con.execute("SELECT * FROM sheets WHERE owner_id=? ORDER BY created_at DESC", (sess["uid"],)).fetchall()
        return page(request, "dashboard.html", sess, sheets=sheets, base=public_base(request))
    finally:
        con.close()


@app.post("/gw/sheets/new")
def sheet_new(request: Request, csrf: str = Form(""), title: str = Form("")):
    con = db.connect()
    try:
        sess, err = guard(con, request, csrf)
        if err:
            return err
        sid = db.new_sheet_id()
        con.execute("INSERT INTO sheets(id,owner_id,title,created_at) VALUES(?,?,?,?)",
                    (sid, sess["uid"], title.strip()[:120] or "Senza titolo", int(time.time())))
        db.audit(con, sess["username"], client_ip(request), "sheet.create", sid)
        return RedirectResponse(f"{PREFIX}/gw/open/{sid}", status_code=303)
    finally:
        con.close()


@app.get("/gw/open/{sid}")
def sheet_open(request: Request, sid: str):
    con = db.connect()
    try:
        sess, err = guard(con, request)
        if err:
            return err
        row = con.execute("SELECT id FROM sheets WHERE id=? AND owner_id=?", (sid, sess["uid"])).fetchone()
        if not row:
            return go("/gw/", "e_notfound")
        # Il token di scrittura e' calcolato qui e consegnato solo al proprietario autenticato.
        return RedirectResponse(f"{PREFIX}/{sid}?auth={db.room_hmac(sid)}", status_code=303)
    finally:
        con.close()


@app.post("/gw/sheets/{sid}/update")
def sheet_update(request: Request, sid: str, csrf: str = Form(""), title: str = Form(""), public_export: str = Form("")):
    con = db.connect()
    try:
        sess, err = guard(con, request, csrf)
        if err:
            return err
        cur = con.execute("UPDATE sheets SET title=?, public_export=? WHERE id=? AND owner_id=?",
                          (title.strip()[:120] or "Senza titolo", 1 if public_export else 0, sid, sess["uid"]))
        if not cur.rowcount:
            return go("/gw/", "e_notfound")
        db.audit(con, sess["username"], client_ip(request), "sheet.update", f"{sid} public={1 if public_export else 0}")
        return go("/gw/", "updated")
    finally:
        con.close()


def delete_sheet(con, sess, request, sid, where_owner=True):
    q = "SELECT id FROM sheets WHERE id=?" + (" AND owner_id=?" if where_owner else "")
    if not con.execute(q, (sid, sess["uid"]) if where_owner else (sid,)).fetchone():
        return "e_notfound"
    status = backend("DELETE", f"/_/{sid}?auth={db.room_hmac(sid)}")
    if not (200 <= status < 300 or status == 404):
        return "e_backend"
    con.execute("DELETE FROM sheets WHERE id=?", (sid,))
    db.audit(con, sess["username"], client_ip(request), "sheet.delete", sid)
    return "deleted"


@app.post("/gw/sheets/{sid}/delete")
def sheet_delete(request: Request, sid: str, csrf: str = Form("")):
    con = db.connect()
    try:
        sess, err = guard(con, request, csrf)
        return err or go("/gw/", delete_sheet(con, sess, request, sid))
    finally:
        con.close()


@app.post("/gw/sheets/{sid}/import")
async def sheet_import(request: Request, sid: str, csrf: str = Form(""), file: UploadFile = File(...)):
    """Sostituisce il contenuto del foglio con un CSV caricato dall'utente.

    Passa dall'API REST di EtherCalc invece che dall'incollaggio nel browser:
    l'operazione e' atomica, non dipende dal WebSocket e resta nel registro.
    """
    con = db.connect()
    try:
        sess, err = guard(con, request, csrf)
        if err:
            return err
        if not con.execute("SELECT 1 FROM sheets WHERE id=? AND owner_id=?", (sid, sess["uid"])).fetchone():
            return go("/gw/", "e_notfound")
        raw = await file.read(MAX_IMPORT_BYTES + 1)
        if not raw or len(raw) > MAX_IMPORT_BYTES:
            return go("/gw/", "e_file")
        text = decode_csv(raw)
        if text is None:
            return go("/gw/", "e_encoding")
        status = backend("PUT", f"/_/{sid}?auth={db.room_hmac(sid)}",
                         text.encode("utf-8"), "text/csv; charset=utf-8")
        if not 200 <= status < 300:
            return go("/gw/", "e_backend")
        db.audit(con, sess["username"], client_ip(request), "sheet.import",
                 f"{sid} {file.filename or ''} {len(raw)}B")
        return go("/gw/", "imported")
    finally:
        con.close()


# --------------------------------------------------------------------------- amministrazione
@app.get("/gw/admin/users")
def admin_users(request: Request):
    con = db.connect()
    try:
        sess, err = guard(con, request, admin=True)
        if err:
            return err
        users = con.execute("SELECT u.*, (SELECT COUNT(*) FROM sheets s WHERE s.owner_id=u.id) AS n "
                            "FROM users u ORDER BY username").fetchall()
        return page(request, "admin_users.html", sess, users=users, now=int(time.time()))
    finally:
        con.close()


@app.post("/gw/admin/users/save")
def admin_user_save(request: Request, csrf: str = Form(""), username: str = Form(""), full_name: str = Form(""),
                    role: str = Form("user"), password: str = Form("")):
    con = db.connect()
    try:
        sess, err = guard(con, request, csrf, admin=True)
        if err:
            return err
        username = username.strip().lower()
        if not RE_USERNAME.match(username) or role not in ("user", "admin"):
            return go("/gw/admin/users", "e_user")
        if len(password) < db.MIN_PW:
            return go("/gw/admin/users", "e_pw")
        try:
            con.execute("INSERT INTO users(username,full_name,pw_hash,role,created_at) VALUES(?,?,?,?,?)",
                        (username, full_name.strip()[:120], db.hash_pw(password), role, int(time.time())))
        except Exception:
            return go("/gw/admin/users", "e_user")
        db.audit(con, sess["username"], client_ip(request), "user.create", f"{username} role={role}")
        return go("/gw/admin/users", "user_ok")
    finally:
        con.close()


@app.post("/gw/admin/users/{uid}/{action}")
def admin_user_action(request: Request, uid: int, action: str, csrf: str = Form(""), password: str = Form("")):
    con = db.connect()
    try:
        sess, err = guard(con, request, csrf, admin=True)
        if err:
            return err
        if action in ("disable", "enable"):
            if uid == sess["uid"]:
                return go("/gw/admin/users", "e_self")
            con.execute("UPDATE users SET active=?, failed=0, locked_until=0 WHERE id=?", (action == "enable", uid))
            con.execute("DELETE FROM sessions WHERE user_id=?", (uid,)) if action == "disable" else None
        elif action == "reset":
            if len(password) < db.MIN_PW:
                return go("/gw/admin/users", "e_pw")
            con.execute("UPDATE users SET pw_hash=?, must_change=1, failed=0, locked_until=0 WHERE id=?",
                        (db.hash_pw(password), uid))
            con.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        else:
            return Response(status_code=404)
        db.audit(con, sess["username"], client_ip(request), f"user.{action}", str(uid))
        return go("/gw/admin/users", "user_ok")
    finally:
        con.close()


@app.get("/gw/admin/sheets")
def admin_sheets(request: Request):
    con = db.connect()
    try:
        sess, err = guard(con, request, admin=True)
        if err:
            return err
        sheets = con.execute("SELECT s.*, u.username FROM sheets s JOIN users u ON u.id=s.owner_id "
                             "ORDER BY s.created_at DESC").fetchall()
        users = con.execute("SELECT id, username FROM users WHERE active=1 ORDER BY username").fetchall()
        return page(request, "admin_sheets.html", sess, sheets=sheets, users=users)
    finally:
        con.close()


@app.post("/gw/admin/sheets/adopt")
def admin_adopt(request: Request, csrf: str = Form(""), sid: str = Form(""), owner_id: int = Form(0), title: str = Form("")):
    """Registra nel gateway un foglio gia' presente in EtherCalc (creato prima dell'attivazione)."""
    con = db.connect()
    try:
        sess, err = guard(con, request, csrf, admin=True)
        if err:
            return err
        sid = sid.strip()
        if not RE_SHEET_ID.match(sid) or backend("GET", f"/_/{sid}") != 200:
            return go("/gw/admin/sheets", "e_notfound")
        if not con.execute("SELECT 1 FROM users WHERE id=? AND active=1", (owner_id,)).fetchone():
            return go("/gw/admin/sheets", "e_user")
        try:
            con.execute("INSERT INTO sheets(id,owner_id,title,created_at) VALUES(?,?,?,?)",
                        (sid, owner_id, title.strip()[:120] or sid, int(time.time())))
        except Exception:
            return go("/gw/admin/sheets", "e_exists")
        db.audit(con, sess["username"], client_ip(request), "sheet.adopt", f"{sid} owner={owner_id}")
        return go("/gw/admin/sheets", "adopted")
    finally:
        con.close()


@app.post("/gw/admin/sheets/{sid}/{action}")
def admin_sheet_action(request: Request, sid: str, action: str, csrf: str = Form(""), owner_id: int = Form(0)):
    con = db.connect()
    try:
        sess, err = guard(con, request, csrf, admin=True)
        if err:
            return err
        if action == "delete":
            return go("/gw/admin/sheets", delete_sheet(con, sess, request, sid, where_owner=False))
        if action == "assign" and con.execute("SELECT 1 FROM users WHERE id=? AND active=1", (owner_id,)).fetchone():
            con.execute("UPDATE sheets SET owner_id=? WHERE id=?", (owner_id, sid))
            db.audit(con, sess["username"], client_ip(request), "sheet.assign", f"{sid} owner={owner_id}")
            return go("/gw/admin/sheets", "updated")
        return go("/gw/admin/sheets", "e_user")
    finally:
        con.close()


@app.get("/gw/admin/audit")
def admin_audit(request: Request, fmt: str = ""):
    con = db.connect()
    try:
        sess, err = guard(con, request, admin=True)
        if err:
            return err
        if fmt == "csv":
            out = io.StringIO()
            w = csv.writer(out)
            w.writerow(["data_ora", "utente", "ip", "azione", "dettaglio"])
            for r in con.execute("SELECT * FROM audit ORDER BY id"):
                safe = [("'" + v) if v and v[0] in "=+-@" else v for v in (r["username"], r["ip"], r["action"], r["detail"])]
                w.writerow([datetime.fromtimestamp(r["ts"]).isoformat(), *safe])
            return Response(out.getvalue(), media_type="text/csv; charset=utf-8",
                            headers={"Content-Disposition": "attachment; filename=registro-attivita.csv"})
        rows = con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 500").fetchall()
        return page(request, "admin_audit.html", sess, rows=rows)
    finally:
        con.close()
