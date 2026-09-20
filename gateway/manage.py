"""CLI di amministrazione:  python manage.py create-admin <username> [nome completo]"""
import getpass, sys, time
import db


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "create-admin":
        sys.exit(__doc__)
    username, full_name = sys.argv[2].strip().lower(), " ".join(sys.argv[3:])
    pw = getpass.getpass("Password (min %d caratteri): " % db.MIN_PW)
    if len(pw) < db.MIN_PW or pw != getpass.getpass("Ripeti password: "):
        sys.exit("Password troppo corta o non coincidente.")
    db.init()
    con = db.connect()
    con.execute(
        "INSERT INTO users(username,full_name,pw_hash,role,must_change,created_at) VALUES(?,?,?,'admin',0,?) "
        "ON CONFLICT(username) DO UPDATE SET pw_hash=excluded.pw_hash, role='admin', active=1, failed=0, locked_until=0",
        (username, full_name, db.hash_pw(pw), int(time.time())))
    db.audit(con, "cli", "local", "admin.create", username)
    print("Amministratore '%s' creato/aggiornato." % username)


if __name__ == "__main__":
    main()
