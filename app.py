import json, os, sqlite3
from functools import wraps
from flask import Flask, request, session, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "ganti-kunci-rahasia-ini")
DB = os.path.join(os.path.dirname(__file__), "kampusku.db")
KINDS = {"jadwal", "tugas", "uang", "catatan", "folder"}


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    with sqlite3.connect(DB) as c:
        c.executescript(
            """CREATE TABLE IF NOT EXISTS users(
                 id INTEGER PRIMARY KEY, nama TEXT, email TEXT UNIQUE, pw TEXT);
               CREATE TABLE IF NOT EXISTS items(
                 id INTEGER PRIMARY KEY, uid INTEGER, kind TEXT, data TEXT);"""
        )


def login_required(f):
    @wraps(f)
    def wrap(*a, **k):
        if "uid" not in session:
            return jsonify(error="Silakan masuk dulu"), 401
        return f(*a, **k)
    return wrap


def err(msg, code=400):
    return jsonify(error=msg), code


# ---------- Akun ----------
@app.post("/api/register")
def register():
    j = request.get_json(force=True)
    nama, email, pw = j.get("nama", "").strip(), j.get("email", "").strip().lower(), j.get("pw", "")
    if not nama or "@" not in email or len(pw) < 6:
        return err("Isi nama, email valid, dan kata sandi minimal 6 karakter")
    try:
        cur = db().execute("INSERT INTO users(nama,email,pw) VALUES(?,?,?)",
                           (nama, email, generate_password_hash(pw)))
        db().commit()
    except sqlite3.IntegrityError:
        return err("Email sudah terdaftar")
    session["uid"] = cur.lastrowid
    return jsonify(nama=nama)


@app.post("/api/login")
def login():
    j = request.get_json(force=True)
    u = db().execute("SELECT * FROM users WHERE email=?", (j.get("email", "").strip().lower(),)).fetchone()
    if not u or not check_password_hash(u["pw"], j.get("pw", "")):
        return err("Email atau kata sandi salah", 401)
    session["uid"] = u["id"]
    return jsonify(nama=u["nama"])


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
@login_required
def me():
    u = db().execute("SELECT nama FROM users WHERE id=?", (session["uid"],)).fetchone()
    if not u:
        session.clear()
        return err("Akun tidak ditemukan", 401)
    return jsonify(nama=u["nama"])


# ---------- CRUD generik: tambah, lihat, ubah, hapus ----------
def row(r):
    return {**json.loads(r["data"]), "id": r["id"]}


@app.get("/api/<kind>")
@login_required
def list_items(kind):
    if kind not in KINDS:
        return err("Tidak ditemukan", 404)
    rs = db().execute("SELECT * FROM items WHERE uid=? AND kind=? ORDER BY id", (session["uid"], kind))
    return jsonify([row(r) for r in rs])


@app.post("/api/<kind>")
@login_required
def add_item(kind):
    if kind not in KINDS:
        return err("Tidak ditemukan", 404)
    data = request.get_json(force=True)
    data.pop("id", None)
    cur = db().execute("INSERT INTO items(uid,kind,data) VALUES(?,?,?)",
                       (session["uid"], kind, json.dumps(data)))
    db().commit()
    return jsonify({**data, "id": cur.lastrowid}), 201


@app.put("/api/<kind>/<int:iid>")
@login_required
def edit_item(kind, iid):
    data = request.get_json(force=True)
    data.pop("id", None)
    cur = db().execute("UPDATE items SET data=? WHERE id=? AND uid=? AND kind=?",
                       (json.dumps(data), iid, session["uid"], kind))
    db().commit()
    if not cur.rowcount:
        return err("Data tidak ditemukan", 404)
    return jsonify({**data, "id": iid})


@app.delete("/api/<kind>/<int:iid>")
@login_required
def del_item(kind, iid):
    db().execute("DELETE FROM items WHERE id=? AND uid=? AND kind=?", (iid, session["uid"], kind))
    if kind == "folder":  # hapus folder = hapus catatan di dalamnya
        pass
    db().commit()
    return jsonify(ok=True)


@app.get("/")
def index():
    return app.send_static_file("index.html")


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
