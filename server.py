#!/usr/bin/env python3
import base64, hashlib, hmac, json, mimetypes, os, re, secrets, time
from pathlib import Path
from urllib.parse import quote
from flask import Flask, Response, jsonify, make_response, request
import psycopg
from psycopg.rows import dict_row

ROOT=Path(__file__).resolve().parent
app=Flask(__name__)
app.config["MAX_CONTENT_LENGTH"]=7*1024*1024
LOGIN_RE=re.compile(r"^[A-Za-zА-Яа-яЁё0-9_.-]{3,32}$")

def db():
    url=os.environ.get("DATABASE_URL")
    if not url: raise RuntimeError("Не задана переменная DATABASE_URL (строка подключения Neon)")
    return psycopg.connect(url, row_factory=dict_row)

def ph(password, salt=None):
    salt=salt or secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,310000)
    return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"

def pok(password, encoded):
    try:
        _,rounds,salt,expected=encoded.split("$")
        actual=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),int(rounds))
        return hmac.compare_digest(actual.hex(),expected)
    except Exception: return False

def token_hash(token): return hashlib.sha256(token.encode()).hexdigest()

def init_db():
    with db() as con, con.cursor() as cur:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,login TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN('admin','user')),
          blocked BOOLEAN NOT NULL DEFAULT FALSE,created_at BIGINT NOT NULL);
        CREATE TABLE IF NOT EXISTS activation_codes(id BIGSERIAL PRIMARY KEY,code_hash TEXT NOT NULL,
          created_at BIGINT NOT NULL,used_at BIGINT,used_by BIGINT REFERENCES users(id),created_by BIGINT REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at BIGINT NOT NULL);
        CREATE TABLE IF NOT EXISTS comments(id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id),
          body TEXT NOT NULL,created_at BIGINT NOT NULL);
        CREATE TABLE IF NOT EXISTS homework(id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id),
          title TEXT NOT NULL,body TEXT NOT NULL,filename TEXT,file_data BYTEA,mime_type TEXT,
          status TEXT NOT NULL DEFAULT 'submitted',admin_note TEXT NOT NULL DEFAULT '',created_at BIGINT NOT NULL);
        """)
        cur.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1")
        if not cur.fetchone():
            password=os.environ.get("MS_ADMIN_PASSWORD")
            if not password: raise RuntimeError("Для первого запуска задайте MS_ADMIN_PASSWORD")
            cur.execute("INSERT INTO users(login,password_hash,role,created_at) VALUES(%s,%s,'admin',%s)",
                        (os.environ.get("MS_ADMIN_LOGIN","admin"),ph(password),int(time.time())))

def current_user():
    token=request.cookies.get("ms_session")
    if not token: return None
    with db() as con, con.cursor() as cur:
        cur.execute("DELETE FROM sessions WHERE expires_at<%s",(int(time.time()),))
        cur.execute("SELECT u.id,u.login,u.role,u.blocked FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=%s AND s.expires_at>%s",
                    (token_hash(token),int(time.time())))
        user=cur.fetchone()
    return user if user and not user["blocked"] else None

def need(admin=False):
    user=current_user()
    if not user: return None,(jsonify(error="Требуется авторизация"),401)
    if admin and user["role"]!="admin": return None,(jsonify(error="Недостаточно прав"),403)
    return user,None

@app.after_request
def secure_headers(response):
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="same-origin"
    if request.path.startswith("/api/"): response.headers["Cache-Control"]="no-store"
    return response

@app.errorhandler(413)
def too_large(_): return jsonify(error="Файл или запрос слишком большой"),413

@app.get("/")
def index():
    raw=(ROOT/"navigator.html").read_text(encoding="utf-8")
    raw=raw.replace("</head>",'<meta http-equiv="Content-Security-Policy" content="default-src \'self\' data:; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; connect-src \'self\'">\n</head>')
    return Response(raw.replace("</body>",'<script src="/app-ui.js"></script>\n</body>'),mimetype="text/html")

@app.get("/app-ui.js")
def ui(): return Response((ROOT/"app-ui.js").read_text(),mimetype="application/javascript")

@app.get("/health")
def health():
    try:
        with db() as con, con.cursor() as cur: cur.execute("SELECT 1")
        return jsonify(ok=True)
    except Exception: return jsonify(ok=False),503

@app.get("/api/me")
def me(): return jsonify(user=current_user())

@app.post("/api/login")
def login():
    data=request.get_json(silent=True) or {}; login=str(data.get("login","")).strip(); password=str(data.get("password",""))
    if not LOGIN_RE.fullmatch(login) or len(password)<8: return jsonify(error="Логин: 3–32 символа; пароль: минимум 8 символов"),400
    now=int(time.time())
    with db() as con, con.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE lower(login)=lower(%s)",(login,)); found=cur.fetchone()
        if found:
            if found["blocked"]: return jsonify(error="Учетная запись заблокирована"),403
            if not pok(password,found["password_hash"]): return jsonify(error="Неверный логин или пароль"),401
            uid=found["id"]
        else:
            cur.execute("SELECT * FROM activation_codes WHERE used_at IS NULL FOR UPDATE"); match=next((x for x in cur.fetchall() if pok(password,x["code_hash"])),None)
            if not match: return jsonify(error="Неверный логин или пароль активации"),401
            cur.execute("INSERT INTO users(login,password_hash,role,created_at) VALUES(%s,%s,'user',%s) RETURNING id",(login,ph(password),now)); uid=cur.fetchone()["id"]
            cur.execute("UPDATE activation_codes SET used_at=%s,used_by=%s WHERE id=%s",(now,uid,match["id"]))
        token=secrets.token_urlsafe(32); cur.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(%s,%s,%s)",(token_hash(token),uid,now+86400))
    out=make_response(jsonify(ok=True)); out.set_cookie("ms_session",token,max_age=86400,httponly=True,secure=bool(os.environ.get("RENDER")),samesite="Strict"); return out

@app.post("/api/logout")
def logout():
    token=request.cookies.get("ms_session")
    if token:
        with db() as con, con.cursor() as cur: cur.execute("DELETE FROM sessions WHERE token_hash=%s",(token_hash(token),))
    out=make_response(jsonify(ok=True)); out.delete_cookie("ms_session"); return out

@app.post("/api/password")
def change_password():
    user,err=need()
    if err:return err
    password=str((request.get_json(silent=True) or {}).get("password",""))
    if len(password)<10:return jsonify(error="Новый пароль — минимум 10 символов"),400
    with db() as con,con.cursor() as cur:cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",(ph(password),user["id"]))
    return jsonify(ok=True)

@app.route("/api/comments",methods=["GET","POST"])
def comments():
    user,err=need()
    if err:return err
    with db() as con,con.cursor() as cur:
        if request.method=="POST":
            body=str((request.get_json(silent=True) or {}).get("body","")).strip()
            if not body or len(body)>3000:return jsonify(error="Комментарий: от 1 до 3000 символов"),400
            cur.execute("INSERT INTO comments(user_id,body,created_at) VALUES(%s,%s,%s)",(user["id"],body,int(time.time())));return jsonify(ok=True),201
        cur.execute("SELECT c.id,c.body,c.created_at,u.login FROM comments c JOIN users u ON u.id=c.user_id ORDER BY c.id DESC LIMIT 200")
        return jsonify(items=cur.fetchall())

@app.route("/api/homework",methods=["GET","POST"])
def homework():
    user,err=need()
    if err:return err
    with db() as con,con.cursor() as cur:
        if request.method=="POST":
            data=request.get_json(silent=True) or {}; title=str(data.get("title","")).strip(); body=str(data.get("body","")).strip(); att=data.get("attachment")
            if not title or len(title)>150 or len(body)>10000:return jsonify(error="Проверьте название и текст работы"),400
            filename=blob=mime=None
            if att:
                filename=Path(str(att.get("name","file"))).name[:180]; mime=str(att.get("type","application/octet-stream"))[:120]
                try:blob=base64.b64decode(att.get("data",""),validate=True)
                except:return jsonify(error="Некорректный файл"),400
                if len(blob)>5*1024*1024:return jsonify(error="Файл больше 5 МБ"),400
            cur.execute("INSERT INTO homework(user_id,title,body,filename,file_data,mime_type,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s)",(user["id"],title,body,filename,blob,mime,int(time.time())));return jsonify(ok=True),201
        if user["role"]=="admin":cur.execute("SELECT h.id,h.user_id,h.title,h.body,h.filename,h.status,h.admin_note,h.created_at,u.login FROM homework h JOIN users u ON u.id=h.user_id ORDER BY h.id DESC")
        else:cur.execute("SELECT h.id,h.user_id,h.title,h.body,h.filename,h.status,h.admin_note,h.created_at,u.login FROM homework h JOIN users u ON u.id=h.user_id WHERE h.user_id=%s ORDER BY h.id DESC",(user["id"],))
        return jsonify(items=cur.fetchall())

@app.get("/api/homework/file/<int:item_id>")
def homework_file(item_id):
    user,err=need()
    if err:return err
    with db() as con,con.cursor() as cur:cur.execute("SELECT user_id,filename,file_data,mime_type FROM homework WHERE id=%s",(item_id,));item=cur.fetchone()
    if not item or (user["role"]!="admin" and item["user_id"]!=user["id"]):return jsonify(error="Не найдено"),404
    if not item["file_data"]:return jsonify(error="Файл отсутствует"),404
    out=Response(bytes(item["file_data"]),mimetype=item["mime_type"] or mimetypes.guess_type(item["filename"])[0]);out.headers["Content-Disposition"]=f"attachment; filename*=UTF-8''{quote(item['filename'])}";return out

@app.get("/api/admin")
def admin_data():
    user,err=need(True)
    if err:return err
    with db() as con,con.cursor() as cur:
        cur.execute("SELECT id,login,role,blocked,created_at FROM users ORDER BY id");users=cur.fetchall()
        cur.execute("SELECT id,created_at,used_at,used_by FROM activation_codes ORDER BY id DESC LIMIT 100");codes=cur.fetchall()
    return jsonify(users=users,codes=codes)

@app.post("/api/admin/code")
def admin_code():
    user,err=need(True)
    if err:return err
    alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";code="".join(secrets.choice(alphabet) for _ in range(12))
    with db() as con,con.cursor() as cur:cur.execute("INSERT INTO activation_codes(code_hash,created_at,created_by) VALUES(%s,%s,%s)",(ph(code),int(time.time()),user["id"]))
    return jsonify(code=code),201

@app.post("/api/admin/block")
def admin_block():
    user,err=need(True)
    if err:return err
    data=request.get_json(silent=True) or {}
    try:uid=int(data.get("id"))
    except:return jsonify(error="Некорректный пользователь"),400
    if uid==user["id"]:return jsonify(error="Нельзя заблокировать себя"),400
    with db() as con,con.cursor() as cur:
        cur.execute("UPDATE users SET blocked=%s WHERE id=%s AND role!='admin'",(bool(data.get("blocked")),uid))
        if data.get("blocked"):cur.execute("DELETE FROM sessions WHERE user_id=%s",(uid,))
    return jsonify(ok=True)

@app.post("/api/admin/homework")
def admin_homework():
    user,err=need(True)
    if err:return err
    data=request.get_json(silent=True) or {};status=str(data.get("status",""));note=str(data.get("note","")).strip()[:3000]
    if status not in ("submitted","accepted","revision"):return jsonify(error="Некорректный статус"),400
    with db() as con,con.cursor() as cur:cur.execute("UPDATE homework SET status=%s,admin_note=%s WHERE id=%s",(status,note,int(data.get("id"))))
    return jsonify(ok=True)

if __name__=="__main__":
    init_db();app.run(host="0.0.0.0",port=int(os.environ.get("PORT","8080")))
