"""
Xtracker — Backend FastAPI avec API BrixHub
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import os, json, httpx, sqlite3, secrets, asyncio, time, random, hashlib, re, string, unicodedata
from collections import defaultdict

try:
    import psycopg2
    import psycopg2.extras
    USE_PG = True
except ImportError:
    USE_PG = False

# ── CONFIG ────────────────────────────────────────────────────────────────────
SECRET_KEY     = os.getenv("SECRET_KEY", "")
ADMIN_EMAIL    = os.getenv("ADMIN_EMAIL", "")
ALGORITHM      = "HS256"
TOKEN_EXPIRE   = 60 * 24 * 365

# ── BRIXHUB API ──────────────────────────────────────────────────────────────
BRIX_KEY       = os.getenv("BRIX_API_KEY", "")
BRIX_BASE      = "https://api.brixhub.ch/api/v1"

SUMUP_SK = os.getenv("SUMUP_SK", "")
SUMUP_PK = os.getenv("SUMUP_PK", "")
PAYGATE_WALLET_BTC = os.getenv("PAYGATE_WALLET_BTC", "")
PAYGATE_WALLET_LTC = os.getenv("PAYGATE_WALLET_LTC", "")
PAYGATE_WALLET_ETH = os.getenv("PAYGATE_WALLET_ETH", "")

DB_PATH        = "xtracker.db"
MAINTENANCE    = os.getenv("MAINTENANCE", "false").lower() == "true"
DATABASE_URL   = os.getenv("DATABASE_URL", "") or os.getenv("POSTGRES_URL", "")
CREDITS_ENABLED = os.getenv("CREDITS_ENABLED", "false").lower() == "true"

# ── AUTH ──────────────────────────────────────────────────────────────────────
pwd_ctx = CryptContext(schemes=["bcrypt"])
security = HTTPBearer(auto_error=False)

def create_token(data, role=None) -> str:
    if isinstance(data, dict):
        payload = data
    else:
        payload = {"sub": str(data), "role": role or "user"}
    payload["exp"] = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE)
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

def is_pg():
    return USE_PG and bool(DATABASE_URL)

def q(sql):
    if is_pg():
        return sql.replace("?", "%s").replace("INTEGER PRIMARY KEY AUTOINCREMENT","SERIAL PRIMARY KEY").replace("DATETIME","TIMESTAMP").replace("INSERT OR IGNORE","INSERT").replace("INSERT OR REPLACE","INSERT")
    return sql

def get_db():
    if is_pg():
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        conn.autocommit = False
        return conn
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def fetchone(db, sql, params=()):
    if is_pg():
        cur = db.cursor()
        cur.execute(q(sql), params)
        row = cur.fetchone()
        cur.close()
        return dict(row) if row else None
    row = db.execute(q(sql), params).fetchone()
    return dict(row) if row else None

def fetchall(db, sql, params=()):
    if is_pg():
        cur = db.cursor()
        cur.execute(q(sql), params)
        rows = cur.fetchall()
        cur.close()
        return [dict(r) for r in rows]
    return [dict(r) for r in db.execute(q(sql), params).fetchall()]

def execute(db, sql, params=()):
    if is_pg():
        cur = db.cursor()
        cur.execute(q(sql), params)
        try:
            result = cur.fetchone()
            db.commit()
            cur.close()
            return dict(result) if result else None
        except:
            db.commit()
            cur.close()
            return None
    return db.execute(q(sql), params)

# ── INIT DB ──────────────────────────────────────────────────────────────────
def init_db():
    db = get_db()
    if is_pg():
        cur = db.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, email TEXT UNIQUE, password TEXT, username TEXT UNIQUE,
            role TEXT DEFAULT 'user', credits INTEGER DEFAULT 0, free_left INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT NOW(), banned BOOLEAN DEFAULT FALSE,
            lifetime BOOLEAN DEFAULT FALSE, auth_type TEXT DEFAULT 'local',
            reg_ip TEXT, discord_id TEXT, discord_username TEXT,
            referral_code TEXT, referred_by INTEGER, theme TEXT DEFAULT 'default')""")
        cur.execute("""CREATE TABLE IF NOT EXISTS searches (
            id SERIAL PRIMARY KEY, user_id INTEGER, query_data TEXT,
            result_count INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())""")
        cur.execute("""CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY, user_id INTEGER, type TEXT, credits INTEGER DEFAULT 0,
            amount_eur REAL DEFAULT 0, stripe_id TEXT, status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT NOW())""")
        cur.execute("CREATE TABLE IF NOT EXISTS blocklist (id SERIAL PRIMARY KEY, type TEXT, value TEXT, created_at TIMESTAMP DEFAULT NOW())")
        cur.execute("CREATE TABLE IF NOT EXISTS ip_used (id SERIAL PRIMARY KEY, ip TEXT UNIQUE)")
        cur.execute("""CREATE TABLE IF NOT EXISTS tickets (
            id SERIAL PRIMARY KEY, user_id INTEGER, subject TEXT, status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT NOW())""")
        cur.execute("""CREATE TABLE IF NOT EXISTS ticket_messages (
            id SERIAL PRIMARY KEY, ticket_id INTEGER, user_id INTEGER, message TEXT,
            created_at TIMESTAMP DEFAULT NOW())""")
        cur.execute("""CREATE TABLE IF NOT EXISTS broadcasts (
            id SERIAL PRIMARY KEY, message TEXT, active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT NOW())""")
        cur.execute("CREATE TABLE IF NOT EXISTS broadcast_reads (id SERIAL PRIMARY KEY, broadcast_id INTEGER, user_id INTEGER, read_at TIMESTAMP DEFAULT NOW(), UNIQUE(broadcast_id, user_id))")
        cur.execute("CREATE TABLE IF NOT EXISTS announcements (id SERIAL PRIMARY KEY, message TEXT, active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW())")
        cur.execute("CREATE TABLE IF NOT EXISTS referrals (id SERIAL PRIMARY KEY, referrer_id INTEGER, referred_id INTEGER, credits_given INTEGER DEFAULT 5, created_at TIMESTAMP DEFAULT NOW())")
        cur.execute("CREATE TABLE IF NOT EXISTS discord_link_codes (id SERIAL PRIMARY KEY, user_id INTEGER, code TEXT UNIQUE, expires_at TIMESTAMP, used BOOLEAN DEFAULT FALSE)")
        cur.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS fiches (id SERIAL PRIMARY KEY, user_id INTEGER, name TEXT, created_at TIMESTAMP DEFAULT NOW())")
        cur.execute("CREATE TABLE IF NOT EXISTS fiche_persons (id SERIAL PRIMARY KEY, fiche_id INTEGER, data TEXT, added_at TIMESTAMP DEFAULT NOW())")
        db.commit()
        cur.close()
        print("✓ Base de données PostgreSQL initialisée")
    else:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT,
            username TEXT UNIQUE, role TEXT DEFAULT 'user', credits INTEGER DEFAULT 0,
            free_left INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            banned INTEGER DEFAULT 0, lifetime INTEGER DEFAULT 0,
            auth_type TEXT DEFAULT 'local', reg_ip TEXT, discord_id TEXT,
            discord_username TEXT, referral_code TEXT, referred_by INTEGER,
            theme TEXT DEFAULT 'default')""")
        db.execute("""CREATE TABLE IF NOT EXISTS searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, query_data TEXT,
            result_count INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        db.execute("""CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, type TEXT,
            credits INTEGER DEFAULT 0, amount_eur REAL DEFAULT 0, stripe_id TEXT,
            status TEXT DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        db.execute("CREATE TABLE IF NOT EXISTS blocklist (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, value TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        db.execute("CREATE TABLE IF NOT EXISTS ip_used (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE)")
        db.execute("CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, subject TEXT, status TEXT DEFAULT 'open', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        db.execute("CREATE TABLE IF NOT EXISTS ticket_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER, user_id INTEGER, message TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        db.execute("CREATE TABLE IF NOT EXISTS broadcasts (id INTEGER PRIMARY KEY AUTOINCREMENT, message TEXT, active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        db.execute("CREATE TABLE IF NOT EXISTS broadcast_reads (id INTEGER PRIMARY KEY AUTOINCREMENT, broadcast_id INTEGER, user_id INTEGER, read_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(broadcast_id, user_id))")
        db.execute("CREATE TABLE IF NOT EXISTS announcements (id INTEGER PRIMARY KEY AUTOINCREMENT, message TEXT, active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        db.execute("CREATE TABLE IF NOT EXISTS referrals (id INTEGER PRIMARY KEY AUTOINCREMENT, referrer_id INTEGER, referred_id INTEGER, credits_given INTEGER DEFAULT 5, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        db.execute("CREATE TABLE IF NOT EXISTS discord_link_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, code TEXT UNIQUE, expires_at DATETIME, used INTEGER DEFAULT 0)")
        db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS fiches (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        db.execute("CREATE TABLE IF NOT EXISTS fiche_persons (id INTEGER PRIMARY KEY AUTOINCREMENT, fiche_id INTEGER, data TEXT, added_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        db.commit()
        print("✓ Base de données SQLite initialisée (fallback)")
    db.close()

init_db()

# ── RATE LIMITING ──────────────────────────────────────────────────────────
_rate_limit = defaultdict(list)

def check_rate_limit(key: str, max_requests: int = 5, window: int = 60) -> bool:
    now = time.time()
    _rate_limit[key] = [t for t in _rate_limit[key] if now - t < window]
    if len(_rate_limit[key]) >= max_requests:
        return True
    _rate_limit[key].append(now)
    return False

# ── PROTECTED TERMS ──────────────────────────────────────────────────────────
PROTECTED_LASTNAMES = ["kocahal", "lauzet", "pacchioni"]
PROTECTED_PHONES    = ["0699407112", "0663435736"]

def get_all_blocked() -> list:
    blocked = []
    for n in PROTECTED_LASTNAMES:
        blocked.append({"type": "nom_famille", "value": n})
    for p in PROTECTED_PHONES:
        blocked.append({"type": "telephone", "value": p})
    try:
        db = get_db()
        rows = fetchall(db, "SELECT type, value FROM blocklist", ())
        db.close()
        blocked.extend([{"type": r["type"], "value": str(r["value"]).lower().strip()} for r in rows])
    except:
        pass
    return blocked

def normalize(val: str) -> str:
    return str(val or "").lower().strip().replace(" ", "").replace(".", "").replace("-", "")

def check_protected(payload: dict) -> bool:
    blocked = get_all_blocked()
    for b in blocked:
        btype = b["type"]
        bval = normalize(b["value"])
        if not bval:
            continue
        if btype in ("nom_famille", "general", "général", ""):
            for field in ["nom_famille", "prenom", "nom_naissance", "nom_affichage", "nom_utilisateur",
                          "email", "adresse", "ville", "societe", "profession"]:
                if bval in normalize(payload.get(field, "")):
                    return True
        elif btype in ("telephone", "mobile"):
            for field in ["telephone", "mobile"]:
                if bval in normalize(payload.get(field, "")):
                    return True
        elif btype == "email":
            if bval in normalize(payload.get("email", "")):
                return True
        elif btype == "adresse":
            if bval in normalize(payload.get("adresse", "")):
                return True
        elif btype == "nir":
            if bval in normalize(payload.get("nir", "")):
                return True
        elif btype == "iban":
            if bval in normalize(payload.get("iban", "")):
                return True
        elif btype == "plaque":
            if bval in normalize(payload.get("vin_plaque", "") + payload.get("immatriculation", "")):
                return True
        elif btype == "prenom":
            if bval == normalize(payload.get("prenom", "")):
                return True
        else:
            for v in payload.values():
                if isinstance(v, str) and bval in normalize(v):
                    return True
    return False

def filter_results(results: list) -> list:
    blocked = get_all_blocked()
    clean = []
    for p in results:
        is_blocked = False
        for b in blocked:
            bval = normalize(b["value"])
            if not bval:
                continue
            for field in ["nom_famille", "prenom", "email", "telephone", "mobile",
                          "adresse", "nir", "iban", "vin_plaque", "immatriculation",
                          "nom_naissance", "nom_affichage", "societe"]:
                if bval in normalize(p.get(field, "")):
                    is_blocked = True
                    break
            if is_blocked:
                break
        if not is_blocked:
            clean.append(p)
    return clean

# ── CREDIT PACKS ─────────────────────────────────────────────────────────────
CREDIT_PACKS = {
    "decouverte":  {"credits": 10,   "price_eur": 0.99,  "old_price": 2.99,  "label": "Decouverte"},
    "starter":     {"credits": 50,   "price_eur": 4.99,  "old_price": 9.99,  "label": "Starter"},
    "pro":         {"credits": 200,  "price_eur": 14.99, "old_price": 29.99,  "label": "Pro"},
    "enterprise":  {"credits": 1000, "price_eur": 49.99, "old_price": 99.99, "label": "Enterprise"},
    "lifetime":    {"credits": -1,   "price_eur": 149.00,"old_price": 299.00,"label": "Lifetime"},
}

# ── USER AUTH ──────────────────────────────────────────────────────────────────
async def get_current_user(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Token manquant")
    token = auth[7:]
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(401, "Token invalide")
    db = get_db()
    u = fetchone(db, "SELECT * FROM users WHERE id=?", (int(payload["sub"]),))
    db.close()
    if not u:
        raise HTTPException(401, "Utilisateur introuvable")
    if u.get("banned"):
        raise HTTPException(403, "Compte banni")
    return u

async def require_admin(request: Request):
    user = await get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Acces refuse")
    return user

def deduct_and_log(user_id: int, query_data: dict, result_count: int):
    db = get_db()
    user = fetchone(db, "SELECT free_left, credits, lifetime FROM users WHERE id=?", (user_id,))
    if not CREDITS_ENABLED:
        cost = 0
    elif user.get("lifetime"):
        cost = 0
    elif user["free_left"] > 0:
        execute(db, "UPDATE users SET free_left=free_left-1 WHERE id=?", (user_id,))
        cost = 0
    elif user["credits"] > 0:
        execute(db, "UPDATE users SET credits=credits-1 WHERE id=?", (user_id,))
        cost = 1
    else:
        db.close()
        raise HTTPException(402, "Plus de crédits")
    execute(db, "INSERT INTO searches (user_id, query_data, result_count, cost) VALUES (?,?,?,?)",
            (user_id, json.dumps(query_data), result_count, cost))
    db.commit()
    updated = fetchone(db, "SELECT free_left, credits FROM users WHERE id=?", (user_id,))
    db.close()
    return dict(updated)

# ── BRIXHUB API CALL ──────────────────────────────────────────────────────────
async def call_brix(method: str, path: str, body: dict = None):
    """Appelle l'API BrixHub"""
    headers = {
        "X-API-Key": BRIX_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Xtracker/1.0",
    }
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=True, http2=False) as client:
            if method == "POST":
                r = await client.post(f"{BRIX_BASE}{path}", json=body, headers=headers)
            else:
                r = await client.get(f"{BRIX_BASE}{path}", headers=headers)
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                raise HTTPException(500, "Reponse invalide de l API")
        elif r.status_code == 500:
            raise HTTPException(500, "Aucun resultat pour cette recherche")
        elif r.status_code == 403:
            raise HTTPException(403, "Erreur API 403 - cle invalide ou expiree")
        elif r.status_code == 429:
            raise HTTPException(429, "Trop de requetes, reessayez dans quelques secondes")
        elif r.status_code == 401:
            raise HTTPException(401, "Cle API invalide")
        else:
            raise HTTPException(r.status_code, f"Erreur API {r.status_code}")
    except httpx.TimeoutException:
        raise HTTPException(504, "Timeout - reessayez dans quelques secondes")
    except httpx.NetworkError:
        raise HTTPException(503, "Erreur reseau - service temporairement indisponible")

# ── CLASSES PYDANTIC ─────────────────────────────────────────────────────────
class SearchModel(BaseModel):
    nom_famille: str = ""
    prenom: str = ""
    nom_naissance: str = ""
    nom_affichage: str = ""
    nom_utilisateur: str = ""
    genre: str = ""
    date_naissance: str = ""
    annee_naissance: str = ""
    email: str = ""
    telephone: str = ""
    mobile: str = ""
    adresse: str = ""
    code_postal: str = ""
    ville: str = ""
    pays: str = ""
    region: str = ""
    departement: str = ""
    nir: str = ""
    iban: str = ""
    siret: str = ""
    siren: str = ""
    flexible: bool = True
    per_page: int = 100
    page: int = 1

class LookupModel(BaseModel):
    lookup: str = ""
    type: str = "email"

class AdminUserUpdate(BaseModel):
    role: str = None
    credits: int = None
    banned: bool = None
    lifetime: bool = None

class RegisterModel(BaseModel):
    username: str
    password: str
    ref_code: str = ""

class LoginModel(BaseModel):
    username: str
    password: str

# ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app = FastAPI(title="Xtracker API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def maintenance_middleware(request, call_next):
    path = request.url.path
    if (path.startswith("/api/admin") or 
        path.startswith("/api/auth") or 
        path == "/maintenance.html" or
        path.startswith("/static") or
        path == "/favicon.ico" or
        path.endswith(".js") or
        path.endswith(".css") or
        path.endswith(".png") or
        path.endswith(".jpg") or
        path == "/manifest.json" or
        path == "/sw.js"):
        return await call_next(request)
    maintenance = False
    try:
        db = get_db()
        row = fetchone(db, "SELECT value FROM settings WHERE key='maintenance_enabled'", ())
        db.close()
        maintenance = bool(row and row.get("value") == "true")
    except:
        maintenance = False
    if maintenance:
        if path in ["/admin.html", "/login.html", "/"]:
            return await call_next(request)
        try:
            auth = request.headers.get("authorization","")
            if auth.startswith("Bearer "):
                token = auth[7:]
                payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                if payload.get("role") == "admin":
                    return await call_next(request)
        except:
            pass
        try:
            db = get_db()
            msg_row = fetchone(db, "SELECT value FROM settings WHERE key='maintenance_message'", ())
            eta_row = fetchone(db, "SELECT value FROM settings WHERE key='maintenance_eta'", ())
            db.close()
            msg = msg_row.get("value","") if msg_row else ""
            eta = eta_row.get("value","") if eta_row else ""
        except:
            msg = ""
            eta = ""
        if path.startswith("/api/"):
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Maintenance en cours", "message": msg}, status_code=503)
        from fastapi.responses import RedirectResponse
        try:
            db2 = get_db()
            sat_row = fetchone(db2, "SELECT value FROM settings WHERE key='maintenance_started_at'", ())
            db2.close()
            started_at = sat_row.get("value","") if sat_row else ""
        except:
            started_at = ""
        params = ""
        if msg: params += f"?msg={msg}"
        if eta: params += ("&" if params else "?") + f"eta={eta}"
        if started_at: params += ("&" if params else "?") + f"started={started_at}"
        return RedirectResponse(url=f"/maintenance.html{params}")
    return await call_next(request)

# ── AUTH ENDPOINTS ────────────────────────────────────────────────────────────
@app.post("/api/auth/register")
async def register(data: RegisterModel, request: Request):
    ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.client.host
    if check_rate_limit(f"register:{ip}", max_requests=3, window=300):
        raise HTTPException(429, "Trop d'inscriptions depuis cette IP, réessayez dans 5 minutes")
    if len(data.username) < 2:
        raise HTTPException(400, "Nom d utilisateur trop court (2 caractères min)")
    if len(data.password) < 8:
        raise HTTPException(400, "Mot de passe trop court (8 caractères min)")
    if not re.match(r"^[a-zA-Z0-9_\-\.]{2,32}$", data.username):
        raise HTTPException(400, "Nom d utilisateur invalide (lettres, chiffres, _ - . uniquement)")
    uid_chars = string.ascii_uppercase + string.digits
    user_uid = "XT-" + "".join(secrets.choice(uid_chars) for _ in range(8))
    fake_email = data.username.lower() + "@xtracker.local"
    ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.client.host
    db = get_db()
    existing = fetchone(db, "SELECT id FROM users WHERE username=?", (data.username,))
    if existing:
        db.close()
        raise HTTPException(400, "Nom d utilisateur déjà pris")
    ip_used = fetchone(db, "SELECT id FROM ip_used WHERE ip=?", (ip,))
    free_left = 0 if ip_used else 5
    hashed = pwd_ctx.hash(data.password)
    if is_pg():
        db_id = execute(db, "INSERT INTO users (email, password, username, free_left, reg_ip) VALUES (?,?,?,?,?) RETURNING id", (fake_email, hashed, data.username, free_left, ip))
    else:
        db_id = execute(db, "INSERT INTO users (email, password, username, free_left, reg_ip) VALUES (?,?,?,?,?)", (fake_email, hashed, data.username, free_left, ip))
    if not ip_used:
        try:
            execute(db, "INSERT INTO ip_used (ip) VALUES (?)", (ip,))
        except:
            pass
    try:
        user_id_new = db_id if not is_pg() else (db_id[0] if db_id else None)
        if user_id_new:
            broads = fetchall(db, "SELECT id FROM broadcasts", ())
            for b in broads:
                try:
                    execute(db, "INSERT OR IGNORE INTO broadcast_reads (broadcast_id, user_id) VALUES (?,?)", (b["id"], user_id_new))
                except:
                    pass
    except:
        pass
    ref_code = data.ref_code.strip().upper() if hasattr(data, 'ref_code') and data.ref_code else None
    if ref_code and db_id:
        referrer = fetchone(db, "SELECT id, reg_ip FROM users WHERE referral_code=?", (ref_code,))
        if referrer and referrer["id"] != db_id:
            referrer_ip = referrer.get("reg_ip")
            if referrer_ip and referrer_ip == ip:
                print(f"[REFERRAL] Blocage auto-parrainage: même IP {ip}")
            else:
                already = fetchone(db, "SELECT id FROM referrals WHERE referrer_id=? AND id IN (SELECT id FROM referrals WHERE referred_id IN (SELECT id FROM users WHERE reg_ip=?))", (referrer["id"], ip))
                if already:
                    print(f"[REFERRAL] Blocage: IP {ip} déjà utilisée pour ce parrain")
                else:
                    execute(db, "UPDATE users SET referred_by=? WHERE id=?", (referrer["id"], db_id))
                    execute(db, "INSERT INTO referrals (referrer_id, referred_id, credits_earned) VALUES (?,?,?)", (referrer["id"], db_id, 5))
                    execute(db, "UPDATE users SET credits=credits+5 WHERE id=?", (referrer["id"],))
    db.commit()
    db.close()
    db2 = get_db()
    new_user = fetchone(db2, "SELECT id FROM users WHERE username=?", (data.username,))
    db2.close()
    real_id = new_user["id"] if new_user else None
    if not real_id:
        raise HTTPException(500, "Erreur creation compte")
    try:
        token = create_token(real_id, "user")
    except Exception as e:
        raise HTTPException(500, f"Erreur token: {str(e)} - real_id={real_id} - SECRET_KEY_len={len(SECRET_KEY)}")
    return {
        "token": token,
        "user_id": user_uid,
        "user": {
            "id": real_id,
            "email": fake_email,
            "username": data.username,
            "role": "user",
            "credits": 0,
            "free_left": free_left
        },
        "message": "Compte cree avec succes !"
    }

@app.post("/api/auth/login")
async def login(data: LoginModel, request: Request):
    ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.client.host
    if check_rate_limit(f"login:{ip}", max_requests=10, window=60):
        raise HTTPException(429, "Trop de tentatives, réessayez dans 1 minute")
    db = get_db()
    login_val = data.username.strip()
    if "@" in login_val and "xtracker.local" not in login_val.lower():
        user = fetchone(db, "SELECT * FROM users WHERE email=?", (login_val.lower(),))
        if user and (user.get("email") or "").startswith("discord_"):
            user = None
    else:
        user = fetchone(db, "SELECT * FROM users WHERE username=?", (login_val,))
        if user and (user.get("email") or "").startswith("discord_"):
            user = None
    if not user or not pwd_ctx.verify(data.password, user["password"]):
        db.close()
        raise HTTPException(401, "Email ou mot de passe incorrect")
    if user["banned"]:
        db.close()
        raise HTTPException(403, "Compte banni")
    from datetime import datetime as _dt
    _now = _dt.utcnow().isoformat()
    try:
        execute(db, "UPDATE users SET last_login=? WHERE id=?", (_now, user["id"]))
    except: pass
    db.commit()
    db.close()
    user = dict(user) if not isinstance(user, dict) else user
    token = create_token(user["id"], user["role"])
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "username": user["username"],
            "role": user["role"],
            "credits": user["credits"],
            "free_left": user["free_left"]
        }
    }

@app.get("/api/auth/me")
async def me(user=Depends(get_current_user)):
    return {
        "id": user["id"],
        "email": user["email"],
        "username": user["username"],
        "role": user["role"],
        "credits": user["credits"],
        "free_left": user["free_left"],
        "created_at": user["created_at"],
        "lifetime": bool(user.get("lifetime", False))
    }

# ── SEARCH ENDPOINT ──────────────────────────────────────────────────────────
@app.post("/api/search")
async def search(data: SearchModel, user=Depends(get_current_user)):
    if CREDITS_ENABLED and not user.get("lifetime") and user["free_left"] <= 0 and user["credits"] <= 0:
        raise HTTPException(402, "Plus de crédits")

    payload = {"flexible": data.flexible, "per_page": 100}
    fields = [
        "nom_famille","prenom","nom_naissance","nom_affichage","nom_utilisateur","genre","civilite",
        "jour_naissance","mois_naissance","annee_naissance","date_naissance","ville_naissance","lieu_naissance",
        "email","telephone","mobile","adresse_ip",
        "adresse","complement_adresse","code_postal","ville","departement","region","pays",
        "nir","iban","bic","siret","siren",
        "vin_plaque","immatriculation","marque","modele",
        "societe","profession","fonction"
    ]
    for f in fields:
        val = getattr(data, f, None)
        if val:
            payload[f] = val
    for k in list(payload.keys()):
        if k not in ('flexible','per_page') and isinstance(payload[k], str) and len(payload[k].strip()) < 2:
            del payload[k]
    if len(payload) <= 2:
        raise HTTPException(400, "Remplissez au moins un champ (2 caractères minimum)")

    def clean_field(val):
        if not isinstance(val, str):
            return val
        val = unicodedata.normalize('NFC', val)
        val = ''.join(c for c in val if unicodedata.category(c) != 'Cc')
        return val.strip()
    for k in list(payload.keys()):
        if isinstance(payload[k], str):
            payload[k] = clean_field(payload[k])

    if check_protected(payload):
        return {
            "results": [],
            "total": 0,
            "took_ms": 0,
            "free_left": user["free_left"],
            "credits": user["credits"],
            "protected": True,
            "message": "Ahah bien essayé mais j'y suis pas 😏"
        }

    result = await call_brix("POST", "/search", payload)
    results = result.get("data", {}).get("results", [])
    results = filter_results(results)

    # Pivot famille
    for p in results[:5]:
        famille = []
        pivot_done = set()

        if p.get("adresse") and p.get("code_postal"):
            pivot_key = f"adresse_{p['adresse']}_{p['code_postal']}"
            if pivot_key not in pivot_done:
                pivot_done.add(pivot_key)
                try:
                    pivot_payload = {
                        "adresse": p["adresse"],
                        "code_postal": p["code_postal"],
                        "flexible": False,
                        "per_page": 10
                    }
                    pivot_result = await call_brix("POST", "/search", pivot_payload)
                    pivot_results = pivot_result.get("data", {}).get("results", [])
                    for pr in pivot_results:
                        if pr.get("nom_famille") == p.get("nom_famille") and pr.get("prenom") == p.get("prenom"):
                            continue
                        membre = {
                            "prenom": pr.get("prenom", ""),
                            "nom_famille": pr.get("nom_famille", ""),
                            "date_naissance": pr.get("date_naissance", ""),
                            "email": pr.get("email", ""),
                            "telephone": pr.get("telephone", ""),
                            "lien": "Même adresse",
                            "_sources": pr.get("_sources", [])
                        }
                        if not any(m["prenom"] == membre["prenom"] and m["nom_famille"] == membre["nom_famille"] for m in famille):
                            famille.append(membre)
                except:
                    pass

        if p.get("telephone") and len(famille) < 5:
            pivot_key = f"tel_{p['telephone']}"
            if pivot_key not in pivot_done:
                pivot_done.add(pivot_key)
                try:
                    pivot_payload = {
                        "telephone": p["telephone"],
                        "flexible": False,
                        "per_page": 5
                    }
                    pivot_result = await call_brix("POST", "/search", pivot_payload)
                    pivot_results = pivot_result.get("data", {}).get("results", [])
                    for pr in pivot_results:
                        if pr.get("nom_famille") == p.get("nom_famille") and pr.get("prenom") == p.get("prenom"):
                            continue
                        membre = {
                            "prenom": pr.get("prenom", ""),
                            "nom_famille": pr.get("nom_famille", ""),
                            "date_naissance": pr.get("date_naissance", ""),
                            "email": pr.get("email", ""),
                            "telephone": pr.get("telephone", ""),
                            "lien": "Téléphone partagé",
                            "_sources": pr.get("_sources", [])
                        }
                        if not any(m["prenom"] == membre["prenom"] and m["nom_famille"] == membre["nom_famille"] for m in famille):
                            famille.append(membre)
                except:
                    pass

        if famille:
            p["famille"] = famille

    updated = deduct_and_log(user["id"], payload, len(results))
    return {
        "results": results,
        "total": result.get("meta", {}).get("total", 0),
        "took_ms": result.get("meta", {}).get("took_ms", 0),
        "free_left": updated["free_left"],
        "credits": updated["credits"],
    }

# ── LOOKUP ENDPOINT ──────────────────────────────────────────────────────────
@app.post("/api/lookup")
async def lookup(data: LookupModel, user=Depends(get_current_user)):
    if CREDITS_ENABLED and not user.get("lifetime") and user["free_left"] <= 0 and user["credits"] <= 0:
        raise HTTPException(402, "Plus de crédits")
    val = data.lookup.strip()

    if "@" in val:
        path = f"/lookup/email/{val}"
    elif val.upper().startswith("FR") and len(val) > 20:
        path = f"/lookup/iban/{val}"
    else:
        path = f"/lookup/phone/{val.replace(' ', '').replace('.', '').replace('-', '')}"

    result = await call_brix("GET", path)
    results = result.get("data", {}).get("results", [])
    updated = deduct_and_log(user["id"], {"lookup": val}, len(results))
    return {
        "results": results,
        "total": result.get("meta", {}).get("total", 0),
        "free_left": updated["free_left"],
        "credits": updated["credits"],
    }

# ── PLAQUE ────────────────────────────────────────────────────────────────────
@app.get("/api/lookup/plaque/{plaque}")
async def lookup_plaque(plaque: str, user=Depends(get_current_user)):
    if CREDITS_ENABLED and not user.get("lifetime") and user["free_left"] <= 0 and user["credits"] <= 0:
        raise HTTPException(402, "Plus de crédits")
    plaque_clean = plaque.upper().replace("-", "").replace(" ", "")
    try:
        result = await call_brix("POST", "/search", {
            "vin_plaque": plaque_clean,
            "flexible": False,
            "per_page": 5
        })
        results = result.get("data", {}).get("results", [])
        results = filter_results(results)
        vehicles = []
        for r in results:
            if r.get("vin_plaque") or r.get("immatriculation") or r.get("marque"):
                vehicles.append({
                    "plaque": r.get("vin_plaque") or r.get("immatriculation", plaque_clean),
                    "marque": r.get("marque", ""),
                    "modele": r.get("modele", ""),
                    "proprietaire": f"{r.get('prenom','')} {r.get('nom_famille','')}".strip(),
                    "adresse": r.get("adresse", ""),
                    "ville": r.get("ville", ""),
                    "code_postal": r.get("code_postal", ""),
                    "date_naissance": r.get("date_naissance", ""),
                    "sources": r.get("_sources", [])
                })
        if results:
            updated = deduct_and_log(user["id"], {"vin_plaque": plaque_clean}, len(results))
        return {
            "plaque": plaque_clean,
            "results": vehicles,
            "raw": results,
            "total": len(results),
            "free_left": user["free_left"],
            "credits": user["credits"]
        }
    except Exception as e:
        raise HTTPException(500, str(e))

# ── HISTORY ────────────────────────────────────────────────────────────────────
@app.get("/api/history")
async def history(user=Depends(get_current_user)):
    db = get_db()
    rows = fetchall(db, "SELECT id, query_data, result_count, cost, created_at FROM searches WHERE user_id=? ORDER BY created_at DESC LIMIT 50", (user["id"],))
    db.close()
    return rows

@app.post("/api/history/{search_id}/replay")
async def history_replay(search_id: int, user=Depends(get_current_user)):
    db = get_db()
    row = fetchone(db, "SELECT query_data FROM searches WHERE id=? AND user_id=?", (search_id, user["id"]))
    db.close()
    if not row:
        raise HTTPException(404, "Recherche introuvable")
    payload = json.loads(row["query_data"])
    payload["per_page"] = 100
    if check_protected(payload):
        return {"results": [], "total": 0, "took_ms": 0, "free_left": user["free_left"], "credits": user["credits"]}
    result = await call_brix("POST", "/search", payload)
    results = result.get("data", {}).get("results", [])
    results = filter_results(results)
    for p in results[:5]:
        famille = []
        if p.get("adresse") and p.get("code_postal"):
            try:
                pr = await call_brix("POST", "/search", {"adresse": p["adresse"], "code_postal": p["code_postal"], "flexible": False, "per_page": 100})
                for m in pr.get("data", {}).get("results", []):
                    if m.get("nom_famille") == p.get("nom_famille") and m.get("prenom") == p.get("prenom"):
                        continue
                    membre = {"prenom": m.get("prenom",""), "nom_famille": m.get("nom_famille",""), "date_naissance": m.get("date_naissance",""), "email": m.get("email",""), "telephone": m.get("telephone",""), "lien": "Meme adresse"}
                    if not any(x["prenom"]==membre["prenom"] and x["nom_famille"]==membre["nom_famille"] for x in famille):
                        famille.append(membre)
            except: pass
        if famille:
            p["famille"] = famille
    return {
        "results": results,
        "total": result.get("meta", {}).get("total", 0),
        "took_ms": result.get("meta", {}).get("took_ms", 0),
        "free_left": user["free_left"],
        "credits": user["credits"],
    }

# ── CREDITS & STRIPE ──────────────────────────────────────────────────────────
@app.post("/api/credits/confirm")
async def confirm_paygate(request: Request, user=Depends(get_current_user)):
    body = await request.json()
    credits = int(body.get("credits", 0))
    pack_id = body.get("pack_id", "")
    order_id = body.get("order_id", "")
    if credits <= 0 or not order_id:
        raise HTTPException(400, "Données invalides")
    pack = CREDIT_PACKS.get(pack_id, {})
    amount = pack.get("price_eur", 0)
    db = get_db()
    existing = fetchone(db, "SELECT id FROM transactions WHERE stripe_id=?", (order_id,))
    if existing:
        db.close()
        return {"message": "Déjà traité"}
    execute(db, "UPDATE users SET credits=credits+? WHERE id=?", (credits, user["id"]))
    execute(db, """
        INSERT INTO transactions (user_id, type, credits, amount_eur, stripe_id, status)
        VALUES (?,?,?,?,?,'completed')
    """, (user["id"], "purchase", credits, amount, order_id))
    db.commit()
    db.close()
    return {"message": "Crédits ajoutés", "credits": credits}

@app.get("/api/credits/packs")
async def get_packs():
    return CREDIT_PACKS

@app.post("/api/credits/checkout/{pack_id}")
async def checkout(pack_id: str, user=Depends(get_current_user), request: Request = None):
    if pack_id not in CREDIT_PACKS:
        raise HTTPException(400, "Pack invalide")
    pack = CREDIT_PACKS[pack_id]
    origin = str(request.base_url).rstrip("/")
    amount = pack["price_eur"]
    credits = pack["credits"]
    import time
    order_id = f"xtracker-{user['id']}-{pack_id}-{credits}-{int(time.time())}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                "https://api.sumup.com/v0.1/checkouts",
                headers={
                    "Authorization": f"Bearer {SUMUP_SK}",
                    "Content-Type": "application/json",
                },
                json={
                    "checkout_reference": order_id,
                    "amount": amount,
                    "currency": "EUR",
                    "description": f"Xtracker {pack['label']} - {credits} credits",
                    "pay_to_email": "julien.kocahal@icloud.com",
                    "redirect_url": f"{origin}/api/sumup/success?order_id={order_id}&uid={user['id']}&credits={credits}&pack={pack_id}",
                    "hosted_checkout": {"enabled": True},
                }
            )
            data = r.json()
            if r.status_code not in [200, 201]:
                raise HTTPException(500, str(data))
            checkout_url = data.get("hosted_checkout_url") or f"https://checkout.sumup.com/pay/{data.get('id')}"
            return {"checkout_url": checkout_url}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/api/sumup/success")
async def sumup_success(request: Request):
    from fastapi.responses import RedirectResponse
    params = dict(request.query_params)
    order_id = params.get("order_id", "")
    uid = int(params.get("uid", 0))
    pack_id = params.get("pack", "")
    if not order_id or not uid or not pack_id:
        return RedirectResponse(url="/dashboard.html?payment=cancel")
    pack = CREDIT_PACKS.get(pack_id, {})
    if not pack:
        return RedirectResponse(url="/dashboard.html?payment=cancel")
    credits = pack["credits"]
    amount = pack["price_eur"]
    try:
        sumup_key = os.getenv("SUMUP_SK", "")
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://api.sumup.com/v0.1/checkouts/{order_id}",
                headers={"Authorization": f"Bearer {sumup_key}"}
            )
            if r.status_code != 200:
                print(f"[SUMUP] Checkout introuvable: {order_id} status={r.status_code}")
                return RedirectResponse(url="/dashboard.html?payment=cancel")
            checkout_data = r.json()
            status = checkout_data.get("status", "")
            paid_amount = float(checkout_data.get("amount", 0))
            currency = checkout_data.get("currency", "")
            print(f"[SUMUP] Checkout {order_id}: status={status} amount={paid_amount} {currency}")
            if status != "PAID":
                print(f"[SUMUP] Paiement non complete: {status}")
                return RedirectResponse(url="/dashboard.html?payment=cancel")
            if abs(paid_amount - amount) > 0.01:
                print(f"[SUMUP] Montant incorrect: attendu {amount} recu {paid_amount}")
                return RedirectResponse(url="/dashboard.html?payment=cancel")
        db = get_db()
        existing = fetchone(db, "SELECT id FROM transactions WHERE stripe_id=?", (order_id,))
        if not existing:
            if pack_id == "lifetime":
                execute(db, "UPDATE users SET lifetime=TRUE, credits=999999 WHERE id=?", (uid,))
            else:
                execute(db, "UPDATE users SET credits=credits+? WHERE id=?", (credits, uid))
            execute(db, "INSERT INTO transactions (user_id, type, credits, amount_eur, stripe_id, status) VALUES (?,?,?,?,?,'completed')",
                    (uid, "purchase", credits, amount, order_id))
            db.commit()
        else:
            print(f"[SUMUP] Transaction deja traitee: {order_id}")
        db.close()
    except Exception as e:
        print(f"[SUMUP] Erreur verification: {e}")
        return RedirectResponse(url="/dashboard.html?payment=cancel")
    return RedirectResponse(url="/dashboard.html?payment=success")

@app.get("/api/transactions")
async def transactions(user=Depends(get_current_user)):
    db = get_db()
    rows = fetchall(db, "SELECT id, type, credits, amount_eur, status, created_at FROM transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 20", (user["id"],))
    db.close()
    return rows

# ── ADMIN ─────────────────────────────────────────────────────────────────────
@app.get("/api/admin/stats")
async def admin_stats(admin=Depends(require_admin)):
    db = get_db()
    def cnt(sql, p=()):
        if is_pg():
            cur=db.cursor()
            cur.execute(q(sql), p)
            r=cur.fetchone()
            cur.close()
            return list(r.values())[0] if r else 0
        return db.execute(q(sql), p).fetchone()[0]
    total_users = cnt("SELECT COUNT(*) FROM users")
    new_today = cnt("SELECT COUNT(*) FROM users WHERE date(created_at)=CURRENT_DATE") if is_pg() else cnt("SELECT COUNT(*) FROM users WHERE date(created_at)=date('now')")
    total_searches = cnt("SELECT COUNT(*) FROM searches")
    searches_today = cnt("SELECT COUNT(*) FROM searches WHERE date(created_at)=CURRENT_DATE") if is_pg() else cnt("SELECT COUNT(*) FROM searches WHERE date(created_at)=date('now')")
    revenue = cnt("SELECT COALESCE(SUM(amount_eur),0) FROM transactions WHERE status='completed'")
    banned = cnt("SELECT COUNT(*) FROM users WHERE banned=TRUE") if is_pg() else cnt("SELECT COUNT(*) FROM users WHERE banned=1")
    try:
        discord_linked = cnt("SELECT COUNT(*) FROM users WHERE discord_id IS NOT NULL AND discord_id != ''")
    except:
        discord_linked = 0
    try:
        lifetime_users = cnt("SELECT COUNT(*) FROM users WHERE lifetime=TRUE") if is_pg() else cnt("SELECT COUNT(*) FROM users WHERE lifetime=1")
    except:
        lifetime_users = 0
    db.close()
    return {
        "total_users": total_users,
        "new_today": new_today,
        "total_searches": total_searches,
        "searches_today": searches_today,
        "revenue_eur": float(revenue),
        "banned": banned,
        "discord_linked": discord_linked,
        "lifetime_users": lifetime_users,
    }

@app.get("/api/admin/users")
async def admin_users(admin=Depends(require_admin), page: int = 1, search: str = ""):
    db = get_db()
    offset = (page - 1) * 20
    if search:
        rows = fetchall(db, "SELECT u.id,u.email,u.username,u.role,u.credits,u.free_left,u.created_at,u.last_login,u.banned,u.reg_ip,u.lifetime,u.discord_username,(SELECT COUNT(*) FROM users u2 WHERE u2.reg_ip=u.reg_ip AND u.reg_ip IS NOT NULL) as ip_count FROM users u WHERE u.email LIKE ? OR u.username LIKE ? ORDER BY u.created_at DESC LIMIT 20 OFFSET ?", (f"%{search}%", f"%{search}%", offset))
        total_r = fetchone(db, "SELECT COUNT(*) as c FROM users WHERE email LIKE ? OR username LIKE ?", (f"%{search}%", f"%{search}%"))
    else:
        rows = fetchall(db, "SELECT u.id,u.email,u.username,u.role,u.credits,u.free_left,u.created_at,u.last_login,u.banned,u.reg_ip,u.lifetime,u.discord_username,(SELECT COUNT(*) FROM users u2 WHERE u2.reg_ip=u.reg_ip AND u.reg_ip IS NOT NULL) as ip_count FROM users u ORDER BY u.created_at DESC LIMIT 20 OFFSET ?", (offset,))
        total_r = fetchone(db, "SELECT COUNT(*) as c FROM users", ())
    total = total_r["c"] if total_r else 0
    db.close()
    return {"users": rows, "total": total}

@app.patch("/api/admin/users/{user_id}")
async def admin_update(user_id: int, data: AdminUserUpdate, admin=Depends(require_admin)):
    db = get_db()
    target = fetchone(db, "SELECT email FROM users WHERE id=?", (user_id,))
    if ADMIN_EMAIL and target and target.get("email") == ADMIN_EMAIL:
        if data.banned is not None or data.role is not None:
            db.close()
            raise HTTPException(403, "Ce compte admin ne peut pas être modifié")
    if data.credits is not None:
        safe_credits = min(int(data.credits), 1000)
        execute(db, "UPDATE users SET credits=credits+? WHERE id=?", (safe_credits, user_id))
    if data.banned is not None:
        banned_val = data.banned if is_pg() else (1 if data.banned else 0)
        execute(db, "UPDATE users SET banned=? WHERE id=?", (banned_val, user_id))
    if data.role is not None:
        execute(db, "UPDATE users SET role=? WHERE id=?", (data.role, user_id))
    db.commit()
    db.close()
    return {"message": "Mis à jour"}

@app.delete("/api/admin/users/{user_id}")
async def admin_delete(user_id: int, admin=Depends(require_admin)):
    db = get_db()
    try: execute(db, "DELETE FROM searches WHERE user_id=?", (user_id,))
    except: pass
    try: execute(db, "DELETE FROM transactions WHERE user_id=?", (user_id,))
    except: pass
    try: execute(db, "DELETE FROM ticket_messages WHERE ticket_id IN (SELECT id FROM tickets WHERE user_id=?)", (user_id,))
    except: pass
    try: execute(db, "DELETE FROM tickets WHERE user_id=?", (user_id,))
    except: pass
    try: execute(db, "DELETE FROM broadcast_reads WHERE user_id=?", (user_id,))
    except: pass
    try: execute(db, "DELETE FROM fiche_persons WHERE fiche_id IN (SELECT id FROM fiches WHERE user_id=?)", (user_id,))
    except: pass
    try: execute(db, "DELETE FROM fiches WHERE user_id=?", (user_id,))
    except: pass
    execute(db, "DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    db.close()
    return {"message": "Supprime"}

@app.post("/api/admin/users/{user_id}/add-credits")
async def admin_add_credits(user_id: int, request: Request, admin=Depends(require_admin)):
    body = await request.json()
    credits = min(int(body.get("credits", 0)), 1000)
    db = get_db()
    execute(db, "UPDATE users SET credits=credits+? WHERE id=?", (credits, user_id))
    execute(db, "INSERT INTO transactions (user_id,type,credits,amount_eur,status) VALUES (?,?,?,0,'completed')", (user_id, "admin_grant", credits))
    db.commit()
    db.close()
    return {"message": f"{credits} crédits ajoutés"}

@app.get("/api/admin/searches")
async def admin_searches(admin=Depends(require_admin), page: int = 1):
    db = get_db()
    offset = (page - 1) * 50
    rows = fetchall(db, "SELECT s.id, s.query_data, s.result_count, s.cost, s.created_at, u.email, u.username FROM searches s JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC LIMIT 50 OFFSET ?", (offset,))
    db.close()
    return rows

@app.get("/api/admin/history")
async def admin_history(admin=Depends(require_admin), page: int = 1):
    db = get_db()
    offset = (page - 1) * 50
    rows = fetchall(db, "SELECT s.id, s.query_data, s.result_count, s.cost, s.created_at, u.email, u.username FROM searches s JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC LIMIT 50 OFFSET ?", (offset,))
    db.close()
    return rows

@app.get("/api/admin/transactions")
async def admin_tx(admin=Depends(require_admin)):
    db = get_db()
    rows = fetchall(db, "SELECT t.id, t.type, t.credits, t.amount_eur, t.status, t.created_at, u.email, u.username FROM transactions t JOIN users u ON t.user_id=u.id ORDER BY t.created_at DESC LIMIT 100")
    db.close()
    return rows

@app.get("/api/admin/blocklist")
async def get_blocklist(admin=Depends(require_admin)):
    db = get_db()
    rows = fetchall(db, "SELECT id, type, value, reason, created_at FROM blocklist ORDER BY created_at DESC", ())
    db.close()
    return rows

@app.post("/api/admin/blocklist")
async def add_blocklist(request: Request, admin=Depends(require_admin)):
    body = await request.json()
    btype = body.get("type", "nom_famille")
    value = body.get("value", "").strip().lower()
    reason = body.get("reason", "")
    if not value:
        raise HTTPException(400, "Valeur requise")
    db = get_db()
    execute(db, "INSERT INTO blocklist (type, value, reason) VALUES (?,?,?)", (btype, value, reason))
    db.commit()
    db.close()
    return {"message": "Ajouté à la blocklist"}

@app.delete("/api/admin/blocklist/{item_id}")
async def delete_blocklist(item_id: int, admin=Depends(require_admin)):
    db = get_db()
    execute(db, "DELETE FROM blocklist WHERE id=?", (item_id,))
    db.commit()
    db.close()
    return {"message": "Supprimé"}

@app.post("/api/admin/maintenance")
async def set_maintenance(request: Request, admin=Depends(require_admin)):
    body = await request.json()
    enabled = body.get("enabled", False)
    message = body.get("message", "")
    eta_minutes = body.get("eta_minutes", 0)
    db = get_db()
    try:
        import time as _time
        start_at = str(int(_time.time())) if enabled else ""
        if is_pg():
            cur = db.cursor()
            cur.execute("INSERT INTO settings (key, value) VALUES ('maintenance_enabled', %s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", ("true" if enabled else "false",))
            cur.execute("INSERT INTO settings (key, value) VALUES ('maintenance_message', %s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", (message,))
            cur.execute("INSERT INTO settings (key, value) VALUES ('maintenance_eta', %s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", (str(eta_minutes) if eta_minutes else "",))
            cur.execute("INSERT INTO settings (key, value) VALUES ('maintenance_started_at', %s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", (start_at,))
            cur.close()
        else:
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('maintenance_enabled', ?)", ("true" if enabled else "false",))
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('maintenance_message', ?)", (message,))
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('maintenance_eta', ?)", (str(eta_minutes) if eta_minutes else "",))
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('maintenance_started_at', ?)", (start_at,))
        db.commit()
    except Exception as e:
        print(f"[MAINTENANCE] Erreur: {e}")
    db.close()
    return {"maintenance": enabled, "message": "Maintenance " + ("activee" if enabled else "desactivee")}

@app.get("/api/admin/maintenance/status")
async def get_maintenance(admin=Depends(require_admin)):
    try:
        db = get_db()
        row = fetchone(db, "SELECT value FROM settings WHERE key='maintenance_enabled'", ())
        msg_row = fetchone(db, "SELECT value FROM settings WHERE key='maintenance_message'", ())
        eta_row = fetchone(db, "SELECT value FROM settings WHERE key='maintenance_eta'", ())
        db.close()
        status = bool(row and row.get("value") == "true")
        started_row = fetchone(db, "SELECT value FROM settings WHERE key='maintenance_started_at'", ())
        started_at = int(started_row.get("value",0)) if started_row and started_row.get("value") else 0
        return {
            "enabled": status,
            "maintenance": status,
            "message": msg_row.get("value","") if msg_row else "",
            "eta_minutes": int(eta_row.get("value",0)) if eta_row and eta_row.get("value") else 0,
            "started_at": started_at
        }
    except Exception as e:
        return {"enabled": False, "maintenance": False, "message": "", "eta_minutes": 0}

# ── STATIC ────────────────────────────────────────────────────────────────────
app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
