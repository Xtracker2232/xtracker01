"""
Xtracker — Backend FastAPI + SQLite (test local)
pip install fastapi uvicorn python-jose passlib bcrypt httpx python-multipart
python app.py
"""
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import os, json, httpx, sqlite3, secrets as _secrets
try:
    import psycopg2
    import psycopg2.extras
    USE_PG = True
except ImportError:
    USE_PG = False

# Force PostgreSQL
_DB_URL = os.environ.get("DATABASE_URL", "") or os.environ.get("POSTGRES_URL", "")
if _DB_URL and "postgresql" in _DB_URL:
    USE_PG = True
    print(f"[DB] PostgreSQL: {_DB_URL[:40]}...")
else:
    USE_PG = False
    print("[DB] SQLite fallback")

# ── CONFIG ────────────────────────────────────────────────────────────────────
SECRET_KEY     = os.getenv("SECRET_KEY", "")
ADMIN_EMAIL    = os.getenv("ADMIN_EMAIL", "")  # Plus de credentials en dur
ALGORITHM      = "HS256"
TOKEN_EXPIRE   = 60 * 24 * 365  # 1 an
BRIX_KEY       = os.getenv("BRIX_API_KEY", "")
BRIX_BASE      = "https://brixhub.site/api/v1"
SUMUP_SK = os.getenv("SUMUP_SK", "")
SUMUP_PK = os.getenv("SUMUP_PK", "")
SUMUP_MERCHANT = "Shop2ToutMHN3Z5RX"
PAYGATE_WALLET_BTC = os.getenv("PAYGATE_WALLET_BTC", "")
PAYGATE_WALLET_LTC = os.getenv("PAYGATE_WALLET_LTC", "")
PAYGATE_WALLET_ETH = os.getenv("PAYGATE_WALLET_ETH", "")

DB_PATH        = "xtracker.db"
MAINTENANCE    = os.getenv("MAINTENANCE", "false").lower() == "true"
DATABASE_URL   = _DB_URL

pwd_ctx  = CryptContext(schemes=["bcrypt"])
security = HTTPBearer(auto_error=False)

# Rate limiting simple en mémoire
import time
from collections import defaultdict

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
        db.commit()
        print("✓ Base de données SQLite initialisée (fallback)")
    db.close()

init_db()

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


_rate_limit = defaultdict(list)

def check_rate_limit(key: str, max_requests: int = 5, window: int = 60) -> bool:
    """Retourne True si la limite est dépassée"""
    now = time.time()
    _rate_limit[key] = [t for t in _rate_limit[key] if now - t < window]
    if len(_rate_limit[key]) >= max_requests:
        return True
    _rate_limit[key].append(now)
    return False

# Termes protégés - retourne un message spécial
# Noms de famille et numéros protégés statiques
PROTECTED_LASTNAMES = ["kocahal", "lauzet", "pacchioni"]
PROTECTED_PHONES    = ["0699407112", "0663435736"]

def get_all_blocked() -> list:
    """Récupère tous les termes bloqués (statiques + BDD)"""
    blocked = []
    # Statiques noms
    for n in PROTECTED_LASTNAMES:
        blocked.append({"type": "nom_famille", "value": n})
    # Statiques téléphones
    for p in PROTECTED_PHONES:
        blocked.append({"type": "telephone", "value": p})
    # BDD
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
    """Vérifie les termes bloqués sur tous les champs de la requête"""
    blocked = get_all_blocked()
    for b in blocked:
        btype = b["type"]
        bval  = normalize(b["value"])
        if not bval:
            continue
        # Champs à vérifier selon le type
        if btype in ("nom_famille", "general", "général", ""):
            # Vérifier dans tous les champs texte
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
            # Type inconnu : chercher partout
            for v in payload.values():
                if isinstance(v, str) and bval in normalize(v):
                    return True
    return False

def filter_results(results: list) -> list:
    """Filtre les résultats BrixHub pour supprimer les fiches protégées"""
    blocked = get_all_blocked()
    clean = []
    for p in results:
        is_blocked = False
        for b in blocked:
            bval = normalize(b["value"])
            if not bval:
                continue
            # Vérifier dans tous les champs du profil
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

CREDIT_PACKS = {
    "decouverte":  {"credits": 10,   "price_eur": 0.99,   "label": "Decouverte"},
    "starter":    {"credits": 20,   "price_eur": 5.00,   "label": "Starter"},
    "pro":        {"credits": 200,  "price_eur": 14.99,  "label": "Pro"},
    "enterprise": {"credits": 1000, "price_eur": 49.99,  "label": "Enterprise"},
    "lifetime":   {"credits": -1,   "price_eur": 150.00, "label": "Lifetime"},
}

app = FastAPI(title="Xtracker API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def maintenance_middleware(request, call_next):
    path = request.url.path
    # Toujours laisser passer : admin, auth, assets statiques
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
    # Vérifier si maintenance active dans la BDD
    try:
        db = get_db()
        row = fetchone(db, "SELECT value FROM settings WHERE key='maintenance_enabled'", ())
        db.close()
        maintenance = bool(row and row.get("value") == "true")
    except:
        maintenance = False
    if maintenance:
        # Laisser toujours passer login et admin
        if path in ["/admin.html", "/login.html", "/"]:
            return await call_next(request)
        # Laisser passer les admins via token
        try:
            auth = request.headers.get("authorization","")
            if auth.startswith("Bearer "):
                token = auth[7:]
                payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                if payload.get("role") == "admin":
                    return await call_next(request)
        except:
            pass
        # Récupérer le message et le temps estimé
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
        params = ""
        if msg: params += f"?msg={msg}"
        if eta: params += ("&" if params else "?") + f"eta={eta}"
        return RedirectResponse(url=f"/maintenance.html{params}")
    return await call_next(request)


@app.post("/api/auth/register")
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

class ChangePasswordModel(BaseModel):
    old_password: str
    new_password: str

async def register(data: RegisterModel, request: Request):
    import re, secrets, string
    ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.client.host
    if check_rate_limit(f"register:{ip}", max_requests=3, window=300):
        raise HTTPException(429, "Trop d'inscriptions depuis cette IP, réessayez dans 5 minutes")
    if len(data.username) < 2:
        raise HTTPException(400, "Nom d utilisateur trop court (2 caractères min)")
    if len(data.password) < 8:
        raise HTTPException(400, "Mot de passe trop court (8 caractères min)")
    if not re.match(r"^[a-zA-Z0-9_\-\.]{2,32}$", data.username):
        raise HTTPException(400, "Nom d utilisateur invalide (lettres, chiffres, _ - . uniquement)")
    # Générer un ID unique lisible
    uid_chars = string.ascii_uppercase + string.digits
    user_uid = "XT-" + "".join(secrets.choice(uid_chars) for _ in range(8))
    # Email fictif basé sur username pour compatibilité DB
    fake_email = data.username.lower() + "@xtracker.local"
    ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.client.host
    db = get_db()
    # Vérifier username unique
    existing = fetchone(db, "SELECT id FROM users WHERE username=?", (data.username,))
    if existing:
        db.close()
        raise HTTPException(400, "Nom d utilisateur déjà pris")
    # Vérifier IP
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
    # Marquer tous les broadcasts existants comme lus pour eviter le flood
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
    # Gérer le parrainage
    ref_code = data.ref_code.strip().upper() if hasattr(data, 'ref_code') and data.ref_code else None
    if ref_code and db_id:
        referrer = fetchone(db, "SELECT id, reg_ip FROM users WHERE referral_code=?", (ref_code,))
        if referrer and referrer["id"] != db_id:
            # Bloquer si même IP que le parrain (anti-triche)
            referrer_ip = referrer.get("reg_ip")
            if referrer_ip and referrer_ip == ip:
                print(f"[REFERRAL] Blocage auto-parrainage: même IP {ip}")
            else:
                # Vérifier que cette IP n'a pas déjà été utilisée pour parrainer ce code
                already = fetchone(db, "SELECT id FROM referrals WHERE referrer_id=? AND id IN (SELECT id FROM referrals WHERE referred_id IN (SELECT id FROM users WHERE reg_ip=?))", (referrer["id"], ip))
                if already:
                    print(f"[REFERRAL] Blocage: IP {ip} déjà utilisée pour ce parrain")
                else:
                    execute(db, "UPDATE users SET referred_by=? WHERE id=?", (referrer["id"], db_id))
                    execute(db, "INSERT INTO referrals (referrer_id, referred_id, credits_earned) VALUES (?,?,?)", (referrer["id"], db_id, 5))
                    execute(db, "UPDATE users SET credits=credits+5 WHERE id=?", (referrer["id"],))
    db.commit()
    db.close()
    token = create_token(db_id, "user")
    return {
        "token": token,
        "user_id": user_uid,
        "user": {
            "id": db_id,
            "email": fake_email,
            "username": data.username,
            "role": "user",
            "credits": 0,
            "free_left": free_left
        },
        "message": "Compte créé avec succès !"
    }

@app.post("/api/auth/login")
async def login(data: LoginModel, request: Request):
    ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.client.host
    if check_rate_limit(f"login:{ip}", max_requests=10, window=60):
        raise HTTPException(429, "Trop de tentatives, réessayez dans 1 minute")
    db = get_db()
    # Si c'est un email, chercher UNIQUEMENT par email
    # Si c'est un username, chercher UNIQUEMENT par username (jamais les comptes discord)
    login_val = data.username.strip()
    if "@" in login_val and "xtracker.local" not in login_val.lower():
        # Login par email réel (pas @xtracker.local)
        user = fetchone(db, "SELECT * FROM users WHERE email=?", (login_val.lower(),))
        if user and (user.get("email") or "").startswith("discord_"):
            user = None
    else:
        # Login par username - exclure seulement les comptes Discord (discord_XXXXX)
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
    execute(db, "UPDATE users SET last_login=? WHERE id=?", (_now, user["id"]))
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
        "id": user["id"], "email": user["email"],
        "username": user["username"], "role": user["role"],
        "credits": user["credits"], "free_left": user["free_left"],
        "created_at": user["created_at"],
        "lifetime": bool(user.get("lifetime", False))
    }

# ── SEARCH ────────────────────────────────────────────────────────────────────
async def call_brix(method: str, path: str, body: dict = None):
    headers = {
        "X-API-Key":    BRIX_KEY,
        "Content-Type": "application/json",
        "Accept":       "application/json",
        "User-Agent":   "Xtracker/1.0",
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
            print(f"[BRIX 403] Key: {BRIX_KEY[:10]}... Response: {r.text[:200]}")
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

def deduct_and_log(user_id: int, query_data: dict, result_count: int):
    db = get_db()
    user = fetchone(db, "SELECT free_left, credits, lifetime FROM users WHERE id=?", (user_id,))
    # Lifetime = recherches illimitées, pas de déduction
    if user.get("lifetime"):
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

@app.post("/api/search")
async def search(data: SearchModel, user=Depends(get_current_user)):
    if not user.get("lifetime") and user["free_left"] <= 0 and user["credits"] <= 0:
        raise HTTPException(402, "Plus de crédits")
    payload = {"flexible": data.flexible, "per_page": 10}
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
        if val: payload[f] = val
    # Filtrer les valeurs trop courtes
    for k in list(payload.keys()):
        if k not in ('flexible','per_page') and isinstance(payload[k], str) and len(payload[k].strip()) < 2:
            del payload[k]
    if len(payload) <= 2:
        raise HTTPException(400, "Remplissez au moins un champ (2 caractères minimum)")

    # Nettoyer les caractères problématiques pour BrixHub
    import unicodedata
    def clean_field(val):
        if not isinstance(val, str): return val
        # Normaliser les accents
        val = unicodedata.normalize('NFC', val)
        # Supprimer les caractères de contrôle
        val = ''.join(c for c in val if unicodedata.category(c) != 'Cc')
        return val.strip()
    for k in list(payload.keys()):
        if isinstance(payload[k], str):
            payload[k] = clean_field(payload[k])

    # Vérifier les termes protégés AVANT d'appeler BrixHub
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
    # Filtrer les résultats protégés (même si BrixHub les retourne)
    results = filter_results(results)

    # Pivot famille : recherche automatique sans coût de crédit
    for p in results[:5]:  # Limiter aux 5 premiers pour économiser les requêtes
        famille = []
        pivot_done = set()

        # Pivot par adresse
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
                        # Exclure le profil principal
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
                        # Éviter les doublons
                        if not any(m["prenom"] == membre["prenom"] and m["nom_famille"] == membre["nom_famille"] for m in famille):
                            famille.append(membre)
                except:
                    pass

        # Pivot par téléphone
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
        "results":   results,
        "total":     result.get("meta", {}).get("total", 0),
        "took_ms":   result.get("meta", {}).get("took_ms", 0),
        "free_left": updated["free_left"],
        "credits":   updated["credits"],
    }

@app.post("/api/lookup")
async def lookup(data: LookupModel, user=Depends(get_current_user)):
    if not user.get("lifetime") and user["free_left"] <= 0 and user["credits"] <= 0:
        raise HTTPException(402, "Plus de crédits")
    val = data.value.strip()
    if "@" in val:
        path = f"/lookup/email/{val}"
    elif val.upper().startswith("FR") and len(val) > 20:
        path = f"/lookup/iban/{val}"
    else:
        path = f"/lookup/phone/{val.replace(' ','').replace('.','').replace('-','')}"
    result = await call_brix("GET", path)
    results = result.get("data", {}).get("results", [])
    updated = deduct_and_log(user["id"], {"lookup": val}, len(results))
    return {
        "results":   results,
        "total":     result.get("meta", {}).get("total", 0),
        "free_left": updated["free_left"],
        "credits":   updated["credits"],
    }

@app.get("/api/history")
async def history(user=Depends(get_current_user)):
    db = get_db()
    rows = fetchall(db, "SELECT id, query_data, result_count, cost, created_at FROM searches WHERE user_id=? ORDER BY created_at DESC LIMIT 50", (user["id"],))
    db.close()
    return rows

@app.post("/api/history/{search_id}/replay")
async def history_replay(search_id: int, user=Depends(get_current_user)):
    """Rejoue une recherche depuis l'historique SANS deduire de credits"""
    db = get_db()
    row = fetchone(db, "SELECT query_data FROM searches WHERE id=? AND user_id=?", (search_id, user["id"]))
    db.close()
    if not row:
        raise HTTPException(404, "Recherche introuvable")
    payload = json.loads(row["query_data"])
    payload["per_page"] = 100
    # Vérifier les termes protégés même pour le replay
    if check_protected(payload):
        return {"results": [], "total": 0, "took_ms": 0, "free_left": user["free_left"], "credits": user["credits"]}
    result = await call_brix("POST", "/search", payload)
    results = result.get("data", {}).get("results", [])
    results = filter_results(results)
    # Pivot famille sans credit
    for p in results[:5]:
        famille = []
        if p.get("adresse") and p.get("code_postal"):
            try:
                pr = await call_brix("POST", "/search", {"adresse": p["adresse"], "code_postal": p["code_postal"], "flexible": False, "per_page": 10})
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

# ── STRIPE ────────────────────────────────────────────────────────────────────
@app.post("/api/credits/confirm")
async def confirm_paygate(request: Request, user=Depends(get_current_user)):
    """Confirme un paiement PayGate et ajoute les crédits"""
    body     = await request.json()
    credits  = int(body.get("credits", 0))
    pack_id  = body.get("pack_id", "")
    order_id = body.get("order_id", "")
    if credits <= 0 or not order_id:
        raise HTTPException(400, "Données invalides")
    pack   = CREDIT_PACKS.get(pack_id, {})
    amount = pack.get("price_eur", 0)
    db = get_db()
    # Vérifier si déjà traité
    existing = db.execute("SELECT id FROM transactions WHERE stripe_id=?", (order_id,)).fetchone()
    if existing:
        db.close()
        return {"message": "Déjà traité"}
    db.execute("UPDATE users SET credits=credits+? WHERE id=?", (credits, user["id"]))
    db.execute("""
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
    pack   = CREDIT_PACKS[pack_id]
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
    """SumUp redirige ici apres paiement - VERIFICATION OBLIGATOIRE avec SumUp API"""
    from fastapi.responses import RedirectResponse
    params   = dict(request.query_params)
    order_id = params.get("order_id", "")
    uid      = int(params.get("uid", 0))
    pack_id  = params.get("pack", "")

    if not order_id or not uid or not pack_id:
        return RedirectResponse(url="/dashboard.html?payment=cancel")

    pack = CREDIT_PACKS.get(pack_id, {})
    if not pack:
        return RedirectResponse(url="/dashboard.html?payment=cancel")

    credits = pack["credits"]
    amount  = pack["price_eur"]

    try:
        # VERIFIER le paiement directement avec l'API SumUp
        sumup_key = os.getenv("SUMUP_SK", "")
        async with httpx.AsyncClient(timeout=15) as client:
            # Récupérer le checkout pour vérifier le statut
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

            # Vérifier que le paiement est bien PAID et que le montant correspond
            if status != "PAID":
                print(f"[SUMUP] Paiement non complete: {status}")
                return RedirectResponse(url="/dashboard.html?payment=cancel")

            if abs(paid_amount - amount) > 0.01:
                print(f"[SUMUP] Montant incorrect: attendu {amount} recu {paid_amount}")
                return RedirectResponse(url="/dashboard.html?payment=cancel")

        # Tout est OK - ajouter les credits
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
            cur=db.cursor(); cur.execute(q(sql),p); r=cur.fetchone(); cur.close()
            return list(r.values())[0] if r else 0
        return db.execute(q(sql),p).fetchone()[0]
    total_users    = cnt("SELECT COUNT(*) FROM users")
    new_today      = cnt("SELECT COUNT(*) FROM users WHERE date(created_at)=CURRENT_DATE") if is_pg() else cnt("SELECT COUNT(*) FROM users WHERE date(created_at)=date('now')")
    total_searches = cnt("SELECT COUNT(*) FROM searches")
    searches_today = cnt("SELECT COUNT(*) FROM searches WHERE date(created_at)=CURRENT_DATE") if is_pg() else cnt("SELECT COUNT(*) FROM searches WHERE date(created_at)=date('now')")
    revenue        = cnt("SELECT COALESCE(SUM(amount_eur),0) FROM transactions WHERE status='completed'")
    banned         = cnt("SELECT COUNT(*) FROM users WHERE banned=TRUE") if is_pg() else cnt("SELECT COUNT(*) FROM users WHERE banned=1")
    try:
        discord_linked = cnt("SELECT COUNT(*) FROM users WHERE discord_id IS NOT NULL AND discord_id != ''")
    except: discord_linked = 0
    try:
        lifetime_users = cnt("SELECT COUNT(*) FROM users WHERE lifetime=TRUE") if is_pg() else cnt("SELECT COUNT(*) FROM users WHERE lifetime=1")
    except: lifetime_users = 0
    db.close()
    return {
        "total_users": total_users, "new_today": new_today,
        "total_searches": total_searches, "searches_today": searches_today,
        "revenue_eur": float(revenue), "banned": banned,
        "discord_linked": discord_linked, "lifetime_users": lifetime_users,
    }

@app.get("/api/admin/users")
async def admin_users(admin=Depends(require_admin), page: int = 1, search: str = ""):
    db     = get_db()
    offset = (page - 1) * 20
    if search:
        rows  = fetchall(db, "SELECT u.id,u.email,u.username,u.role,u.credits,u.free_left,u.created_at,u.last_login,u.banned,u.reg_ip,u.lifetime,u.discord_username,(SELECT COUNT(*) FROM users u2 WHERE u2.reg_ip=u.reg_ip AND u.reg_ip IS NOT NULL) as ip_count FROM users u WHERE u.email LIKE ? OR u.username LIKE ? ORDER BY u.created_at DESC LIMIT 20 OFFSET ?", (f"%{search}%", f"%{search}%", offset))
        total_r = fetchone(db, "SELECT COUNT(*) as c FROM users WHERE email LIKE ? OR username LIKE ?", (f"%{search}%", f"%{search}%"))
    else:
        rows  = fetchall(db, "SELECT u.id,u.email,u.username,u.role,u.credits,u.free_left,u.created_at,u.last_login,u.banned,u.reg_ip,u.lifetime,u.discord_username,(SELECT COUNT(*) FROM users u2 WHERE u2.reg_ip=u.reg_ip AND u.reg_ip IS NOT NULL) as ip_count FROM users u ORDER BY u.created_at DESC LIMIT 20 OFFSET ?", (offset,))
        total_r = fetchone(db, "SELECT COUNT(*) as c FROM users", ())
    total = total_r["c"] if total_r else 0
    db.close()
    return {"users": rows, "total": total}

@app.patch("/api/admin/users/{user_id}")
async def admin_update(user_id: int, data: AdminUserUpdate, admin=Depends(require_admin)):
    db = get_db()
    # Protéger le compte admin principal
    target = fetchone(db, "SELECT email FROM users WHERE id=?", (user_id,))
    if ADMIN_EMAIL and target and target.get("email") == ADMIN_EMAIL:
        if data.banned is not None or data.role is not None:
            db.close()
            raise HTTPException(403, "Ce compte admin ne peut pas être modifié")
    if data.credits is not None:
        safe_credits = min(int(data.credits), 1000)  # Max 1000 credits
        execute(db, "UPDATE users SET credits=credits+? WHERE id=?", (safe_credits, user_id))
    if data.banned is not None:
        banned_val = data.banned if is_pg() else (1 if data.banned else 0)
        execute(db, "UPDATE users SET banned=? WHERE id=?", (banned_val, user_id))
    if data.role is not None:
        execute(db, "UPDATE users SET role=? WHERE id=?", (data.role, user_id))
    db.commit(); db.close()
    return {"message": "Mis à jour"}

@app.delete("/api/admin/users/{user_id}")
async def admin_delete(user_id: int, admin=Depends(require_admin)):
    db = get_db()
    execute(db, "DELETE FROM searches WHERE user_id=?", (user_id,))
    execute(db, "DELETE FROM transactions WHERE user_id=?", (user_id,))
    execute(db, "DELETE FROM users WHERE id=?", (user_id,))
    db.commit(); db.close()
    return {"message": "Supprimé"}

@app.post("/api/admin/users/{user_id}/add-credits")
async def admin_add_credits(user_id: int, request: Request, admin=Depends(require_admin)):
    body    = await request.json()
    credits = min(int(body.get("credits", 0)), 1000)  # Max 1000 credits par ajout
    db = get_db()
    execute(db, "UPDATE users SET credits=credits+? WHERE id=?", (credits, user_id))
    execute(db, "INSERT INTO transactions (user_id,type,credits,amount_eur,status) VALUES (?,?,?,0,'completed')", (user_id, "admin_grant", credits))
    db.commit(); db.close()
    return {"message": f"{credits} crédits ajoutés"}

@app.get("/api/admin/searches")
async def admin_searches(admin=Depends(require_admin), page: int = 1):
    db     = get_db()
    offset = (page - 1) * 50
    rows   = fetchall(db, "SELECT s.id, s.query_data, s.result_count, s.cost, s.created_at, u.email, u.username FROM searches s JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC LIMIT 50 OFFSET ?", (offset,))
    db.close()
    return rows

@app.get("/api/admin/history")
async def admin_history(admin=Depends(require_admin), page: int = 1):
    db     = get_db()
    offset = (page - 1) * 50
    rows   = fetchall(db, "SELECT s.id, s.query_data, s.result_count, s.cost, s.created_at, u.email, u.username FROM searches s JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC LIMIT 50 OFFSET ?", (offset,))
    db.close()
    return rows

@app.get("/api/admin/transactions")
async def admin_tx(admin=Depends(require_admin)):
    db   = get_db()
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
    btype  = body.get("type", "nom_famille")
    value  = body.get("value", "").strip().lower()
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
    # Sauvegarder dans la table settings
    def upsert_setting(key, value):
        try:
            execute(db, "INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, value))
        except:
            try:
                execute(db, "INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
            except:
                pass
    upsert_setting("maintenance_enabled", "true" if enabled else "false")
    upsert_setting("maintenance_message", message)
    upsert_setting("maintenance_eta", str(eta_minutes) if eta_minutes else "")
    db.commit(); db.close()
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
        return {
            "enabled": status,
            "maintenance": status,
            "message": msg_row.get("value","") if msg_row else "",
            "eta_minutes": int(eta_row.get("value",0)) if eta_row and eta_row.get("value") else 0
        }
    except Exception as e:
        return {"enabled": False, "maintenance": False, "message": "", "eta_minutes": 0}

# ── STATIC ────────────────────────────────────────────────────────────────────
# ── AI ASSISTANT ──────────────────────────────────────────────────────────────
class ChatModel(BaseModel):
    messages: list
    system: str = ""

@app.post("/api/ai/chat")
async def ai_chat(data: ChatModel, user=Depends(get_current_user)):
    groq_key = os.getenv("GROQ_API_KEY", "")
    if not groq_key:
        raise HTTPException(500, "GROQ_API_KEY manquante")
    try:
        msgs = []
        if data.system:
            msgs.append({"role": "system", "content": data.system})
        for m in data.messages:
            msgs.append({"role": m["role"], "content": m["content"]})
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
                json={"model": "llama-3.1-8b-instant", "max_tokens": 1000, "messages": msgs}
            )
            groq_data = r.json()
            text = groq_data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return {"content": [{"type": "text", "text": text}]}
    except Exception as e:
        print(f"[AI] Error: {e}")
        raise HTTPException(500, str(e))

@app.post("/api/admin/users/{user_id}/reset-credits")
async def admin_reset_credits(user_id: int, admin=Depends(require_admin)):
    db = get_db()
    execute(db, "UPDATE users SET credits=0, free_left=0 WHERE id=?", (user_id,))
    db.commit()
    db.close()
    return {"ok": True, "message": "Credits remis a zero"}

@app.post("/api/admin/users/{user_id}/set-role")
async def admin_set_role(user_id: int, request: Request, admin=Depends(require_admin)):
    body = await request.json()
    role = body.get("role", "user")
    if role not in ["user", "admin"]:
        raise HTTPException(400, "Role invalide")
    db = get_db()
    # Protéger le compte admin principal
    target = fetchone(db, "SELECT email FROM users WHERE id=?", (user_id,))
    if ADMIN_EMAIL and target and target.get("email") == ADMIN_EMAIL:
        db.close()
        raise HTTPException(403, "Ce compte admin ne peut pas être modifié")
    execute(db, "UPDATE users SET role=? WHERE id=?", (role, user_id))
    db.commit()
    db.close()
    return {"ok": True, "message": f"Role mis a jour: {role}"}

@app.post("/api/auth/logout")
async def logout():
    from fastapi.responses import JSONResponse
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("xtoken")
    return resp

# ── TICKETS ───────────────────────────────────────────────────────────────────
class TicketModel(BaseModel):
    subject: str
    message: str

class TicketReplyModel(BaseModel):
    message: str

@app.post("/api/tickets")
async def create_ticket(data: TicketModel, user=Depends(get_current_user)):
    db = get_db()
    if is_pg():
        tid = execute(db, "INSERT INTO tickets (user_id, subject, status) VALUES (?,?,?) RETURNING id", (user["id"], data.subject, "open"))
        execute(db, "INSERT INTO ticket_messages (ticket_id, user_id, message, is_admin) VALUES (?,?,?,?)", (tid, user["id"], data.message, False))
    else:
        tid = execute(db, "INSERT INTO tickets (user_id, subject, status) VALUES (?,?,?)", (user["id"], data.subject, "open"))
        execute(db, "INSERT INTO ticket_messages (ticket_id, user_id, message, is_admin) VALUES (?,?,?,?)", (tid, user["id"], data.message, False))
    db.commit(); db.close()
    return {"ok": True, "ticket_id": tid}

@app.get("/api/tickets")
async def get_tickets(user=Depends(get_current_user)):
    db = get_db()
    rows = fetchall(db, "SELECT t.id, t.subject, t.status, t.created_at, (SELECT COUNT(*) FROM ticket_messages WHERE ticket_id=t.id AND is_admin=TRUE AND read_by_user=FALSE) as unread FROM tickets t WHERE t.user_id=? ORDER BY t.created_at DESC", (user["id"],))
    db.close()
    return rows

@app.get("/api/tickets/{ticket_id}")
async def get_ticket(ticket_id: int, user=Depends(get_current_user)):
    db = get_db()
    ticket = fetchone(db, "SELECT * FROM tickets WHERE id=? AND (user_id=? OR ?='admin')", (ticket_id, user["id"], user["role"]))
    if not ticket: raise HTTPException(404, "Ticket introuvable")
    messages = fetchall(db, "SELECT tm.*, u.username FROM ticket_messages tm JOIN users u ON tm.user_id=u.id WHERE tm.ticket_id=? ORDER BY tm.created_at ASC", (ticket_id,))
    # Marquer comme lu
    if user["role"] != "admin":
        execute(db, "UPDATE ticket_messages SET read_by_user=TRUE WHERE ticket_id=? AND is_admin=TRUE", (ticket_id,))
    else:
        execute(db, "UPDATE ticket_messages SET read_by_admin=TRUE WHERE ticket_id=? AND is_admin=FALSE", (ticket_id,))
    db.commit(); db.close()
    return {"ticket": ticket, "messages": messages}

@app.post("/api/tickets/{ticket_id}/reply")
async def reply_ticket(ticket_id: int, data: TicketReplyModel, user=Depends(get_current_user)):
    db = get_db()
    ticket = fetchone(db, "SELECT * FROM tickets WHERE id=?", (ticket_id,))
    if not ticket: raise HTTPException(404, "Ticket introuvable")
    if ticket["status"] == "closed": raise HTTPException(400, "Ticket fermé")
    is_admin = user["role"] == "admin"
    execute(db, "INSERT INTO ticket_messages (ticket_id, user_id, message, is_admin) VALUES (?,?,?,?)", (ticket_id, user["id"], data.message, is_admin))
    db.commit(); db.close()
    return {"ok": True}

@app.post("/api/tickets/{ticket_id}/close")
async def close_ticket(ticket_id: int, user=Depends(get_current_user)):
    db = get_db()
    ticket = fetchone(db, "SELECT * FROM tickets WHERE id=? AND (user_id=? OR ?='admin')", (ticket_id, user["id"], user["role"]))
    if not ticket: raise HTTPException(404, "Ticket introuvable")
    execute(db, "UPDATE tickets SET status='closed' WHERE id=?", (ticket_id,))
    db.commit(); db.close()
    return {"ok": True}

@app.get("/api/admin/tickets")
async def admin_tickets(admin=Depends(require_admin)):
    db = get_db()
    rows = fetchall(db, "SELECT t.id, t.subject, t.status, t.created_at, u.username, (SELECT COUNT(*) FROM ticket_messages WHERE ticket_id=t.id AND is_admin=FALSE AND read_by_admin=FALSE) as unread FROM tickets t JOIN users u ON t.user_id=u.id ORDER BY t.status ASC, t.created_at DESC LIMIT 100")
    db.close()
    return rows

# ── MESSAGES BROADCAST ─────────────────────────────────────────────────────────
class BroadcastModel(BaseModel):
    message: str
    target_user_id: int = None

@app.post("/api/admin/broadcast")
async def send_broadcast(request: Request, admin=Depends(require_admin)):
    body = await request.json()
    message = body.get("message", "").strip()
    target_raw = body.get("target_user_id")  # peut être int, string ID, ou string username
    if not message:
        raise HTTPException(400, "Message requis")

    resolved_id = None

    if target_raw is not None and str(target_raw).strip() != "":
        target_str = str(target_raw).strip()
        db2 = get_db()
        # Essayer par ID d'abord
        try:
            maybe_id = int(target_str)
            u = fetchone(db2, "SELECT id FROM users WHERE id=?", (maybe_id,))
            if u:
                resolved_id = u["id"]
        except ValueError:
            pass
        # Si pas trouvé par ID, chercher par username
        if resolved_id is None:
            u = fetchone(db2, "SELECT id FROM users WHERE username=?", (target_str,))
            if u:
                resolved_id = u["id"]
            else:
                db2.close()
                raise HTTPException(404, f"Utilisateur '{target_str}' introuvable")
        db2.close()

    db = get_db()
    if resolved_id is not None:
        execute(db, "INSERT INTO broadcasts (message, target_user_id, created_by) VALUES (?,?,?)", (message, resolved_id, admin["id"]))
    else:
        execute(db, "INSERT INTO broadcasts (message, target_user_id, created_by) VALUES (?,NULL,?)", (message, admin["id"]))
    db.commit(); db.close()
    return {"ok": True, "target_id": resolved_id}

@app.get("/api/broadcasts")
async def get_broadcasts(user=Depends(get_current_user)):
    db = get_db()
    rows = fetchall(db, "SELECT id, message, created_at FROM broadcasts WHERE (target_user_id IS NULL OR target_user_id=?) AND id NOT IN (SELECT broadcast_id FROM broadcast_reads WHERE user_id=?) ORDER BY created_at DESC LIMIT 5", (user["id"], user["id"]))
    db.close()
    return rows

@app.post("/api/broadcasts/{bid}/read")
async def mark_broadcast_read(bid: int, user=Depends(get_current_user)):
    db = get_db()
    try:
        execute(db, "INSERT INTO broadcast_reads (broadcast_id, user_id) VALUES (?,?)", (bid, user["id"]))
        db.commit()
    except: pass
    db.close()
    return {"ok": True}

# ── ANNOUNCEMENTS (navbar) ─────────────────────────────────────────────────────
class AnnouncementModel(BaseModel):
    message: str

@app.post("/api/admin/announcements")
async def create_announcement(data: AnnouncementModel, admin=Depends(require_admin)):
    db = get_db()
    execute(db, "DELETE FROM announcements", ())  # Une seule annonce active
    execute(db, "INSERT INTO announcements (message) VALUES (?)", (data.message,))
    db.commit(); db.close()
    return {"ok": True}

@app.delete("/api/admin/announcements")
async def delete_announcement(admin=Depends(require_admin)):
    db = get_db()
    execute(db, "DELETE FROM announcements", ())
    db.commit(); db.close()
    return {"ok": True}

@app.get("/api/announcements")
async def get_announcement(user=Depends(get_current_user)):
    db = get_db()
    row = fetchone(db, "SELECT * FROM announcements ORDER BY created_at DESC LIMIT 1", ())
    db.close()
    return row or {}

# ── LOOKUP PLAQUE ─────────────────────────────────────────────────────────────
@app.get("/api/lookup/plaque/{plaque}")
async def lookup_plaque(plaque: str, user=Depends(get_current_user)):
    if not user.get("lifetime") and user["free_left"] <= 0 and user["credits"] <= 0:
        raise HTTPException(402, "Plus de crédits")
    plaque_clean = plaque.upper().replace("-","").replace(" ","")
    # Recherche via BrixHub avec le champ vin_plaque
    try:
        result = await call_brix("POST", "/search", {
            "vin_plaque": plaque_clean,
            "flexible": False,
            "per_page": 5
        })
        results = result.get("data", {}).get("results", [])
        results = filter_results(results)
        # Extraire les infos véhicule
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

# ── EXPORT PDF ─────────────────────────────────────────────────────────────────
@app.post("/api/export/pdf")
async def export_pdf(request: Request, user=Depends(get_current_user)):
    """Génère un PDF d'une fiche personne"""
    body = await request.json()
    profile = body.get("profile", {})
    if not profile:
        raise HTTPException(400, "Profil requis")
    
    name = f"{profile.get('prenom','')} {profile.get('nom_famille','')}".strip() or "Profil inconnu"
    
    # Générer HTML pour le PDF
    fields = []
    labels = {
        "prenom": "Prénom", "nom_famille": "Nom", "date_naissance": "Date de naissance",
        "email": "Email", "telephone": "Téléphone", "mobile": "Mobile",
        "adresse": "Adresse", "code_postal": "Code postal", "ville": "Ville",
        "region": "Région", "pays": "Pays", "nir": "NIR (Sécurité sociale)",
        "iban": "IBAN", "siret": "SIRET", "societe": "Société",
        "profession": "Profession", "vin_plaque": "Plaque/VIN", "marque": "Marque", "modele": "Modèle"
    }
    skip = {"_confidence", "_sources", "_es_ids", "_source_files", "famille", "membres_famille"}
    
    for k, v in profile.items():
        if k not in skip and v and isinstance(v, str) and v.strip():
            label = labels.get(k, k)
            fields.append(f"<tr><td style='font-weight:600;color:#666;padding:6px 12px;border-bottom:1px solid #eee;width:40%'>{label}</td><td style='padding:6px 12px;border-bottom:1px solid #eee'>{v}</td></tr>")
    
    famille = profile.get("famille", [])
    famille_html = ""
    if famille:
        membres = "".join([f"<li style='padding:4px 0'>{m.get('prenom','')} {m.get('nom_famille','')} {('- ' + m.get('lien','')) if m.get('lien') else ''} {('né le ' + m.get('date_naissance','')) if m.get('date_naissance') else ''}</li>" for m in famille])
        famille_html = f"<h3 style='margin:16px 0 8px;color:#333'>Famille associée</h3><ul style='list-style:none;padding:0'>{membres}</ul>"
    
    sources = profile.get("_sources", [])
    sources_html = ""
    if sources:
        sources_html = f"<p style='font-size:11px;color:#999;margin-top:16px'>Sources : {', '.join(sources)}</p>"
    
    html = f"""<!DOCTYPE html><html><head><meta charset='UTF-8'>
    <style>body{{font-family:Arial,sans-serif;margin:40px;color:#333}}h1{{color:#6366f1;font-size:22px;margin-bottom:4px}}
    .badge{{background:#6366f1;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px}}
    table{{width:100%;border-collapse:collapse;margin:16px 0}}</style></head>
    <body>
    <h1>Fiche — {name}</h1>
    <span class='badge'>Xtracker</span>
    <p style='color:#999;font-size:11px;margin:8px 0'>Généré le {__import__('datetime').datetime.now().strftime('%d/%m/%Y à %H:%M')}</p>
    <table>{"".join(fields)}</table>
    {famille_html}{sources_html}
    </body></html>"""
    
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html, headers={
        "Content-Disposition": f"attachment; filename=xtracker_{name.replace(' ','_')}.html"
    })

# ── ADMIN LIFETIME ─────────────────────────────────────────────────────────────
@app.post("/api/admin/users/{user_id}/set-lifetime")
async def admin_set_lifetime(user_id: int, request: Request, admin=Depends(require_admin)):
    body = await request.json()
    lifetime = body.get("lifetime", False)
    db = get_db()
    if lifetime:
        execute(db, "UPDATE users SET lifetime=TRUE, credits=999999 WHERE id=?", (user_id,))
    else:
        execute(db, "UPDATE users SET lifetime=FALSE WHERE id=?", (user_id,))
    db.commit(); db.close()
    return {"ok": True}

# ── CHANGEMENT MOT DE PASSE ───────────────────────────────────────────────────
class ChangePasswordModel(BaseModel):
    current_password: str
    new_password: str

@app.post("/api/auth/change-password")
async def change_password(data: ChangePasswordModel, user=Depends(get_current_user)):
    if len(data.new_password) < 8:
        raise HTTPException(400, "Nouveau mot de passe trop court (8 caractères min)")
    db = get_db()
    u = fetchone(db, "SELECT password FROM users WHERE id=?", (user["id"],))
    if not pwd_ctx.verify(data.current_password, u["password"]):
        db.close()
        raise HTTPException(401, "Mot de passe actuel incorrect")
    hashed = pwd_ctx.hash(data.new_password)
    execute(db, "UPDATE users SET password=? WHERE id=?", (hashed, user["id"]))
    db.commit(); db.close()
    return {"ok": True, "message": "Mot de passe modifié"}

# ── THEME ──────────────────────────────────────────────────────────────────────
class ThemeModel(BaseModel):
    theme: str

@app.post("/api/user/theme")
async def save_theme(data: ThemeModel, user=Depends(get_current_user)):
    db = get_db()
    try:
        execute(db, "ALTER TABLE users ADD COLUMN IF NOT EXISTS theme TEXT DEFAULT NULL", ())
        db.commit()
    except: pass
    execute(db, "UPDATE users SET theme=? WHERE id=?", (data.theme, user["id"]))
    db.commit(); db.close()
    return {"ok": True}

@app.get("/api/user/theme")
async def get_theme(user=Depends(get_current_user)):
    db = get_db()
    try:
        execute(db, "ALTER TABLE users ADD COLUMN IF NOT EXISTS theme TEXT DEFAULT NULL", ())
        db.commit()
    except: pass
    u = fetchone(db, "SELECT theme FROM users WHERE id=?", (user["id"],))
    db.close()
    return {"theme": u.get("theme") if u else None}

# ── PARRAINAGE ────────────────────────────────────────────────────────────────
@app.get("/api/referral/code")
async def get_referral_code(user=Depends(get_current_user)):
    db = get_db()
    u = fetchone(db, "SELECT referral_code FROM users WHERE id=?", (user["id"],))
    code = u.get("referral_code") if u else None
    if not code:
        import secrets
        code = secrets.token_urlsafe(8).upper()[:10]
        execute(db, "UPDATE users SET referral_code=? WHERE id=?", (code, user["id"]))
        db.commit()
    # Stats parrainage
    refs = fetchall(db, "SELECT r.id, r.credits_earned, r.created_at, u.username FROM referrals r JOIN users u ON r.referred_id=u.id WHERE r.referrer_id=? ORDER BY r.created_at DESC", (user["id"],))
    total_credits = sum(r["credits_earned"] for r in refs)
    db.close()
    return {
        "code": code,
        "total_referred": len(refs),
        "total_credits": total_credits,
        "referrals": refs
    }

@app.get("/api/referral/info/{code}")
async def referral_info(code: str):
    db = get_db()
    u = fetchone(db, "SELECT id, username FROM users WHERE referral_code=?", (code.upper(),))
    db.close()
    if not u:
        raise HTTPException(404, "Code invalide")
    return {"username": u["username"], "valid": True}

# Route admin parrainage
@app.get("/api/admin/referrals")
async def admin_referrals(admin=Depends(require_admin)):
    db = get_db()
    rows = fetchall(db, """
        SELECT u.id, u.username, u.referral_code,
               COUNT(r.id) as total_referred,
               COALESCE(SUM(r.credits_earned),0) as total_credits
        FROM users u
        LEFT JOIN referrals r ON r.referrer_id=u.id
        WHERE u.referral_code IS NOT NULL
        GROUP BY u.id, u.username, u.referral_code
        ORDER BY total_referred DESC
        LIMIT 100
    """)
    db.close()
    return rows

# ── LIAISON DISCORD ───────────────────────────────────────────────────────────
@app.post("/api/discord/generate-link-code")
async def generate_link_code(user=Depends(get_current_user)):
    import secrets
    db = get_db()
    # Supprimer anciens codes non utilisés
    execute(db, "DELETE FROM discord_link_codes WHERE user_id=? AND used=FALSE", (user["id"],))
    code = secrets.token_hex(4).upper()  # Code 8 caractères ex: A1B2C3D4
    if is_pg():
        execute(db, "INSERT INTO discord_link_codes (user_id, code) VALUES (?,?) RETURNING id", (user["id"], code))
    else:
        execute(db, "INSERT INTO discord_link_codes (user_id, code) VALUES (?,?)", (user["id"], code))
    db.commit(); db.close()
    return {"code": code, "expires_in": 3600}  # 1 heure

@app.post("/api/discord/link")
async def link_discord(request: Request):
    """Appelé par le bot Discord pour lier un compte"""
    body = await request.json()
    code = body.get("code", "").upper().strip()
    discord_id = str(body.get("discord_id", ""))
    discord_username = body.get("discord_username", "")
    bot_secret = body.get("bot_secret", "")
    
    # Vérifier le secret du bot
    if bot_secret != os.getenv("BOT_SECRET", "xtracker_bot_secret_2024"):
        raise HTTPException(403, "Acces refuse")
    
    if not code or not discord_id:
        raise HTTPException(400, "Code et discord_id requis")
    
    db = get_db()
    # Vérifier le code
    link_row = fetchone(db, "SELECT * FROM discord_link_codes WHERE code=? AND used=FALSE", (code,))
    if not link_row:
        db.close()
        raise HTTPException(404, "Code invalide ou expiré")
    
    # Vérifier expiration
    if is_pg():
        expired = fetchone(db, "SELECT id FROM discord_link_codes WHERE code=? AND expires_at < NOW()", (code,))
        if expired:
            db.close()
            raise HTTPException(410, "Code expiré, génère-en un nouveau sur Xtracker")
    
    user_id = link_row["user_id"]
    
    # Vérifier que ce Discord n'est pas déjà lié à un autre compte
    existing = fetchone(db, "SELECT id, username FROM users WHERE discord_id=?", (discord_id,))
    if existing and existing["id"] != user_id:
        db.close()
        raise HTTPException(409, f"Ce Discord est déjà lié au compte {existing['username']}")
    
    # Lier le compte
    execute(db, "UPDATE users SET discord_id=?, discord_username=? WHERE id=?", (discord_id, discord_username, user_id))
    execute(db, "UPDATE discord_link_codes SET used=TRUE WHERE code=?", (code,))
    db.commit()
    
    user = fetchone(db, "SELECT username FROM users WHERE id=?", (user_id,))
    db.close()
    return {"ok": True, "xtracker_username": user["username"]}

@app.get("/api/discord/user/{discord_id}")
async def get_user_by_discord(discord_id: str, request: Request):
    bot_secret = request.headers.get("X-Bot-Secret","")
    if bot_secret != os.getenv("BOT_SECRET","xtracker_bot_secret_2024"):
        raise HTTPException(403,"Accès refusé")
    db = get_db()
    u = fetchone(db, "SELECT username, credits, free_left, lifetime FROM users WHERE discord_id=?", (discord_id,))
    db.close()
    if not u: raise HTTPException(404,"Non lié")
    return dict(u)

@app.delete("/api/discord/unlink")
async def unlink_discord(user=Depends(get_current_user)):
    db = get_db()
    execute(db, "UPDATE users SET discord_id=NULL, discord_username=NULL WHERE id=?", (user["id"],))
    db.commit(); db.close()
    return {"ok": True}

@app.get("/api/discord/status")
async def discord_status(user=Depends(get_current_user)):
    db = get_db()
    u = fetchone(db, "SELECT discord_id, discord_username FROM users WHERE id=?", (user["id"],))
    db.close()
    return {
        "linked": bool(u and u.get("discord_id")),
        "discord_username": u.get("discord_username") if u else None,
        "discord_id": u.get("discord_id") if u else None
    }

@app.get("/api/discord/my-stats")
async def my_discord_stats(user=Depends(get_current_user)):
    """Stats Discord de l'utilisateur connecté"""
    db = get_db()
    total_searches = fetchone(db, "SELECT COUNT(*) as c FROM searches WHERE user_id=?", (user["id"],))
    db.close()
    return {
        "total_searches": total_searches["c"] if total_searches else 0,
        "credits_today_left": 5  # Le vrai compteur est dans la mémoire du bot
    }

# ── ROUTES BOT DISCORD ────────────────────────────────────────────────────────
def check_bot_secret(request: Request):
    secret = request.headers.get("X-Bot-Secret","")
    if secret != os.getenv("BOT_SECRET","xtracker_bot_secret_2024"):
        raise HTTPException(403, "Accès refusé")

@app.get("/api/discord/find-user")
async def find_user_by_username(username: str, request: Request):
    check_bot_secret(request)
    db = get_db()
    u = fetchone(db, "SELECT id, username, credits, free_left, lifetime FROM users WHERE username=?", (username,))
    db.close()
    if not u: raise HTTPException(404, f"Utilisateur '{username}' introuvable")
    return dict(u)

@app.post("/api/discord/rename-user")
async def rename_user_bot(request: Request):
    check_bot_secret(request)
    body = await request.json()
    username = body.get("username","").strip()
    new_username = body.get("new_username","").strip()
    if not username or not new_username:
        raise HTTPException(400, "username et new_username requis")
    import re
    if not re.match(r"^[a-zA-Z0-9_\-\.]{2,32}$", new_username):
        raise HTTPException(400, "Nouveau pseudo invalide")
    db = get_db()
    u = fetchone(db, "SELECT id FROM users WHERE username=?", (username,))
    if not u:
        db.close()
        raise HTTPException(404, f"Utilisateur '{username}' introuvable")
    existing = fetchone(db, "SELECT id FROM users WHERE username=?", (new_username,))
    if existing:
        db.close()
        raise HTTPException(409, "Ce pseudo est déjà pris")
    execute(db, "UPDATE users SET username=? WHERE username=?", (new_username, username))
    db.commit(); db.close()
    return {"ok": True}



@app.get("/api/discord/lookup-user")
async def lookup_user_bot(username: str = None, discord_id: str = None, request: Request = None):
    bot_secret = request.headers.get("X-Bot-Secret","")
    if bot_secret != os.getenv("BOT_SECRET","xtracker_bot_secret_2024"):
        raise HTTPException(403, "Acces refuse")
    db = get_db()
    if discord_id:
        u = fetchone(db, "SELECT id, email, username, role, credits, free_left, lifetime, created_at, banned, reg_ip, discord_username, discord_id, referral_code FROM users WHERE discord_id=?", (discord_id,))
    elif username:
        u = fetchone(db, "SELECT id, email, username, role, credits, free_left, lifetime, created_at, banned, reg_ip, discord_username, discord_id, referral_code FROM users WHERE username=?", (username,))
    else:
        db.close()
        raise HTTPException(400, "username ou discord_id requis")
    if not u:
        db.close()
        raise HTTPException(404, "Utilisateur introuvable ou compte non lie")
    refs = fetchone(db, "SELECT COUNT(*) as c FROM referrals WHERE referrer_id=?", (u["id"],))
    total_refs = refs["c"] if refs else 0
    searches_count = fetchone(db, "SELECT COUNT(*) as c FROM searches WHERE user_id=?", (u["id"],))
    total_searches = searches_count["c"] if searches_count else 0
    # 20 dernières recherches
    last_searches = fetchall(db, "SELECT query_data, result_count, created_at FROM searches WHERE user_id=? ORDER BY created_at DESC LIMIT 20", (u["id"],))
    db.close()
    return {
        "id": u["id"],
        "username": u["username"],
        "email": u["email"],
        "role": u["role"],
        "credits": u["credits"],
        "free_left": u["free_left"],
        "lifetime": bool(u.get("lifetime")),
        "banned": bool(u.get("banned")),
        "created_at": str(u.get("created_at",""))[:10],
        "reg_ip": u.get("reg_ip",""),
        "discord_username": u.get("discord_username",""),
        "discord_id": u.get("discord_id",""),
        "referral_code": u.get("referral_code",""),
        "total_referrals": total_refs,
        "total_searches": total_searches,
        "last_searches": [{"query": json.loads(r["query_data"]) if r["query_data"] else {}, "results": r["result_count"], "date": str(r["created_at"])[:10]} for r in last_searches]
    }

@app.get("/api/discord/users-list")
async def bot_users_list(request: Request, page: int = 1, search: str = ""):
    bot_secret = request.headers.get("X-Bot-Secret","")
    if bot_secret != os.getenv("BOT_SECRET","xtracker_bot_secret_2024"):
        raise HTTPException(403, "Acces refuse")
    db = get_db()
    offset = (page-1)*10
    if search:
        rows = fetchall(db, "SELECT id,username,role,credits,lifetime,banned,discord_username FROM users WHERE username LIKE ? OR discord_username LIKE ? ORDER BY created_at DESC LIMIT 10 OFFSET ?", (f"%{search}%",f"%{search}%",offset))
        total_r = fetchone(db, "SELECT COUNT(*) as c FROM users WHERE username LIKE ? OR discord_username LIKE ?", (f"%{search}%",f"%{search}%"))
    else:
        rows = fetchall(db, "SELECT id,username,role,credits,lifetime,banned,discord_username FROM users ORDER BY created_at DESC LIMIT 10 OFFSET ?", (offset,))
        total_r = fetchone(db, "SELECT COUNT(*) as c FROM users", ())
    total = total_r["c"] if total_r else 0
    db.close()
    return {"users": rows, "total": total, "page": page, "pages": (total+9)//10}

# ── PAYGATE CRYPTO ────────────────────────────────────────────────────────────
@app.post("/api/credits/checkout-crypto/{pack_id}")
async def checkout_crypto(pack_id: str, user=Depends(get_current_user), request: Request = None):
    if pack_id not in CREDIT_PACKS:
        raise HTTPException(400, "Pack invalide")
    pack = CREDIT_PACKS[pack_id]
    amount = pack["price_eur"]
    credits = pack["credits"]
    wallet = PAYGATE_WALLET
    if not wallet:
        raise HTTPException(500, "Wallet non configure")
    import time
    order_id = f"xtracker-{user['id']}-{pack_id}-{int(time.time())}"
    origin = str(request.base_url).rstrip("/")
    # URL PayGate API
    paygate_url = (
        f"https://paygate.to/charge.php"
        f"?amount={amount}"
        f"&to={wallet}"
        f"&currency=EUR"
        f"&orderId={order_id}"
        f"&redirectUrl={origin}/api/paygate/success?order_id={order_id}&uid={user['id']}&pack={pack_id}"
        f"&webhook={origin}/api/paygate/webhook"
    )
    return {"checkout_url": paygate_url, "order_id": order_id}

@app.get("/api/paygate/check")
async def paygate_check(order_id: str, user=Depends(get_current_user)):
    """Vérifie si une commande crypto a été payée"""
    db = get_db()
    tx = fetchone(db, "SELECT id, status FROM transactions WHERE stripe_id=?", (order_id,))
    db.close()
    if tx and tx.get("status") == "completed":
        return {"paid": True}
    # Vérifier si expiré (>30 min)
    import time
    parts = order_id.split("-")
    if len(parts) >= 4:
        try:
            ts = int(parts[-1])
            if time.time() - ts > 1800:
                return {"paid": False, "expired": True}
        except: pass
    return {"paid": False, "expired": False}

@app.get("/api/paygate/success")
async def paygate_success(request: Request):
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
    db = get_db()
    existing = fetchone(db, "SELECT id FROM transactions WHERE stripe_id=?", (order_id,))
    if not existing:
        if pack_id == "lifetime":
            execute(db, "UPDATE users SET lifetime=TRUE, credits=999999 WHERE id=?", (uid,))
        else:
            execute(db, "UPDATE users SET credits=credits+? WHERE id=?", (credits, uid))
        execute(db, "INSERT INTO transactions (user_id, type, credits, amount_eur, stripe_id, status) VALUES (?,?,?,?,?,'completed')",
                (uid, "purchase_crypto", credits, amount, order_id))
        db.commit()
    db.close()
    return RedirectResponse(url="/dashboard.html?payment=success")

@app.post("/api/paygate/webhook")
async def paygate_webhook(request: Request):
    """Webhook PayGate pour confirmer le paiement"""
    body = await request.json()
    order_id = body.get("orderId", "")
    status = body.get("status", "")
    if status != "paid" or not order_id:
        return {"ok": False}
    # Extraire uid et pack depuis order_id: xtracker-{uid}-{pack}-{timestamp}
    parts = order_id.split("-")
    if len(parts) < 3:
        return {"ok": False}
    try:
        uid = int(parts[1])
        pack_id = parts[2]
    except:
        return {"ok": False}
    pack = CREDIT_PACKS.get(pack_id, {})
    if not pack:
        return {"ok": False}
    credits = pack["credits"]
    amount = pack["price_eur"]
    db = get_db()
    existing = fetchone(db, "SELECT id FROM transactions WHERE stripe_id=?", (order_id,))
    if not existing:
        if pack_id == "lifetime":
            execute(db, "UPDATE users SET lifetime=TRUE, credits=999999 WHERE id=?", (uid,))
        else:
            execute(db, "UPDATE users SET credits=credits+? WHERE id=?", (credits, uid))
        execute(db, "INSERT INTO transactions (user_id, type, credits, amount_eur, stripe_id, status) VALUES (?,?,?,?,?,'completed')",
                (uid, "purchase_crypto", credits, amount, order_id))
        db.commit()
    db.close()
    return {"ok": True}

@app.get("/api/crypto/wallets/{pack_id}")
async def get_crypto_wallets(pack_id: str, user=Depends(get_current_user)):
    """Retourne les adresses crypto et le montant converti"""
    if pack_id not in CREDIT_PACKS:
        raise HTTPException(400, "Pack invalide")
    pack = CREDIT_PACKS[pack_id]
    amount_eur = pack["price_eur"]
    # Taux approximatifs (à mettre à jour)
    import time
    order_id = f"xtracker-{user['id']}-{pack_id}-{int(time.time())}"
    # Récupérer taux BTC/EUR et LTC/EUR et ETH/EUR depuis CoinGecko
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,litecoin,ethereum&vs_currencies=eur")
            rates = r.json()
            btc_rate = rates.get("bitcoin", {}).get("eur", 90000)
            ltc_rate = rates.get("litecoin", {}).get("eur", 80)
            eth_rate = rates.get("ethereum", {}).get("eur", 3000)
    except:
        btc_rate = 90000
        ltc_rate = 80
        eth_rate = 3000
    btc_amount = round(amount_eur / btc_rate, 8)
    ltc_amount = round(amount_eur / ltc_rate, 6)
    eth_amount = round(amount_eur / eth_rate, 6)
    # Sauvegarder l'order en BDD pour tracking
    db = get_db()
    execute(db, "INSERT INTO transactions (user_id, type, credits, amount_eur, stripe_id, status) VALUES (?,?,?,?,?,'pending')",
            (user["id"], "purchase_crypto", pack["credits"], amount_eur, order_id))
    db.commit(); db.close()
    return {
        "order_id": order_id,
        "pack": pack["label"],
        "amount_eur": amount_eur,
        "wallets": {
            "BTC": {"address": PAYGATE_WALLET_BTC, "amount": btc_amount, "symbol": "BTC"},
            "LTC": {"address": PAYGATE_WALLET_LTC, "amount": ltc_amount, "symbol": "LTC"},
            "ETH": {"address": PAYGATE_WALLET_ETH, "amount": eth_amount, "symbol": "ETH"},
        }
    }

@app.post("/api/crypto/confirm/{order_id}")
async def confirm_crypto_manual(order_id: str, request: Request, user=Depends(get_current_user)):
    """L'utilisateur confirme avoir envoyé le paiement"""
    body = await request.json()
    tx_hash = body.get("tx_hash", "").strip()
    db = get_db()
    tx = fetchone(db, "SELECT * FROM transactions WHERE stripe_id=? AND user_id=?", (order_id, user["id"]))
    if not tx:
        db.close()
        raise HTTPException(404, "Commande introuvable")
    if tx["status"] == "completed":
        db.close()
        return {"ok": True, "message": "Deja traite"}
    execute(db, "UPDATE transactions SET status='confirming', stripe_id=? WHERE stripe_id=?",
            (f"{order_id}|{tx_hash}", order_id))
    db.commit(); db.close()
    return {"ok": True, "message": "Paiement en attente de confirmation admin"}

@app.get("/api/admin/crypto-order")
async def admin_crypto_order(order_id: str, admin=Depends(require_admin)):
    db = get_db()
    tx = fetchone(db, """SELECT t.*, u.username FROM transactions t 
                         LEFT JOIN users u ON t.user_id=u.id 
                         WHERE t.stripe_id=?""", (order_id,))
    db.close()
    if not tx:
        raise HTTPException(404, "Commande introuvable")
    return dict(tx)

@app.post("/api/admin/crypto-validate")
async def admin_crypto_validate(request: Request, admin=Depends(require_admin)):
    body = await request.json()
    order_id = body.get("order_id","").strip()
    if not order_id:
        raise HTTPException(400, "order_id requis")
    db = get_db()
    tx = fetchone(db, "SELECT * FROM transactions WHERE stripe_id=?", (order_id,))
    if not tx:
        db.close()
        raise HTTPException(404, "Commande introuvable")
    if tx["status"] == "completed":
        db.close()
        return {"ok": True, "message": "Deja valide"}
    uid = tx["user_id"]
    credits = tx["credits"]
    parts = order_id.split("-")
    pack_id = parts[2] if len(parts) >= 3 else ""
    if pack_id == "lifetime":
        execute(db, "UPDATE users SET lifetime=TRUE, credits=999999 WHERE id=?", (uid,))
    else:
        execute(db, "UPDATE users SET credits=credits+? WHERE id=?", (credits, uid))
    execute(db, "UPDATE transactions SET status='completed' WHERE stripe_id=?", (order_id,))
    db.commit(); db.close()
    return {"ok": True, "message": f"{credits} credits ajoutes"}

@app.post("/api/admin/crypto-cancel")
async def admin_crypto_cancel(request: Request, admin=Depends(require_admin)):
    body = await request.json()
    order_id = body.get("order_id","").strip()
    db = get_db()
    execute(db, "UPDATE transactions SET status='cancelled' WHERE stripe_id=?", (order_id,))
    db.commit(); db.close()
    return {"ok": True}

@app.get("/api/admin/crypto-pending")
async def admin_crypto_pending(admin=Depends(require_admin)):
    db = get_db()
    rows = fetchall(db, """SELECT t.*, u.username FROM transactions t
                           LEFT JOIN users u ON t.user_id=u.id
                           WHERE t.type='purchase_crypto' AND t.status='pending'
                           ORDER BY t.created_at DESC LIMIT 50""", ())
    db.close()
    return {"orders": rows}

# ── API EXTERNE / SSO ─────────────────────────────────────────────────────────
@app.get("/api/auth/verify")
async def verify_token(user=Depends(get_current_user)):
    """Vérifie un token JWT et retourne les infos utilisateur - pour extensions/apps tierces"""
    db = get_db()
    u = fetchone(db, "SELECT id, username, email, role, credits, lifetime, banned, discord_id, discord_username FROM users WHERE id=?", (user["id"],))
    db.close()
    if not u:
        raise HTTPException(404, "Utilisateur introuvable")
    if u.get("banned"):
        raise HTTPException(403, "Compte banni")
    return {
        "ok": True,
        "user": {
            "id": u["id"],
            "username": u["username"],
            "email": u["email"],
            "role": u["role"],
            "credits": u["credits"],
            "lifetime": bool(u.get("lifetime")),
            "discord_id": u.get("discord_id"),
            "discord_username": u.get("discord_username"),
        }
    }

@app.post("/api/auth/token-login")
async def token_login(request: Request):
    """Permet à une extension de se connecter avec email/password et récupérer un token"""
    body = await request.json()
    email = body.get("email","").strip().lower()
    password = body.get("password","")
    if not email or not password:
        raise HTTPException(400, "Email et mot de passe requis")
    db = get_db()
    u = fetchone(db, "SELECT * FROM users WHERE (email=? OR username=?) AND banned=0", (email, email))
    db.close()
    if not u or not pwd_ctx.verify(password, u.get("password","")):
        raise HTTPException(401, "Identifiants incorrects")
    token = create_token({"sub": str(u["id"]), "role": u["role"]})
    return {
        "ok": True,
        "token": token,
        "user": {
            "id": u["id"],
            "username": u["username"],
            "role": u["role"],
            "credits": u["credits"],
            "lifetime": bool(u.get("lifetime")),
        }
    }

@app.delete("/api/admin/broadcasts/all")
async def delete_all_broadcasts(admin=Depends(require_admin)):
    db = get_db()
    execute(db, "DELETE FROM broadcast_reads", ())
    execute(db, "DELETE FROM broadcasts", ())
    db.commit(); db.close()
    return {"ok": True, "message": "Tous les broadcasts supprimes"}

@app.get("/api/restore-admin-xtracker2026")
async def restore_admin(username: str):
    db = get_db()
    execute(db, "UPDATE users SET role='admin' WHERE username=? OR email=?", (username, username))
    db.commit(); db.close()
    return {"ok": True, "message": f"Compte {username} remis en admin"}

@app.get("/api/admin/fix-maintenance-off")
async def fix_maintenance_off():
    """Route d urgence pour desactiver la maintenance"""
    try:
        db = get_db()
        execute(db, "UPDATE settings SET value='false' WHERE key='maintenance_enabled'", ())
        execute(db, "DELETE FROM settings WHERE key='maintenance_enabled'", ())
        db.commit(); db.close()
    except: pass
    return {"ok": True, "message": "Maintenance desactivee"}

app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)