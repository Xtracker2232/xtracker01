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
import os, json, httpx, sqlite3
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
ALGORITHM      = "HS256"
TOKEN_EXPIRE   = 60 * 24 * 7
BRIX_KEY       = os.getenv("BRIX_API_KEY", "")
BRIX_BASE      = "https://brixhub.net/api/v1"
SUMUP_SK = os.getenv("SUMUP_SK", "")
SUMUP_PK = os.getenv("SUMUP_PK", "")
SUMUP_MERCHANT = "Shop2ToutMHN3Z5RX"

DB_PATH        = "xtracker.db"
MAINTENANCE    = os.getenv("MAINTENANCE", "false").lower() == "true"
DATABASE_URL   = _DB_URL

pwd_ctx  = CryptContext(schemes=["bcrypt"])
security = HTTPBearer(auto_error=False)

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
    "starter":    {"credits": 20,   "price_eur": 5.00,  "label": "Starter"},
    "pro":        {"credits": 200,  "price_eur": 14.99, "label": "Pro"},
    "enterprise": {"credits": 1000, "price_eur": 49.99, "label": "Enterprise"},
}

app = FastAPI(title="Xtracker API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def maintenance_middleware(request, call_next):
    # Recharger la variable à chaque requête pour permettre l'activation à chaud
    try:
        with open(".maintenance", "r") as _f:
            maintenance = _f.read().strip() == "true"
    except:
        maintenance = os.getenv("MAINTENANCE", "false").lower() == "true"
    if maintenance:
        path = request.url.path
        # Laisser passer les routes API admin, maintenance.html, preview, et assets
        if path.startswith("/api/admin") or path.startswith("/api/auth") or path == "/maintenance.html" or path.startswith("/preview"):
            return await call_next(request)
        # Vérifier si l'utilisateur est admin via token JWT
        try:
            auth = request.headers.get("authorization","")
            if auth.startswith("Bearer "):
                token = auth.split(" ")[1]
                payload = jwt.decode(token, SECRET_KEY, [ALGORITHM])
                if payload.get("role") == "admin":
                    return await call_next(request)
        except:
            pass
        # Laisser passer les pages admin et dashboard pour les admins
        if path in ["/admin.html", "/dashboard.html", "/login.html"]:
            return await call_next(request)
        from fastapi.responses import HTMLResponse
        with open("maintenance.html", "r", encoding="utf-8") as f:
            html = f.read()
        return HTMLResponse(content=html, status_code=503)
    return await call_next(request)

# ── DATABASE ──────────────────────────────────────────────────────────────────
def get_db():
    if USE_PG and DATABASE_URL:
        try:
            conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
            return conn
        except Exception as e:
            print(f"[DB] Erreur PostgreSQL: {e}, fallback SQLite")
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db

def is_pg():
    return USE_PG and bool(DATABASE_URL)

def q(sql):
    """Adapte les placeholders ? -> %s pour PostgreSQL"""
    if is_pg():
        return sql.replace("?", "%s")
    return sql

def fetchone(cur_or_db, sql, params=()):
    if is_pg():
        cur = cur_or_db.cursor()
        cur.execute(q(sql), params)
        row = cur.fetchone()
        cur.close()
        return dict(row) if row else None
    return cur_or_db.execute(q(sql), params).fetchone()

def fetchall(cur_or_db, sql, params=()):
    if is_pg():
        cur = cur_or_db.cursor()
        cur.execute(q(sql), params)
        rows = cur.fetchall()
        cur.close()
        return [dict(r) for r in rows]
    return cur_or_db.execute(q(sql), params).fetchall()

def execute(db, sql, params=()):
    if is_pg():
        cur = db.cursor()
        cur.execute(q(sql), params)
        lastid = None
        try:
            lastid = cur.fetchone()
            if lastid: lastid = list(lastid.values())[0]
        except: pass
        cur.close()
        return lastid
    else:
        cur = db.execute(q(sql), params)
        return cur.lastrowid

def now_sql():
    return "NOW()" if is_pg() else "datetime('now')"

def date_sql():
    return "date(NOW())" if is_pg() else "date('now')"

def init_db():
    db = get_db()
    if is_pg():
        cur = db.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
            id         SERIAL PRIMARY KEY,
            email      TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            username   TEXT NOT NULL,
            role       TEXT DEFAULT 'user',
            credits    INTEGER DEFAULT 0,
            free_left  INTEGER DEFAULT 5,
            created_at TIMESTAMP DEFAULT NOW(),
            last_login TIMESTAMP,
            banned     BOOLEAN DEFAULT FALSE,
            stripe_id  TEXT,
            auth_type  TEXT DEFAULT 'local'
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS searches (
            id           SERIAL PRIMARY KEY,
            user_id      INTEGER REFERENCES users(id),
            query_data   TEXT,
            result_count INTEGER DEFAULT 0,
            cost         INTEGER DEFAULT 1,
            created_at   TIMESTAMP DEFAULT NOW()
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS transactions (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER REFERENCES users(id),
            type       TEXT,
            credits    INTEGER,
            amount_eur FLOAT,
            stripe_id  TEXT,
            status     TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT NOW()
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS blocklist (
            id         SERIAL PRIMARY KEY,
            type       TEXT NOT NULL,
            value      TEXT NOT NULL,
            reason     TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS ip_used (
            id         SERIAL PRIMARY KEY,
            ip         TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )""")
        cur.execute("SELECT id FROM users WHERE email='admin@xtracker.io'")
        if not cur.fetchone():
            cur.execute("""INSERT INTO users (email, password, username, role, credits, free_left)
                VALUES (%s,%s,'Admin','admin',99999,99999)""",
                ("admin@xtracker.io", pwd_ctx.hash("Admin1234!")))
        db.commit()
        cur.close()
        db.close()
        print("✓ Base de données PostgreSQL initialisée")
    else:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            username   TEXT NOT NULL,
            role       TEXT DEFAULT 'user',
            credits    INTEGER DEFAULT 0,
            free_left  INTEGER DEFAULT 5,
            created_at TEXT DEFAULT (datetime('now')),
            last_login TEXT,
            banned     INTEGER DEFAULT 0,
            stripe_id  TEXT
        );
        CREATE TABLE IF NOT EXISTS searches (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER,
            query_data   TEXT,
            result_count INTEGER DEFAULT 0,
            cost         INTEGER DEFAULT 1,
            created_at   TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            type       TEXT,
            credits    INTEGER,
            amount_eur REAL,
            stripe_id  TEXT,
            status     TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS blocklist (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            type       TEXT NOT NULL,
            value      TEXT NOT NULL,
            reason     TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS ip_used (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT UNIQUE NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        """)
        existing = db.execute("SELECT id FROM users WHERE email='admin@xtracker.io'").fetchone()
        if not existing:
            db.execute("""INSERT INTO users (email, password, username, role, credits, free_left)
                VALUES (?,?,'Admin','admin',99999,99999)""",
                ("admin@xtracker.io", pwd_ctx.hash("Admin1234!")))
        db.commit()
        db.close()
        print("✓ Base de données SQLite initialisée (fallback)")


init_db()
print("✓ Base de données SQLite initialisée (fallback)")

# ── AUTH ──────────────────────────────────────────────────────────────────────
def create_token(user_id: int, role: str) -> str:
    exp = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE)
    return jwt.encode({"sub": str(user_id), "role": role, "exp": exp}, SECRET_KEY, ALGORITHM)

def get_current_user(request: Request, creds: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):
    # Cookie httpOnly en priorité, sinon header Authorization
    token = request.cookies.get("xtoken")
    if not token and creds:
        token = creds.credentials
    if not token:
        raise HTTPException(401, "Non authentifié")
    try:
        payload = jwt.decode(token, SECRET_KEY, [ALGORITHM])
        uid = int(payload["sub"])
    except Exception:
        raise HTTPException(401, "Token invalide")
    db = get_db()
    user = fetchone(db, "SELECT * FROM users WHERE id=?", (uid,))
    db.close()
    if not user: raise HTTPException(401, "Introuvable")
    if user["banned"]: raise HTTPException(403, "Compte banni")
    return dict(user) if not isinstance(user, dict) else user

def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Accès refusé")
    return user

# ── MODELS ────────────────────────────────────────────────────────────────────
class RegisterModel(BaseModel):
    username: str
    password: str

class LoginModel(BaseModel):
    username: str
    password: str

class SearchModel(BaseModel):
    # Identité
    nom_famille: str = ""
    prenom: str = ""
    nom_naissance: str = ""
    nom_affichage: str = ""
    nom_utilisateur: str = ""
    genre: str = ""
    civilite: str = ""
    # Naissance
    date_naissance: str = ""
    annee_naissance: str = ""
    jour_naissance: int = None
    mois_naissance: int = None
    ville_naissance: str = ""
    lieu_naissance: str = ""
    # Contact
    email: str = ""
    telephone: str = ""
    mobile: str = ""
    adresse_ip: str = ""
    # Adresse
    adresse: str = ""
    complement_adresse: str = ""
    code_postal: str = ""
    ville: str = ""
    pays: str = ""
    region: str = ""
    departement: str = ""
    # Identifiants uniques
    nir: str = ""
    iban: str = ""
    bic: str = ""
    siret: str = ""
    siren: str = ""
    # Véhicule
    vin_plaque: str = ""
    immatriculation: str = ""
    marque: str = ""
    modele: str = ""
    # Professionnel
    societe: str = ""
    profession: str = ""
    fonction: str = ""
    # Options
    flexible: bool = True
    per_page: int = 10

class LookupModel(BaseModel):
    value: str

class AdminUserUpdate(BaseModel):
    credits: int = None
    banned: bool = None
    role: str = None

# ── AUTH ROUTES ───────────────────────────────────────────────────────────────
@app.post("/api/auth/register")
async def register(data: RegisterModel, request: Request):
    import re, secrets, string
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
        db_id = execute(db, "INSERT INTO users (email, password, username, free_left, auth_type) VALUES (?,?,?,?,?) RETURNING id", (fake_email, hashed, data.username, free_left, "local"))
    else:
        db_id = execute(db, "INSERT INTO users (email, password, username, free_left, auth_type) VALUES (?,?,?,?,?)", (fake_email, hashed, data.username, free_left, "local"))
    if not ip_used:
        try:
            execute(db, "INSERT INTO ip_used (ip) VALUES (?)", (ip,))
        except:
            pass
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
async def login(data: LoginModel):
    db = get_db()
    # Si c'est un email, chercher UNIQUEMENT par email
    # Si c'est un username, chercher UNIQUEMENT par username (jamais les comptes discord)
    login_val = data.username.strip()
    if "@" in login_val:
        user = fetchone(db, "SELECT * FROM users WHERE email=? AND auth_type='local'", (login_val.lower(),))
    else:
        user = fetchone(db, "SELECT * FROM users WHERE username=? AND auth_type='local'", (login_val,))
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
        "created_at": user["created_at"]
    }

# ── SEARCH ────────────────────────────────────────────────────────────────────
async def call_brix(method: str, path: str, body: dict = None):
    headers = {
        "X-API-Key":    BRIX_KEY,
        "Content-Type": "application/json",
        "Accept":       "application/json",
        "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    }
    async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
        if method == "POST":
            r = await client.post(f"{BRIX_BASE}{path}", json=body, headers=headers)
        else:
            r = await client.get(f"{BRIX_BASE}{path}", headers=headers)
    if r.status_code == 200:
        return r.json()
    raise HTTPException(r.status_code, f"Erreur API {r.status_code}")

def deduct_and_log(user_id: int, query_data: dict, result_count: int):
    db = get_db()
    user = fetchone(db, "SELECT free_left, credits FROM users WHERE id=?", (user_id,))
    if user["free_left"] > 0:
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
    if user["free_left"] <= 0 and user["credits"] <= 0:
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
        if val: payload[f] = val
    # Filtrer les valeurs trop courtes
    for k in list(payload.keys()):
        if k not in ('flexible','per_page') and isinstance(payload[k], str) and len(payload[k].strip()) < 2:
            del payload[k]
    if len(payload) <= 2:
        raise HTTPException(400, "Remplissez au moins un champ (2 caractères minimum)")

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
    if user["free_left"] <= 0 and user["credits"] <= 0:
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
    # Appeler BrixHub sans deduire de credits
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
            execute(db, "UPDATE users SET credits=credits+? WHERE id=?", (credits, uid))
            execute(db, "INSERT INTO transactions (user_id, type, credits, amount_eur, stripe_id, status) VALUES (?,?,?,?,?,'completed')",
                    (uid, "purchase", credits, amount, order_id))
            db.commit()
            print(f"[SUMUP] Credits ajoutes: uid={uid} credits={credits}")
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
    db.close()
    return {
        "total_users": total_users, "new_today": new_today,
        "total_searches": total_searches, "searches_today": searches_today,
        "revenue_eur": float(revenue), "banned": banned,
    }

@app.get("/api/admin/users")
async def admin_users(admin=Depends(require_admin), page: int = 1, search: str = ""):
    db     = get_db()
    offset = (page - 1) * 20
    if search:
        rows  = fetchall(db, "SELECT id,email,username,role,credits,free_left,created_at,last_login,banned FROM users WHERE email LIKE ? OR username LIKE ? ORDER BY created_at DESC LIMIT 20 OFFSET ?", (f"%{search}%", f"%{search}%", offset))
        total_r = fetchone(db, "SELECT COUNT(*) as c FROM users WHERE email LIKE ? OR username LIKE ?", (f"%{search}%", f"%{search}%"))
    else:
        rows  = fetchall(db, "SELECT id,email,username,role,credits,free_left,created_at,last_login,banned FROM users ORDER BY created_at DESC LIMIT 20 OFFSET ?", (offset,))
        total_r = fetchone(db, "SELECT COUNT(*) as c FROM users", ())
    total = total_r["c"] if total_r else 0
    db.close()
    return {"users": rows, "total": total}

@app.patch("/api/admin/users/{user_id}")
async def admin_update(user_id: int, data: AdminUserUpdate, admin=Depends(require_admin)):
    db = get_db()
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
    # Écrire dans un fichier flag
    with open(".maintenance", "w") as f:
        f.write("true" if enabled else "false")
    return {"maintenance": enabled, "message": "Maintenance " + ("activée" if enabled else "désactivée")}

@app.get("/api/admin/maintenance/status")
async def get_maintenance(admin=Depends(require_admin)):
    try:
        with open(".maintenance", "r") as f:
            status = f.read().strip() == "true"
    except:
        status = False
    return {"maintenance": status}

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
        print(f"[AI] Calling Groq, key={groq_key[:10]}..., msgs={len(msgs)}")
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
                json={"model": "llama-3.1-8b-instant", "max_tokens": 1000, "messages": msgs}
            )
            print(f"[AI] Groq status: {r.status_code}")
            groq_data = r.json()
            print(f"[AI] Groq response: {str(groq_data)[:200]}")
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

app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)