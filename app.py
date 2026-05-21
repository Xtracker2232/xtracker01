"""
Xtracker — Backend FastAPI + SQLite (test local)
pip install fastapi uvicorn python-jose passlib bcrypt stripe httpx python-multipart
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
import sqlite3, os, json, stripe, httpx

# ── CONFIG ────────────────────────────────────────────────────────────────────
SECRET_KEY     = "xtracker-secret-2026-changez-en-prod"
ALGORITHM      = "HS256"
TOKEN_EXPIRE   = 60 * 24 * 7
BRIX_KEY       = "brix_JUs29gtJ46uOB8SBtDU5y3dIbnYCFoEVS5iDSWuFmeC8LGBY"
BRIX_BASE      = "https://brixhub.net/api/v1"
STRIPE_SECRET  = os.getenv("STRIPE_SECRET", "sk_test_REMPLACER")
STRIPE_WEBHOOK = os.getenv("STRIPE_WEBHOOK", "whsec_REMPLACER")
DB_PATH        = "xtracker.db"

stripe.api_key = STRIPE_SECRET
pwd_ctx  = CryptContext(schemes=["bcrypt"])
security = HTTPBearer(auto_error=False)

CREDIT_PACKS = {
    "starter":    {"credits": 20,   "price_eur": 5.00,  "label": "Starter"},
    "pro":        {"credits": 200,  "price_eur": 14.99, "label": "Pro"},
    "enterprise": {"credits": 1000, "price_eur": 49.99, "label": "Enterprise"},
}

app = FastAPI(title="Xtracker API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── DATABASE ──────────────────────────────────────────────────────────────────
def get_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        email      TEXT UNIQUE NOT NULL,
        password   TEXT NOT NULL,
        username   TEXT NOT NULL,
        role       TEXT DEFAULT 'user',
        credits    INTEGER DEFAULT 0,
        free_left  INTEGER DEFAULT 10,
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
    """)
    existing = db.execute("SELECT id FROM users WHERE email='admin@xtracker.io'").fetchone()
    if not existing:
        db.execute("""
            INSERT INTO users (email, password, username, role, credits, free_left)
            VALUES (?, ?, 'Admin', 'admin', 99999, 99999)
        """, ("admin@xtracker.io", pwd_ctx.hash("Admin1234!")))
    db.commit()
    db.close()

init_db()
print("✓ Base de données SQLite initialisée")

# ── AUTH ──────────────────────────────────────────────────────────────────────
def create_token(user_id: int, role: str) -> str:
    exp = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE)
    return jwt.encode({"sub": str(user_id), "role": role, "exp": exp}, SECRET_KEY, ALGORITHM)

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(401, "Non authentifié")
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, [ALGORITHM])
        uid = int(payload["sub"])
    except JWTError:
        raise HTTPException(401, "Token invalide")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    db.close()
    if not user: raise HTTPException(401, "Introuvable")
    if user["banned"]: raise HTTPException(403, "Compte banni")
    return dict(user)

def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Accès refusé")
    return user

# ── MODELS ────────────────────────────────────────────────────────────────────
class RegisterModel(BaseModel):
    email: str
    password: str
    username: str

class LoginModel(BaseModel):
    email: str
    password: str

class SearchModel(BaseModel):
    nom_famille: str = ""
    prenom: str = ""
    email: str = ""
    telephone: str = ""
    adresse: str = ""
    ville: str = ""
    code_postal: str = ""
    pays: str = ""
    flexible: bool = True

class LookupModel(BaseModel):
    value: str

class AdminUserUpdate(BaseModel):
    credits: int = None
    banned: bool = None
    role: str = None

# ── AUTH ROUTES ───────────────────────────────────────────────────────────────
@app.post("/api/auth/register")
async def register(data: RegisterModel):
    if len(data.password) < 8:
        raise HTTPException(400, "Mot de passe trop court (8 caractères min)")
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email=?", (data.email.lower(),)).fetchone()
    if existing:
        db.close()
        raise HTTPException(400, "Email déjà utilisé")
    hashed = pwd_ctx.hash(data.password)
    cur = db.execute("""
        INSERT INTO users (email, password, username) VALUES (?,?,?)
    """, (data.email.lower(), hashed, data.username))
    db.commit()
    uid = cur.lastrowid
    db.close()
    token = create_token(uid, "user")
    return {"token": token, "message": "Compte créé — 10 recherches gratuites !"}

@app.post("/api/auth/login")
async def login(data: LoginModel):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (data.email.lower(),)).fetchone()
    if not user or not pwd_ctx.verify(data.password, user["password"]):
        db.close()
        raise HTTPException(401, "Email ou mot de passe incorrect")
    if user["banned"]:
        db.close()
        raise HTTPException(403, "Compte banni")
    db.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],))
    db.commit()
    db.close()
    token = create_token(user["id"], user["role"])
    return {
        "token": token,
        "user": {
            "id": user["id"], "email": user["email"],
            "username": user["username"], "role": user["role"],
            "credits": user["credits"], "free_left": user["free_left"]
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
    user = db.execute("SELECT free_left, credits FROM users WHERE id=?", (user_id,)).fetchone()
    if user["free_left"] > 0:
        db.execute("UPDATE users SET free_left=free_left-1 WHERE id=?", (user_id,))
        cost = 0
    elif user["credits"] > 0:
        db.execute("UPDATE users SET credits=credits-1 WHERE id=?", (user_id,))
        cost = 1
    else:
        db.close()
        raise HTTPException(402, "Plus de crédits")
    db.execute("""
        INSERT INTO searches (user_id, query_data, result_count, cost)
        VALUES (?,?,?,?)
    """, (user_id, json.dumps(query_data), result_count, cost))
    db.commit()
    updated = db.execute("SELECT free_left, credits FROM users WHERE id=?", (user_id,)).fetchone()
    db.close()
    return dict(updated)

@app.post("/api/search")
async def search(data: SearchModel, user=Depends(get_current_user)):
    if user["free_left"] <= 0 and user["credits"] <= 0:
        raise HTTPException(402, "Plus de crédits")
    payload = {"flexible": data.flexible, "per_page": 10}
    if data.nom_famille: payload["nom_famille"] = data.nom_famille
    if data.prenom:      payload["prenom"]      = data.prenom
    if data.email:       payload["email"]       = data.email
    if data.telephone:   payload["telephone"]   = data.telephone
    if data.adresse:     payload["adresse"]     = data.adresse
    if data.ville:       payload["ville"]       = data.ville
    if data.code_postal: payload["code_postal"] = data.code_postal
    if data.pays:        payload["pays"]        = data.pays
    if len(payload) <= 2:
        raise HTTPException(400, "Remplissez au moins un champ")
    result = await call_brix("POST", "/search", payload)
    results = result.get("data", {}).get("results", [])
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
    rows = db.execute("""
        SELECT id, query_data, result_count, cost, created_at
        FROM searches WHERE user_id=? ORDER BY created_at DESC LIMIT 50
    """, (user["id"],)).fetchall()
    db.close()
    return [dict(r) for r in rows]

# ── STRIPE ────────────────────────────────────────────────────────────────────
@app.get("/api/credits/packs")
async def get_packs():
    return CREDIT_PACKS

@app.post("/api/credits/checkout/{pack_id}")
async def checkout(pack_id: str, user=Depends(get_current_user), request: Request = None):
    if pack_id not in CREDIT_PACKS:
        raise HTTPException(400, "Pack invalide")
    pack   = CREDIT_PACKS[pack_id]
    origin = str(request.base_url).rstrip("/")
    try:
        print(f"[STRIPE] key={STRIPE_SECRET[:20]}... pack={pack_id}")
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency":     "eur",
                    "product_data": {"name": f"Xtracker — {pack['label']} ({pack['credits']} crédits)"},
                    "unit_amount":  int(pack["price_eur"] * 100),
                },
                "quantity": 1,
            }],
            mode="payment",
            success_url=f"{origin}/dashboard.html?payment=success",
            cancel_url=f"{origin}/dashboard.html?payment=cancel",
            metadata={"user_id": str(user["id"]), "pack_id": pack_id, "credits": str(pack["credits"])},
        )
        return {"checkout_url": session.url}
    except Exception as e:
        print(f"[STRIPE ERROR] {e}")
        raise HTTPException(500, str(e))

@app.post("/api/stripe/webhook")
async def webhook(request: Request):
    payload = await request.body()
    sig     = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK)
    except Exception:
        raise HTTPException(400, "Webhook invalide")
    if event["type"] == "checkout.session.completed":
        s       = event["data"]["object"]
        uid     = int(s["metadata"]["user_id"])
        credits = int(s["metadata"]["credits"])
        amount  = s["amount_total"] / 100
        db = get_db()
        db.execute("UPDATE users SET credits=credits+? WHERE id=?", (credits, uid))
        db.execute("""
            INSERT INTO transactions (user_id, type, credits, amount_eur, stripe_id, status)
            VALUES (?,?,?,?,?,'completed')
        """, (uid, "purchase", credits, amount, s["id"]))
        db.commit()
        db.close()
    return {"status": "ok"}

@app.get("/api/transactions")
async def transactions(user=Depends(get_current_user)):
    db = get_db()
    rows = db.execute("""
        SELECT id, type, credits, amount_eur, status, created_at
        FROM transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 20
    """, (user["id"],)).fetchall()
    db.close()
    return [dict(r) for r in rows]

# ── ADMIN ─────────────────────────────────────────────────────────────────────
@app.get("/api/admin/stats")
async def admin_stats(admin=Depends(require_admin)):
    db = get_db()
    total_users    = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    new_today      = db.execute("SELECT COUNT(*) FROM users WHERE date(created_at)=date('now')").fetchone()[0]
    total_searches = db.execute("SELECT COUNT(*) FROM searches").fetchone()[0]
    searches_today = db.execute("SELECT COUNT(*) FROM searches WHERE date(created_at)=date('now')").fetchone()[0]
    revenue        = db.execute("SELECT COALESCE(SUM(amount_eur),0) FROM transactions WHERE status='completed'").fetchone()[0]
    banned         = db.execute("SELECT COUNT(*) FROM users WHERE banned=1").fetchone()[0]
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
        rows  = db.execute("SELECT id,email,username,role,credits,free_left,created_at,last_login,banned FROM users WHERE email LIKE ? OR username LIKE ? ORDER BY created_at DESC LIMIT 20 OFFSET ?", (f"%{search}%", f"%{search}%", offset)).fetchall()
        total = db.execute("SELECT COUNT(*) FROM users WHERE email LIKE ? OR username LIKE ?", (f"%{search}%", f"%{search}%")).fetchone()[0]
    else:
        rows  = db.execute("SELECT id,email,username,role,credits,free_left,created_at,last_login,banned FROM users ORDER BY created_at DESC LIMIT 20 OFFSET ?", (offset,)).fetchall()
        total = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    db.close()
    return {"users": [dict(r) for r in rows], "total": total}

@app.patch("/api/admin/users/{user_id}")
async def admin_update(user_id: int, data: AdminUserUpdate, admin=Depends(require_admin)):
    db = get_db()
    if data.credits is not None:
        db.execute("UPDATE users SET credits=? WHERE id=?", (data.credits, user_id))
    if data.banned is not None:
        db.execute("UPDATE users SET banned=? WHERE id=?", (1 if data.banned else 0, user_id))
    if data.role is not None:
        db.execute("UPDATE users SET role=? WHERE id=?", (data.role, user_id))
    db.commit(); db.close()
    return {"message": "Mis à jour"}

@app.delete("/api/admin/users/{user_id}")
async def admin_delete(user_id: int, admin=Depends(require_admin)):
    db = get_db()
    db.execute("DELETE FROM searches WHERE user_id=?", (user_id,))
    db.execute("DELETE FROM transactions WHERE user_id=?", (user_id,))
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit(); db.close()
    return {"message": "Supprimé"}

@app.post("/api/admin/users/{user_id}/add-credits")
async def admin_add_credits(user_id: int, request: Request, admin=Depends(require_admin)):
    body    = await request.json()
    credits = int(body.get("credits", 0))
    db = get_db()
    db.execute("UPDATE users SET credits=credits+? WHERE id=?", (credits, user_id))
    db.execute("INSERT INTO transactions (user_id,type,credits,amount_eur,status) VALUES (?,?,?,0,'completed')", (user_id, "admin_grant", credits))
    db.commit(); db.close()
    return {"message": f"{credits} crédits ajoutés"}

@app.get("/api/admin/searches")
async def admin_searches(admin=Depends(require_admin), page: int = 1):
    db     = get_db()
    offset = (page - 1) * 50
    rows   = db.execute("""
        SELECT s.id, s.query_data, s.result_count, s.cost, s.created_at, u.email, u.username
        FROM searches s JOIN users u ON s.user_id=u.id
        ORDER BY s.created_at DESC LIMIT 50 OFFSET ?
    """, (offset,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.get("/api/admin/transactions")
async def admin_tx(admin=Depends(require_admin)):
    db   = get_db()
    rows = db.execute("""
        SELECT t.id, t.type, t.credits, t.amount_eur, t.status, t.created_at, u.email, u.username
        FROM transactions t JOIN users u ON t.user_id=u.id
        ORDER BY t.created_at DESC LIMIT 100
    """).fetchall()
    db.close()
    return [dict(r) for r in rows]

# ── STATIC ────────────────────────────────────────────────────────────────────
app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    print("\n╔══════════════════════════════════════╗")
    print("  Xtracker Server")
    print("  http://localhost:8080")
    print("  Admin : admin@xtracker.io / Admin1234!")
    print("╚══════════════════════════════════════╝\n")
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=True)