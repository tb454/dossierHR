import os, uuid, json, hashlib, hmac, time
from datetime import datetime
from typing import Optional, List, Annotated

import structlog
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, Header, Query, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, Field
import bcrypt
import psycopg
from psycopg.rows import dict_row

# --------------------------
# Env & logging
# --------------------------
load_dotenv()
log = structlog.get_logger()

ENV = os.getenv("ENV", "development")
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev_secret_change_me")
HOSTS = [h.strip() for h in os.getenv("HOSTS", "localhost,127.0.0.1").split(",")]
DB_URL = os.getenv("DATABASE_URL")
BRIDGE_SYNC_HMAC_SECRET = os.getenv("BRIDGE_SYNC_HMAC_SECRET", "dev_hmac")  # kept for backward compat if you ever need it
INGEST_WEBHOOK_SECRET = os.getenv("INGEST_WEBHOOK_SECRET", "dev_ingest")
PROM_ENABLED = os.getenv("PROM_ENABLED", "true").lower() == "true"

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@dossierhr.local")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")  # bcrypt hash

# ===== Multi-product HMAC secrets (NEW) =====
PRODUCT_SECRETS = {
    "bridge": os.getenv("BRIDGE_SYNC_HMAC_SECRET", ""),
    "truck_tunnel": os.getenv("TRUCK_TUNNEL_HMAC_SECRET", ""),
    "polevolt": os.getenv("POLEVOLT_HMAC_SECRET", ""),
    "oceangrid": os.getenv("OCEANGRID_HMAC_SECRET", ""),
    "vayudeck": os.getenv("VAYUDECK_HMAC_SECRET", ""),
    "loct": os.getenv("LOCT_HMAC_SECRET", ""),
    "starhop": os.getenv("STARHOP_HMAC_SECRET", ""),
}

def _verify_hmac_by_product(body: bytes, header_sig: Optional[str], product: str) -> None:
    secret = PRODUCT_SECRETS.get(product) or ""
    mac = hmac.new(secret.encode(), body or b"", hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, header_sig or ""):
        raise HTTPException(401, "Invalid signature")

# --------------------------
# App
# --------------------------
app = FastAPI(
    title="Dossier HR Backend",
    version="1.0.0",
    description="Industrial-grade HR/Review/Verification backend for Dossier.",
)

# Security headers (CSP, frame, etc.)
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp: Response = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-XSS-Protection"] = "0"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none';"
        return resp

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"] if ENV != "production" else HOSTS)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="lax", https_only=(ENV=="production"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if ENV!="production" else ["https://dossierdating.com","https://atlasipholdingsllc.com"],
    allow_credentials=True,
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allow_headers=["*"],
)

# Rate limit
limiter = Limiter(key_func=get_remote_address)
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response

# Prometheus
if PROM_ENABLED:
    Instrumentator().instrument(app).expose(app)

# --------------------------
# DB helper
# --------------------------
def db():
    if not DB_URL:
        raise RuntimeError("DATABASE_URL missing")
    return psycopg.connect(DB_URL, autocommit=True, row_factory=dict_row)

# --------------------------
# Schemas
# --------------------------
class LoginIn(BaseModel):
    email: str
    password: str

class ProfileIn(BaseModel):
    display_name: str
    external_ref: Optional[str] = None
    picture_url: Optional[str] = None

class ProfileOut(ProfileIn):
    id: str
    created_at: datetime
    deleted_at: Optional[datetime] = None

class ReviewIn(BaseModel):
    reviewer_profile_id: Optional[str] = None
    subject_profile_id: str
    stars: int = Field(ge=1, le=5)
    text: Optional[str] = None

class ReviewOut(BaseModel):
    id: str
    subject_profile_id: str
    stars: int
    text: Optional[str]
    sentiment: Optional[float]
    weight: float
    status: str
    created_at: datetime
    moderation_meta: dict

class VerificationIn(BaseModel):
    profile_id: str
    kind: str  # gov_id, selfie, video, evidence
    meta: dict = {}

class DisputeIn(BaseModel):
    review_id: str
    notes: Optional[str] = None

# --------------------------
# Auth utils (bcrypt fallback)
# --------------------------
def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False

def require_admin(req: Request):
    role = req.session.get("role")
    if role != "admin":
        raise HTTPException(403, "Admin only")
    return True

def require_manager_or_admin(req: Request):
    role = req.session.get("role")
    if role not in ("admin","manager"):
        raise HTTPException(403, "Manager/Admin only")
    return True

# --------------------------
# Health
# --------------------------
@app.get("/health", tags=["System"], summary="Healthcheck")
def health():
    return {"ok": True, "env": ENV, "ts": datetime.utcnow().isoformat()}

# --------------------------
# Auth
# --------------------------
@app.post("/login", tags=["Auth"], summary="Login")
@limiter.limit("10/minute")
def login(payload: LoginIn, request: Request):
    # Quick admin fallback
    if payload.email == ADMIN_EMAIL and ADMIN_PASSWORD_HASH and verify_password(payload.password, ADMIN_PASSWORD_HASH):
        request.session["user"] = ADMIN_EMAIL
        request.session["role"] = "admin"
        return {"ok": True, "role": "admin"}

    # DB lookup
    with db() as conn:
        row = conn.execute(
            "SELECT u.email, u.password_hash, r.name as role FROM hr_users u JOIN roles r ON u.role_id=r.id WHERE u.email=%s AND u.is_active=TRUE",
            (payload.email,)
        ).fetchone()
        if not row:
            raise HTTPException(401, "Invalid credentials")
        if not verify_password(payload.password, row["password_hash"]):
            raise HTTPException(401, "Invalid credentials")
    request.session["user"] = row["email"]
    request.session["role"] = row["role"]
    return {"ok": True, "role": row["role"]}

@app.post("/logout", tags=["Auth"], summary="Logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}

# --------------------------
# Profiles
# --------------------------
@app.post("/profiles", tags=["Profiles"], summary="Create profile")
def create_profile(p: ProfileIn, request: Request):
    require_manager_or_admin(request)
    with db() as conn:
        row = conn.execute(
            "INSERT INTO profiles (display_name, external_ref, picture_url) VALUES (%s,%s,%s) RETURNING id, display_name, external_ref, picture_url, created_at, deleted_at",
            (p.display_name, p.external_ref, p.picture_url)
        ).fetchone()
    return row

@app.get("/profiles", tags=["Profiles"], summary="List profiles")
def list_profiles(
    q: Optional[str]=Query(None, description="Search by display_name/external_ref"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    sql = "SELECT * FROM profiles WHERE deleted_at IS NULL"
    vals = []
    if q:
        sql += " AND (display_name ILIKE %s OR external_ref ILIKE %s)"
        vals.extend([f"%{q}%", f"%{q}%"])
    sql += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
    vals.extend([limit, offset])
    with db() as conn:
        rows = conn.execute(sql, tuple(vals)).fetchall()
    return rows

# --------------------------
# Reviews (with moderation pipeline)
# --------------------------
BANNED_WORDS = {"kill","die","tranny","slur1","slur2"}  # minimal example

def run_moderation(text: Optional[str]) -> dict:
    if not text:
        return {"profanity": False, "hate": False, "threat": False, "doxx": False, "opinion_defamation": False, "sentiment": 0.0, "weight": 1.0, "status": "approved"}
    t = text.lower()
    flags = {
        "profanity": any(w in t for w in ["fuck","shit"]),
        "hate": any(w in t for w in ["tranny","kike","spic","nigger","retard"]),  # example; expand in real filter
        "threat": any(w in t for w in ["kill","i'll find you","hope you die"]),
        "doxx": any(k in t for k in ["@gmail.com",".com", " st ", " ave ", " road ", " street ", "address"]),
        "opinion_defamation": any(phrase in t for phrase in ["has herpes","is a criminal"]),
    }
    negative = any(flags[k] for k in ["hate","threat"])
    # crude sentiment
    sentiment = -0.6 if negative else (-0.2 if "lied" in t or "manipulative" in t else 0.2 if "respectful" in t else 0.0)
    weight = 1.35 if sentiment < -0.5 else (1.15 if sentiment < -0.1 else 1.0)
    status = "blocked" if flags["hate"] or flags["threat"] else ("pending" if flags["opinion_defamation"] else "approved")
    return {"sentiment": sentiment, "weight": weight, "status": status, **flags}

@app.post("/reviews", tags=["Reviews"], summary="Create review")
def create_review(r: ReviewIn, request: Request):
    # anyone authenticated can post; moderation decides visibility
    pipe = run_moderation(r.text)
    with db() as conn:
        row = conn.execute(
            """INSERT INTO reviews (reviewer_profile_id, subject_profile_id, stars, text, sentiment, weight, status, moderation_meta)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
               RETURNING id, subject_profile_id, stars, text, sentiment, weight, status, created_at, moderation_meta""",
            (r.reviewer_profile_id, r.subject_profile_id, r.stars, r.text, pipe["sentiment"], pipe["weight"], pipe["status"], json.dumps(pipe))
        ).fetchone()
        # flags table
        for k in ("profanity","hate","threat","doxx","opinion_defamation"):
            if pipe.get(k):
                sev = 5 if k in ("hate","threat") else 3
                conn.execute("INSERT INTO review_flags (review_id, flag_type, severity) VALUES (%s,%s,%s)", (row["id"], "defamation" if k=="opinion_defamation" else k, sev))
        # append immutable HR record
        conn.execute(
            "INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,'review',%s)",
            (r.subject_profile_id, json.dumps({"review_id": row["id"], "stars": r.stars, "status": pipe["status"]}))
        )
    return row

@app.get("/reviews", tags=["Reviews"], summary="List reviews")
def list_reviews(
    subject_profile_id: Optional[str]=None,
    status: Optional[str]=Query(None, description="approved/pending/blocked"),
    start: Optional[datetime]=None,
    end: Optional[datetime]=None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    sql = "SELECT id, subject_profile_id, stars, text, sentiment, weight, status, created_at, moderation_meta FROM reviews WHERE 1=1"
    vals = []
    if subject_profile_id:
        sql += " AND subject_profile_id=%s"; vals.append(subject_profile_id)
    if status:
        sql += " AND status=%s"; vals.append(status)
    if start:
        sql += " AND created_at >= %s"; vals.append(start)
    if end:
        sql += " AND created_at <= %s"; vals.append(end)
    sql += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
    vals.extend([limit, offset])
    with db() as conn:
        rows = conn.execute(sql, tuple(vals)).fetchall()
    return rows

# --------------------------
# Moderation admin endpoints
# --------------------------
class ReviewStatusPatch(BaseModel):
    status: str = Field(pattern="^(approved|pending|blocked)$")
    note: Optional[str] = None

@app.patch("/admin/reviews/{review_id}", tags=["Moderation"], summary="Moderate review")
def moderate_review(review_id: str, patch: ReviewStatusPatch, request: Request):
    require_manager_or_admin(request)
    with db() as conn:
        conn.execute("UPDATE reviews SET status=%s, moderated_at=NOW() WHERE id=%s", (patch.status, review_id))
        conn.execute(
            "INSERT INTO hr_records (profile_id, event_type, payload) "
            "SELECT subject_profile_id, 'review', jsonb_build_object('review_id', id, 'moderated_to', %s) FROM reviews WHERE id=%s",
            (patch.status, review_id)
        )
    return {"ok": True}

@app.post("/disputes", tags=["Moderation"], summary="Open dispute/appeal")
def open_dispute(d: DisputeIn, request: Request):
    with db() as conn:
        row = conn.execute(
            "INSERT INTO disputes (review_id, notes) VALUES (%s,%s) RETURNING id, status, created_at",
            (d.review_id, d.notes)
        ).fetchone()
    return row

@app.post("/admin/disputes/{dispute_id}/decide", tags=["Moderation"], summary="Decide dispute (manager/admin)")
def decide_dispute(dispute_id: str, outcome: Annotated[str, Query(pattern="^(upheld|removed)$")], request: Request):
    require_manager_or_admin(request)
    with db() as conn:
        conn.execute("UPDATE disputes SET status=%s, decided_at=NOW() WHERE id=%s", (outcome, dispute_id))
        # if removed, set review blocked
        if outcome == "removed":
            rev = conn.execute("SELECT review_id FROM disputes WHERE id=%s", (dispute_id,)).fetchone()
            if rev:
                conn.execute("UPDATE reviews SET status='blocked', moderated_at=NOW() WHERE id=%s", (rev["review_id"],))
    return {"ok": True}

# --------------------------
# Verifications
# --------------------------
@app.post("/verifications", tags=["Verification"], summary="Submit verification")
def submit_verification(v: VerificationIn, request: Request):
    with db() as conn:
        row = conn.execute(
            "INSERT INTO verifications (profile_id, kind, status, meta) VALUES (%s,%s,'pending',%s) RETURNING *",
            (v.profile_id, v.kind, json.dumps(v.meta))
        ).fetchone()
        conn.execute(
            "INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,'verification',%s)",
            (v.profile_id, json.dumps({"verification_id": row["id"], "kind": v.kind, "status": "pending"}))
        )
    return row

@app.post("/admin/verifications/{verification_id}/approve", tags=["Verification"], summary="Approve verification")
def approve_verification(verification_id: str, request: Request):
    require_manager_or_admin(request)
    with db() as conn:
        row = conn.execute("UPDATE verifications SET status='approved', reviewed_at=NOW() WHERE id=%s RETURNING profile_id", (verification_id,)).fetchone()
        if row:
            conn.execute("INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,'verification',%s)",
                         (row["profile_id"], json.dumps({"verification_id": verification_id, "status": "approved"})))
    return {"ok": True}

# --------------------------
# Shadowban
# --------------------------
@app.post("/admin/shadowban/{profile_id}", tags=["Moderation"], summary="Shadowban a profile")
def shadowban(profile_id: str, reason: Optional[str]=None, request: Request=Depends()):
    require_manager_or_admin(request)
    with db() as conn:
        conn.execute("INSERT INTO shadowbans (profile_id, reason, active) VALUES (%s,%s,TRUE)", (profile_id, reason))
        conn.execute("INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,'shadowban',%s)", (profile_id, json.dumps({"reason": reason})))
    return {"ok": True}

# --------------------------
# Analytics
# --------------------------
@app.get("/analytics/reviews_by_day", tags=["Analytics"], summary="Count reviews by day")
def reviews_by_day(days: int = Query(30, ge=1, le=365)):
    with db() as conn:
        rows = conn.execute(
            "SELECT date_trunc('day', created_at) AS day, COUNT(*) AS cnt FROM reviews WHERE created_at >= NOW() - (%s || ' days')::interval GROUP BY 1 ORDER BY 1",
            (days,)
        ).fetchall()
    return rows

# --------------------------
# Nightly dump (CSV-like JSONL) + export
# --------------------------
@app.post("/admin/run_nightly_dump", tags=["Data"], summary="Run nightly dump (admin)")
def run_dump(request: Request):
    require_admin(request)
    run_id = str(uuid.uuid4())
    path = f"/tmp/dossier_dump_{run_id}.jsonl"
    with db() as conn, open(path, "w", encoding="utf-8") as f:
        conn.execute("INSERT INTO nightly_dumps (id, status, file_path) VALUES (%s,'running',%s)", (run_id, path))
        for table in ("profiles","verifications","reviews","review_flags","shadowbans","disputes","hr_records"):
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()
            for r in rows:
                f.write(json.dumps({"table": table, "row": r}, default=str) + "\n")
        conn.execute("UPDATE nightly_dumps SET status='success', run_at=NOW() WHERE id=%s", (run_id,))
    return {"ok": True, "dump_id": run_id, "file_path": path}

@app.get("/admin/dump/{dump_id}/download", tags=["Data"], summary="Download dump file")
def download_dump(dump_id: str, request: Request):
    require_admin(request)
    with db() as conn:
        row = conn.execute("SELECT file_path FROM nightly_dumps WHERE id=%s AND status='success'", (dump_id,)).fetchone()
        if not row or not row["file_path"] or not os.path.exists(row["file_path"]):
            raise HTTPException(404, "Dump not found")
    return FileResponse(row["file_path"], filename=os.path.basename(row["file_path"]))

# --------------------------
# Portfolio-wide ingest (NEW)
# --------------------------
@app.post("/sync/{product}", tags=["Sync"], summary="Ingest signed events from any Atlas build")
def sync_product(
    product: str,
    request: Request,
    x_signature: Optional[str] = Header(None),
    idempotency_key: Optional[str] = Header(None)
):
    body = request.scope.get("_body") or b""
    _verify_hmac_by_product(body, x_signature, product)

    try:
        payload = json.loads(body.decode() or "{}")
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    processed = 0
    with db() as conn:
        # ensure idempotency table exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ingest_ids (
              id TEXT PRIMARY KEY,
              created_at TIMESTAMP NOT NULL DEFAULT NOW()
            )
        """)
        if idempotency_key:
            exists = conn.execute("SELECT 1 FROM ingest_ids WHERE id=%s", (idempotency_key,)).fetchone()
            if exists:
                return {"ok": True, "product": product, "deduped": True, "processed": 0}
            conn.execute("INSERT INTO ingest_ids (id) VALUES (%s)", (idempotency_key,))

        for e in payload.get("events", []):
            # tag the source for analytics
            e["source"] = product
            conn.execute(
                "INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,%s,%s)",
                (e.get("profile_id"), f"{product}_event", json.dumps(e))
            )
            processed += 1

    return {"ok": True, "product": product, "processed": processed}

# --------------------------
# Legal pages (stubs)
# --------------------------
@app.get("/terms", tags=["Legal"], summary="Terms page")
def terms():
    return PlainTextResponse("Dossier HR Terms (see Dossier Dating Terms for platform-wide coverage).")

@app.get("/privacy", tags=["Legal"], summary="Privacy page")
def privacy():
    return PlainTextResponse("Dossier HR Privacy Policy (aligned to Dossier Dating Privacy).")

@app.get("/eula", tags=["Legal"], summary="EULA page")
def eula():
    return PlainTextResponse("Dossier HR EULA / Verified User Agreement summary.")

# --------------------------
# Run
# --------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dossier_hr_backend:app", host="0.0.0.0", port=int(os.getenv("PORT","8081")), reload=(ENV!="production"))
