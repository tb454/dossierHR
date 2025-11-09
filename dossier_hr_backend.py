import os, uuid, json, hashlib, hmac, time
from datetime import datetime
from typing import Optional, List, Annotated
from pathlib import Path

import structlog
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, Header, Query, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
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

from scraper_router import router as scraper_router
from urllib.parse import urlparse

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
app.include_router(scraper_router)

# Serve /static/* (HTML/JS/JSON)
app.mount("/static", StaticFiles(directory="static", html=True), name="static")
STATIC_DIR = Path("static")

# Security headers (CSP, frame, etc.)
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp: Response = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-XSS-Protection"] = "0"
        # Allow Tailwind CDN for your static pages; keep strict elsewhere
        # If you self-host Tailwind later, you can revert to 'self' only.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "script-src 'self' https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline'; "
            "frame-ancestors 'none';"
        )
        # HSTS in prod only (bonus hardening)
        if ENV == "production":
            resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
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
# Passive ingestion
# --------------------------
class DossierEvent(BaseModel):
    user_id: str
    source_product: str   # "BRidge", "Vayudeck", etc.
    activity_type: str    # "contract_posted", "motion_detected", etc.
    raw_data: dict
    timestamp: Optional[datetime] = None  # allow sender to omit

@app.post("/dossier-dump", tags=["Sync"], summary="Passive nightly dump from other platforms")
def dossier_dump(e: DossierEvent):
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dossier_behavior_log (
              id UUID PRIMARY KEY,
              user_id TEXT NOT NULL,
              source_product TEXT NOT NULL,
              activity_type TEXT NOT NULL,
              raw_data JSONB,
              timestamp TIMESTAMP NOT NULL DEFAULT NOW()
            )
        """)
        conn.execute("""
            INSERT INTO dossier_behavior_log (id, user_id, source_product, activity_type, raw_data, timestamp)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (
            str(uuid.uuid4()),
            e.user_id,
            e.source_product,
            e.activity_type,
            json.dumps(e.raw_data),
            e.timestamp or datetime.utcnow()
        ))
    return {"ok": True}

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

@app.get("/me", tags=["Auth"], summary="Return current session identity")
def me(request: Request):
    return {
        "ok": True,
        "email": request.session.get("user"),
        "role": request.session.get("role")
    }

# --------------------------
# Server-side role-gated UI routes (belt & suspenders)
# --------------------------
def _serve_html(name: str) -> HTMLResponse:
    path = STATIC_DIR / name
    if not path.exists():
        raise HTTPException(404, "Page not found")
    return HTMLResponse(path.read_text(encoding="utf-8"))

@app.get("/dashboard/employee", tags=["UI"], summary="Employee dashboard (role-gated)")
def ui_employee(request: Request):
    role = request.session.get("role")
    if role not in ("employee", "manager", "admin"):
        return RedirectResponse("/static/login.html", status_code=302)
    return _serve_html("employee.html")

@app.get("/dashboard/manager", tags=["UI"], summary="Manager dashboard (role-gated)")
def ui_manager(request: Request):
    role = request.session.get("role")
    if role not in ("manager", "admin"):
        return RedirectResponse("/static/login.html", status_code=302)
    return _serve_html("manager.html")

@app.get("/dashboard/admin", tags=["UI"], summary="Admin dashboard (role-gated)")
def ui_admin(request: Request):
    role = request.session.get("role")
    if role != "admin":
        return RedirectResponse("/static/login.html", status_code=302)
    return _serve_html("admin.html")

# --------------------------
from pydantic import BaseModel, Field, AnyUrl
from typing import List, Optional
import uuid
from urllib.parse import urlparse

# ---------- Bulk upsert companies (+ optional seeds) ----------
class SeedIn(BaseModel):
    url: AnyUrl
    scope: str = "host"
    source: Optional[str] = None  # 'official','dps','yelp','bbb','scrapmonster','mapquest', etc.

class CompanyIn(BaseModel):
    name: str = Field(min_length=1)
    city: Optional[str] = None
    state: Optional[str] = "AZ"
    notes: Optional[str] = None
    seeds: List[SeedIn] = []      # zero or more seed URLs

@app.post("/admin/companies/bulk_upsert", tags=["Admin","Scraper"], summary="Bulk upsert companies and attach seed URLs")
def bulk_upsert_companies(items: List[CompanyIn], request: Request):
    require_admin(request)
    added, updated, seeds_added = 0, 0, 0
    with db() as conn:
        for it in items:
            # find by exact name + (optional) city/state; adjust matching as you like
            row = conn.execute(
                "SELECT id FROM companies WHERE name=%s AND COALESCE(city,'')=COALESCE(%s,'') AND COALESCE(state,'')=COALESCE(%s,'')",
                (it.name, it.city, it.state)
            ).fetchone()
            if row:
                cid = row["id"]
                conn.execute("UPDATE companies SET notes=COALESCE(%s, notes), updated_at=NOW() WHERE id=%s", (it.notes, cid))
                updated += 1
            else:
                cid = str(uuid.uuid4())
                conn.execute("INSERT INTO companies (id,name,city,state,notes) VALUES (%s,%s,%s,%s,%s)", (cid, it.name, it.city, it.state, it.notes))
                added += 1

            # attach seeds (and push into frontier queue)
            for s in it.seeds:
                try:
                    sid = str(uuid.uuid4())
                    conn.execute(
                        "INSERT INTO company_seeds (id, company_id, url, scope, source) VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                        (sid, cid, str(s.url), s.scope, s.source)
                    )
                    # also mirror into scrape_frontier so scheduler will pick it up
                    pu = urlparse(str(s.url))
                    conn.execute(
                        "INSERT INTO scrape_frontier (id, seed_id, url, host, scope, priority) "
                        "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                        (str(uuid.uuid4()), sid, str(s.url), pu.netloc.lower(), s.scope, 50)
                    )
                    seeds_added += 1
                except Exception:
                    pass
    return {"ok": True, "companies_added": added, "companies_updated": updated, "seeds_enqueued": seeds_added}

# ---------- Queue verification for one company (kick off your existing flow) ----------
@app.post("/admin/companies/{company_id}/queue_verification", tags=["Admin","Scraper"], summary="Queue verification crawl for a company")
def queue_company_verification(company_id: str, request: Request, max_pages: int = Query(25, ge=1, le=200), scope: str = Query("host")):
    require_admin(request)
    with db() as conn:
        # gather seeds for the company
        seeds = conn.execute("SELECT id, url, scope FROM company_seeds WHERE company_id=%s", (company_id,)).fetchall()
        if not seeds:
            raise HTTPException(400, "No seeds for this company")
    # Create an ad-hoc scrape task per seed (your /scraper/tasks runner handles background)
    created = []
    for s in seeds:
        tid = str(uuid.uuid4())
        # record task
        with db() as conn:
            conn.execute(
                "INSERT INTO scrape_tasks (id, seed_url, max_pages, scope, notes, status) VALUES (%s,%s,%s,%s,%s,'queued')",
                (tid, s["url"], max_pages, scope or s["scope"], f"company:{company_id}")
            )
        # run background locally (reuse router’s runner)
        from scraper_router import run_task  # safe import (module-level function)
        # You can also push this to a worker queue; here we just return identifiers:
        created.append({"task_id": tid, "seed_url": s["url"]})
    return {"ok": True, "created_tasks": created}
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

class VerifyWebsiteOut(BaseModel):
    profile_id: str
    target_url: str
    found_canonical: Optional[str] = None
    title_match: Optional[bool] = None
    status: str
    notes: Optional[str] = None

@app.post("/admin/profiles/{profile_id}/verify_website", tags=["Verification"], summary="Scrape & verify a profile's website (admin)")
def verify_profile_website(profile_id: str, request: Request, max_pages: int = Query(10, ge=1, le=100), scope: str = Query("host")):
    require_manager_or_admin(request)
    # 1) lookup profile
    with db() as conn:
        prof = conn.execute("SELECT id, display_name, external_ref FROM profiles WHERE id=%s", (profile_id,)).fetchone()
        if not prof:
            raise HTTPException(404, "profile not found")
    if not prof["external_ref"]:
        raise HTTPException(400, "profile has no external_ref (website) set")

    # 2) create a scrape task and run inline (small scope) to produce an immediate signal
    #    (for larger scale use /scraper/tasks to run in background)
    from scraper_core import PoliteSyncCrawler
    crawler = PoliteSyncCrawler()

    seed = prof["external_ref"]
    seen, queue = set(), [seed]
    found = None
    title_match = None
    parsed_name = (prof["display_name"] or "").lower()

    try:
        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen: 
                continue
            seen.add(url)
            rec, err = crawler.fetch(url)
            if rec:
                # store result for provenance (ad hoc, separate from /scraper/tasks)
                with db() as conn:
                    conn.execute(
                        "INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,'web_verify',%s)",
                        (prof["id"], json.dumps({
                            "url": rec["url"], "status_code": rec["status_code"],
                            "title": rec["title"], "canonical_url": rec["canonical_url"],
                            "meta_sample": list(rec["meta"].keys())[:8],
                            "ts": rec["fetched_at"].isoformat()
                        }, default=str))
                    )

                # signal extraction
                if rec.get("canonical_url"):
                    found = rec["canonical_url"]
                if rec.get("title"):
                    t = (rec["title"] or "").lower()
                    # simple heuristic: display_name must appear in <title>
                    title_match = (parsed_name in t) if parsed_name else None

                # limited discovery
                for link in (rec.get("links_sample") or []):
                    from scraper_router import _within_scope
                    if _within_scope(seed, link, scope):
                        queue.append(link)

        status = "verified" if (found or title_match) else "inconclusive"
        notes = None if status == "verified" else "No clear canonical/title signal found within scope."
        out = VerifyWebsiteOut(profile_id=prof["id"], target_url=seed, found_canonical=found,
                               title_match=title_match, status=status, notes=notes)
        # persist verification summary
        with db() as conn:
            conn.execute(
                "INSERT INTO verifications (profile_id, kind, status, meta) VALUES (%s,%s,%s,%s)",
                (prof["id"], "website", status, json.dumps(out.model_dump()))
            )
            conn.execute(
                "INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,'verification',%s)",
                (prof["id"], json.dumps({"kind":"website","status":status,"details":out.model_dump()}))
            )
        return out
    except Exception as e:
        raise HTTPException(500, f"verification failed: {e}")
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
def shadowban(profile_id: str, request: Request, reason: Optional[str] = None):
    require_manager_or_admin(request)
    with db() as conn:
        conn.execute(
            "INSERT INTO shadowbans (profile_id, reason, active) VALUES (%s,%s,TRUE)",
            (profile_id, reason)
        )
        conn.execute(
            "INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,'shadowban',%s)",
            (profile_id, json.dumps({"reason": reason}))
        )
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
# Portfolio-wide ingest (signed, idempotent)
# --------------------------
@app.post("/sync/{product}", tags=["Sync"], summary="Ingest signed events from any Atlas build")
async def sync_product(
    product: str,
    request: Request,
    x_signature: Optional[str] = Header(None),
    idempotency_key: Optional[str] = Header(None)
):
    body = await request.body()
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
