import os, uuid, json, hashlib, hmac, time
from datetime import datetime
from typing import Optional, List, Annotated
from pathlib import Path
from datetime import timedelta
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
from pydantic import AnyUrl, BaseModel, Field
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
ATLAS_INGEST_SECRET = os.getenv("ATLAS_INGEST_SECRET", "")
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

def _verify_atlas_hmac(raw: bytes, ts: Optional[str], sig: Optional[str]) -> None:
    """
    Verify HMAC for BRidge/Atlas ingest.

    BRidge computes:
      ts = str(int(time.time()))
      mac = HMAC(ATLAS_INGEST_SECRET, ts + "." + raw_body).hexdigest()
      headers:
        X-Atlas-Timestamp: ts
        X-Atlas-Signature: mac
    """
    if not ATLAS_INGEST_SECRET:
        # In dev/CI, skip verification if no secret configured
        return

    if not (ts and sig):
        raise HTTPException(401, "Missing Atlas signature")

    expected = hmac.new(
        ATLAS_INGEST_SECRET.encode("utf-8"),
        ts.encode("utf-8") + b"." + (raw or b""),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, sig):
        raise HTTPException(401, "Invalid Atlas signature")

app = FastAPI(
    title="Dossier HR Backend",
    version="1.0.0",
    description="Industrial-grade HR/Review/Verification backend for Dossier.",
)
app.include_router(scraper_router)

# ----- BRidge Sales  -----
def ensure_sales_tables(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS sales_reps (
      id UUID PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'candidate', -- candidate/active/suspended/terminated
      legal_name TEXT,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      referral_code TEXT UNIQUE NOT NULL,
      agreement_signed_at TIMESTAMP NULL,
      w9_received_at TIMESTAMP NULL,
      payout_method TEXT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sales_accounts (
      id UUID PRIMARY KEY,
      bridge_account_id TEXT UNIQUE NOT NULL,
      company_name TEXT NULL,
      plan_tier TEXT NULL, -- starter/standard/enterprise
      status TEXT NOT NULL DEFAULT 'unknown', -- active/past_due/canceled/etc
      first_paid_at TIMESTAMP NULL, -- first subscription payment date
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS account_ownership (
      id UUID PRIMARY KEY,
      bridge_account_id TEXT NOT NULL,
      sales_owner_rep_id UUID NULL,
      house_account BOOLEAN NOT NULL DEFAULT FALSE,
      protection_expires_at TIMESTAMP NULL, -- 14-day lead protection window
      ownership_start TIMESTAMP NOT NULL DEFAULT NOW(),
      ownership_end TIMESTAMP NULL,
      ownership_reason TEXT NOT NULL DEFAULT 'unknown',
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_account_ownership_bridge ON account_ownership(bridge_account_id);
    CREATE INDEX IF NOT EXISTS idx_account_ownership_owner ON account_ownership(sales_owner_rep_id);

    CREATE TABLE IF NOT EXISTS commission_events (
      id UUID PRIMARY KEY,
      bridge_account_id TEXT NOT NULL,
      event_type TEXT NOT NULL, -- subscription_payment, overage_payment, refund, chargeback, milestone
      external_ref TEXT NULL,   -- invoice_id/payment_intent/etc for idempotency
      amount_cents BIGINT NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'USD',
      occurred_at TIMESTAMP NOT NULL,
      payload JSONB,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      UNIQUE (event_type, external_ref)
    );

    CREATE TABLE IF NOT EXISTS commission_ledger (
      id UUID PRIMARY KEY,
      rep_id UUID NOT NULL,
      bridge_account_id TEXT NOT NULL,
      commission_event_id UUID NULL,
      line_type TEXT NOT NULL, -- activation_bonus, residual_mrr, overage_residual, clawback, manual_adjustment
      amount_cents BIGINT NOT NULL,
      vesting_status TEXT NOT NULL DEFAULT 'earned', -- earned/pending/forfeited/paid
      scheduled_earn_date TIMESTAMP NOT NULL DEFAULT NOW(),
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_ledger_rep ON commission_ledger(rep_id);
    CREATE INDEX IF NOT EXISTS idx_ledger_sched ON commission_ledger(scheduled_earn_date);

    CREATE TABLE IF NOT EXISTS rep_payouts (
      id UUID PRIMARY KEY,
      rep_id UUID NOT NULL,
      period_start DATE NOT NULL,
      period_end DATE NOT NULL,
      net30_release_date DATE NOT NULL,
      total_cents BIGINT NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pending', -- pending/approved/paid/failed
      payout_ref TEXT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      paid_at TIMESTAMP NULL
    );

    CREATE TABLE IF NOT EXISTS rep_payout_lines (
      id UUID PRIMARY KEY,
      payout_id UUID NOT NULL,
      ledger_id UUID NOT NULL,
      amount_cents BIGINT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sales_sync_state (
      id TEXT PRIMARY KEY, -- e.g. 'bridge_commission_sync'
      last_created_at TIMESTAMP NOT NULL DEFAULT '1970-01-01'
    );

    CREATE TABLE IF NOT EXISTS sales_leads (
      id UUID PRIMARY KEY,
      rep_id UUID NOT NULL,
      company_name TEXT NOT NULL,
      contact_name TEXT NULL,
      contact_email TEXT NULL,
      contact_phone TEXT NULL,
      website TEXT NULL,
      city TEXT NULL,
      state TEXT NULL,
      stage TEXT NOT NULL DEFAULT 'new', -- new/contacted/demo/sent_invoice/closed_won/closed_lost
      notes TEXT NULL,
      protection_expires_at TIMESTAMP NOT NULL DEFAULT (NOW() + INTERVAL '14 days'),
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_sales_leads_rep ON sales_leads(rep_id);
    CREATE INDEX IF NOT EXISTS idx_sales_leads_stage ON sales_leads(stage);
    CREATE INDEX IF NOT EXISTS idx_sales_leads_created ON sales_leads(created_at);

    CREATE TABLE IF NOT EXISTS sales_lead_activities (
      id UUID PRIMARY KEY,
      lead_id UUID NOT NULL,
      rep_id UUID NOT NULL,
      activity_type TEXT NOT NULL, -- call/email/demo/note/text/other
      notes TEXT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_sales_lead_acts_lead ON sales_lead_activities(lead_id);
    CREATE INDEX IF NOT EXISTS idx_sales_lead_acts_rep ON sales_lead_activities(rep_id);             
    
    INSERT INTO sales_sync_state (id, last_created_at)
    VALUES ('bridge_commission_sync', '1970-01-01')
    ON CONFLICT (id) DO NOTHING;
    """)

PLAN_ACTIVATION = {
    "starter": 250_00,
    "standard": 750_00,
    "enterprise": 2500_00,
}

MRR_RATE_Y1 = 0.15
MRR_RATE_Y2 = 0.05
OVERAGE_RATE = 0.02

ACTIVATION_VESTING = [
    (0.50, 1),  # 50% after month 1 payment clears
    (0.25, 3),  # 25% after month 3
    (0.25, 6),  # 25% after month 6
]

class SalesRepCreateIn(BaseModel):
    legal_name: Optional[str] = None
    email: str
    phone: Optional[str] = None

def _new_ref_code():
    # short, human-friendly
    return uuid.uuid4().hex[:6].upper()

@app.post("/admin/sales/reps", tags=["Admin","Sales"], summary="Create sales rep (candidate)")
def create_sales_rep(payload: SalesRepCreateIn, request: Request):
    require_admin(request)
    with db() as conn:
        ensure_sales_tables(conn)
        rep_id = str(uuid.uuid4())
        code = _new_ref_code()
        row = conn.execute("""
            INSERT INTO sales_reps (id, status, legal_name, email, phone, referral_code)
            VALUES (%s,'candidate',%s,%s,%s,%s)
            RETURNING id, status, legal_name, email, phone, referral_code, created_at
        """, (rep_id, payload.legal_name, payload.email.lower().strip(), payload.phone, code)).fetchone()
    return row

@app.get("/admin/sales/reps", tags=["Admin","Sales"], summary="List sales reps")
def list_sales_reps(request: Request, limit: int = Query(200, ge=1, le=2000)):
    require_admin(request)
    with db() as conn:
        ensure_sales_tables(conn)
        rows = conn.execute("""
            SELECT id, status, legal_name, email, phone, referral_code, agreement_signed_at, w9_received_at, payout_method, created_at
            FROM sales_reps
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,)).fetchall()
    return rows

def _get_sales_owner(conn, bridge_account_id: str) -> Optional[str]:
    # Most recent active ownership row wins
    row = conn.execute("""
      SELECT sales_owner_rep_id, house_account
      FROM account_ownership
      WHERE bridge_account_id=%s AND ownership_end IS NULL
      ORDER BY ownership_start DESC
      LIMIT 1
    """, (bridge_account_id,)).fetchone()
    if not row or row["house_account"]:
        return None
    return row["sales_owner_rep_id"]

def _month_index(first_paid_at: datetime, paid_at: datetime) -> int:
    # 1-based month number from first payment
    return (paid_at.year - first_paid_at.year) * 12 + (paid_at.month - first_paid_at.month) + 1

def _upsert_sales_account(conn, bridge_account_id: str, payload: dict):
    company = payload.get("company_name")
    plan = (payload.get("plan_tier") or payload.get("plan") or "").lower() or None
    status = payload.get("status") or "unknown"
    conn.execute("""
      INSERT INTO sales_accounts (id, bridge_account_id, company_name, plan_tier, status)
      VALUES (%s,%s,%s,%s,%s)
      ON CONFLICT (bridge_account_id)
      DO UPDATE SET company_name=COALESCE(EXCLUDED.company_name, sales_accounts.company_name),
                    plan_tier=COALESCE(EXCLUDED.plan_tier, sales_accounts.plan_tier),
                    status=COALESCE(EXCLUDED.status, sales_accounts.status),
                    updated_at=NOW()
    """, (str(uuid.uuid4()), bridge_account_id, company, plan, status))

def _ensure_owner_from_referral(conn, bridge_account_id: str, referral_code: Optional[str], created_at: datetime):
    if not referral_code:
        return
    rep = conn.execute("SELECT id FROM sales_reps WHERE referral_code=%s", (referral_code,)).fetchone()
    if not rep:
        return
    # If no owner exists yet, set protection + provisional owner (you can override)
    existing = conn.execute("""
      SELECT 1 FROM account_ownership WHERE bridge_account_id=%s AND ownership_end IS NULL
    """, (bridge_account_id,)).fetchone()
    if existing:
        return
    conn.execute("""
      INSERT INTO account_ownership (id, bridge_account_id, sales_owner_rep_id, protection_expires_at, ownership_reason)
      VALUES (%s,%s,%s,%s,%s)
    """, (str(uuid.uuid4()), bridge_account_id, rep["id"], created_at + timedelta(days=14), "lead_referral_protection"))

@app.post("/admin/sales/sync_bridge_nightly", tags=["Admin","Sales"], summary="Nightly: process BRidge events into commission ledger")
def sync_bridge_nightly(request: Request, limit: int = Query(5000, ge=1, le=20000)):
    require_admin(request)
    processed = 0
    with db() as conn:
        ensure_sales_tables(conn)

        state = conn.execute("SELECT last_created_at FROM sales_sync_state WHERE id='bridge_commission_sync'").fetchone()
        cursor = state["last_created_at"]

        rows = conn.execute("""
          SELECT created_at, source_id, event_type, payload
          FROM atlas_ingest_log
          WHERE lower(source_system)='bridge'
            AND created_at > %s
          ORDER BY created_at ASC
          LIMIT %s
        """, (cursor, limit)).fetchall()

        for r in rows:
            created_at = r["created_at"]
            ev_type = (r["event_type"] or "").upper()
            payload = r["payload"] or {}

            bridge_account_id = payload.get("bridge_account_id") or payload.get("account_id") or payload.get("tenant_id")
            if not bridge_account_id:
                continue

            _upsert_sales_account(conn, bridge_account_id, payload)

            # Optional: claim owner from referral code early (lead protection)
            _ensure_owner_from_referral(conn, bridge_account_id, payload.get("referral_code"), created_at)

            # Map BRidge event types → commission event types
            mapped = None
            amount_cents = int(payload.get("amount_cents") or 0)
            currency = (payload.get("currency") or "USD").upper()
            external_ref = payload.get("invoice_id") or payload.get("payment_intent") or payload.get("external_ref")

            if ev_type in ("SUBSCRIPTION_PAYMENT_COLLECTED","SUBSCRIPTION_PAID","INVOICE_PAID"):
                mapped = "subscription_payment"
            elif ev_type in ("OVERAGE_PAYMENT_COLLECTED","OVERAGE_PAID"):
                mapped = "overage_payment"
            elif ev_type in ("REFUND_ISSUED","CHARGEBACK"):
                mapped = "refund"
                amount_cents = -abs(amount_cents)
            elif ev_type in ("MILESTONE_HIT","FIRST_BOL","FIRST_TONS","FIRST_CONTRACT"):
                mapped = "milestone"

            if not mapped:
                continue

            # Insert commission_event idempotently
            try:
                ce = conn.execute("""
                  INSERT INTO commission_events (id, bridge_account_id, event_type, external_ref, amount_cents, currency, occurred_at, payload)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                  RETURNING id
                """, (str(uuid.uuid4()), bridge_account_id, mapped, external_ref, amount_cents, currency, created_at, json.dumps(payload))).fetchone()
            except Exception:
                # likely UNIQUE(event_type, external_ref) collision
                ce = None

            # Now generate ledger lines off this event
            if ce:
                _apply_commission_rules(conn, bridge_account_id, mapped, created_at, amount_cents, payload, ce["id"])

            processed += 1
            cursor = created_at

        # advance cursor
        conn.execute("UPDATE sales_sync_state SET last_created_at=%s WHERE id='bridge_commission_sync'", (cursor,))

    return {"ok": True, "processed": processed}

def _ensure_first_paid_at(conn, bridge_account_id: str, paid_at: datetime):
    row = conn.execute("SELECT first_paid_at FROM sales_accounts WHERE bridge_account_id=%s", (bridge_account_id,)).fetchone()
    if row and row["first_paid_at"]:
        return row["first_paid_at"]
    conn.execute("UPDATE sales_accounts SET first_paid_at=%s WHERE bridge_account_id=%s", (paid_at, bridge_account_id))
    return paid_at

def _activation_awarded(conn, bridge_account_id: str) -> bool:
    row = conn.execute("""
      SELECT 1 FROM commission_ledger
      WHERE bridge_account_id=%s AND line_type='activation_bonus'
      LIMIT 1
    """, (bridge_account_id,)).fetchone()
    return bool(row)

def _milestone_seen(conn, bridge_account_id: str) -> bool:
    row = conn.execute("""
      SELECT 1 FROM commission_events
      WHERE bridge_account_id=%s AND event_type='milestone'
      LIMIT 1
    """, (bridge_account_id,)).fetchone()
    return bool(row)

def _apply_commission_rules(conn, bridge_account_id: str, mapped_type: str, occurred_at: datetime, amount_cents: int, payload: dict, commission_event_id: str):
    rep_id = _get_sales_owner(conn, bridge_account_id)
    if not rep_id:
        return  # house or unowned = no commission

    plan_tier = (payload.get("plan_tier") or payload.get("plan") or "").lower()

    # subscription payments -> residuals + possible activation vesting
    if mapped_type == "subscription_payment":
        first_paid_at = _ensure_first_paid_at(conn, bridge_account_id, occurred_at)
        mi = _month_index(first_paid_at, occurred_at)

        # residual rate based on month index
        rate = MRR_RATE_Y1 if mi <= 12 else (MRR_RATE_Y2 if mi <= 24 else 0.0)
        if rate > 0:
            comm = int(round(abs(amount_cents) * rate))
            conn.execute("""
              INSERT INTO commission_ledger (id, rep_id, bridge_account_id, commission_event_id, line_type, amount_cents, vesting_status, scheduled_earn_date)
              VALUES (%s,%s,%s,%s,'residual_mrr',%s,'earned',%s)
            """, (str(uuid.uuid4()), rep_id, bridge_account_id, commission_event_id, comm, occurred_at))

        # activation vesting only if milestone exists + not previously awarded
        if (not _activation_awarded(conn, bridge_account_id)) and _milestone_seen(conn, bridge_account_id):
            bonus_total = PLAN_ACTIVATION.get(plan_tier or "", 0)
            if bonus_total > 0:
                for pct, month_n in ACTIVATION_VESTING:
                    scheduled = occurred_at + timedelta(days=30*month_n)
                    conn.execute("""
                      INSERT INTO commission_ledger (id, rep_id, bridge_account_id, commission_event_id, line_type, amount_cents, vesting_status, scheduled_earn_date)
                      VALUES (%s,%s,%s,%s,'activation_bonus',%s,'pending',%s)
                    """, (str(uuid.uuid4()), rep_id, bridge_account_id, commission_event_id, int(round(bonus_total * pct)), scheduled))

    # milestone event might arrive before first payment — just store it and wait
    elif mapped_type == "milestone":
        return

    # overage payments -> 2%
    elif mapped_type == "overage_payment":
        comm = int(round(abs(amount_cents) * OVERAGE_RATE))
        if comm:
            conn.execute("""
              INSERT INTO commission_ledger (id, rep_id, bridge_account_id, commission_event_id, line_type, amount_cents, vesting_status, scheduled_earn_date)
              VALUES (%s,%s,%s,%s,'overage_residual',%s,'earned',%s)
            """, (str(uuid.uuid4()), rep_id, bridge_account_id, commission_event_id, comm, occurred_at))

    # refunds/chargebacks -> clawback (negative)
    elif mapped_type == "refund":
        # claw back proportional amounts if you have external_ref mapping later;
        # for now: create a negative adjustment equal to OVERAGE/MRR computed previously is harder.
        # Minimal: record the refund as a negative manual adjustment for review.
        conn.execute("""
          INSERT INTO commission_ledger (id, rep_id, bridge_account_id, commission_event_id, line_type, amount_cents, vesting_status, scheduled_earn_date)
          VALUES (%s,%s,%s,%s,'clawback',%s,'earned',%s)
        """, (str(uuid.uuid4()), rep_id, bridge_account_id, commission_event_id, int(round(amount_cents * 0.15)), occurred_at))

@app.post("/admin/sales/run_payouts", tags=["Admin","Sales"], summary="Create payout batches (net-30)")
def run_payouts(request: Request, period_start: str, period_end: str):
    require_admin(request)
    # period_start/end as YYYY-MM-DD
    ps = datetime.fromisoformat(period_start).date()
    pe = datetime.fromisoformat(period_end).date()
    net30 = (pe + timedelta(days=30))

    with db() as conn:
        ensure_sales_tables(conn)

        # eligible = earned/pending lines whose scheduled_earn_date is within period and <= period_end
        rows = conn.execute("""
          SELECT rep_id, id as ledger_id, amount_cents
          FROM commission_ledger
          WHERE vesting_status IN ('earned','pending')
            AND scheduled_earn_date::date BETWEEN %s AND %s
        """, (ps, pe)).fetchall()

        # group by rep
        by_rep = {}
        for r in rows:
            by_rep.setdefault(r["rep_id"], []).append(r)

        payouts = []
        for rep_id, lines in by_rep.items():
            payout_id = str(uuid.uuid4())
            total = sum(int(x["amount_cents"]) for x in lines)
            conn.execute("""
              INSERT INTO rep_payouts (id, rep_id, period_start, period_end, net30_release_date, total_cents, status)
              VALUES (%s,%s,%s,%s,%s,%s,'pending')
            """, (payout_id, rep_id, ps, pe, net30, total))

            for ln in lines:
                conn.execute("""
                  INSERT INTO rep_payout_lines (id, payout_id, ledger_id, amount_cents)
                  VALUES (%s,%s,%s,%s)
                """, (str(uuid.uuid4()), payout_id, ln["ledger_id"], ln["amount_cents"]))

            payouts.append({"rep_id": rep_id, "payout_id": payout_id, "total_cents": total})

        return {"ok": True, "payouts_created": len(payouts), "payouts": payouts}
#  ----- BRidge Sales -----


# ------ App --------
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

# -------- Health -----------
@app.get("/health", tags=["System"], summary="Healthcheck")
def health():
    return {"ok": True, "env": ENV, "ts": datetime.utcnow().isoformat()}

# -------- Auth --------------
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
# ------ Auth --------------

# ------- Server-side role-gated UI routes (belt & suspenders) -------
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
# --------- Server-side role-gated UI routes (belt & suspenders) ---------

# --- Sales UI pages ---
@app.get("/apply/sales", tags=["UI"], summary="Public sales rep application page")
def ui_sales_apply():
    return _serve_html("sales-apply.html")

@app.get("/dashboard/sales", tags=["UI"], summary="Sales rep portal (role-gated)")
def ui_sales_portal(request: Request):
    role = request.session.get("role")
    if role not in ("sales_rep", "admin"):
        return RedirectResponse("/static/login.html", status_code=302)
    return _serve_html("sales-portal.html")

class SalesApplyIn(BaseModel):
    legal_name: str = Field(min_length=1)
    email: str = Field(min_length=3)
    phone: Optional[str] = None

@app.post("/sales/apply", tags=["Sales"], summary="Sales rep applies (public)")
def sales_apply(payload: SalesApplyIn):
    with db() as conn:
        ensure_sales_tables(conn)

        # normalize
        email = payload.email.lower().strip()

        # already exists?
        existing = conn.execute("SELECT id, referral_code, status FROM sales_reps WHERE email=%s", (email,)).fetchone()
        if existing:
            return {"ok": True, "already_exists": True, "status": existing["status"], "referral_code": existing["referral_code"]}

        rep_id = str(uuid.uuid4())
        code = _new_ref_code()

        row = conn.execute("""
            INSERT INTO sales_reps (id, status, legal_name, email, phone, referral_code)
            VALUES (%s,'candidate',%s,%s,%s,%s)
            RETURNING id, status, legal_name, email, phone, referral_code, created_at
        """, (rep_id, payload.legal_name, email, payload.phone, code)).fetchone()

        # optional: log it into hr_records for audit trail
        conn.execute(
            "INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,%s,%s)",
            (None, "sales_rep_applied", json.dumps({"rep_id": rep_id, "email": email}))
        )

    return {"ok": True, "rep": row}

class SalesApproveIn(BaseModel):
    temp_password: str = Field(min_length=8)

def _bcrypt_hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

@app.post("/admin/sales/reps/{rep_id}/approve", tags=["Admin","Sales"], summary="Approve rep + create login user")
def approve_sales_rep(rep_id: str, payload: SalesApproveIn, request: Request):
    require_admin(request)
    with db() as conn:
        ensure_sales_tables(conn)

        rep = conn.execute("SELECT id, email, status FROM sales_reps WHERE id=%s", (rep_id,)).fetchone()
        if not rep:
            raise HTTPException(404, "rep not found")

        # ensure role exists
        role = conn.execute("SELECT id FROM roles WHERE name='sales_rep'").fetchone()
        if not role:
            role_id = str(uuid.uuid4())
            conn.execute("INSERT INTO roles (id, name) VALUES (%s,'sales_rep')", (role_id,))
        else:
            role_id = role["id"]

        # create hr_user login (or update if exists)
        pw_hash = _bcrypt_hash(payload.temp_password)

        existing_user = conn.execute("SELECT id FROM hr_users WHERE email=%s", (rep["email"],)).fetchone()
        if existing_user:
            conn.execute("""
                UPDATE hr_users SET password_hash=%s, role_id=%s, is_active=TRUE
                WHERE email=%s
            """, (pw_hash, role_id, rep["email"]))
        else:
            conn.execute("""
                INSERT INTO hr_users (id, email, password_hash, role_id, is_active)
                VALUES (%s,%s,%s,%s,TRUE)
            """, (str(uuid.uuid4()), rep["email"], pw_hash, role_id))

        # activate rep
        conn.execute("UPDATE sales_reps SET status='active', updated_at=NOW() WHERE id=%s", (rep_id,))

    return {"ok": True, "rep_id": rep_id, "status": "active"}

def require_sales_rep(request: Request):
    role = request.session.get("role")
    if role not in ("sales_rep", "admin"):
        raise HTTPException(403, "Sales rep only")
    email = (request.session.get("user") or "").lower().strip()
    if not email:
        raise HTTPException(401, "Not logged in")

    with db() as conn:
        ensure_sales_tables(conn)
        rep = conn.execute("SELECT * FROM sales_reps WHERE email=%s", (email,)).fetchone()
        if not rep:
            raise HTTPException(403, "No sales rep record for this user")
        return rep

LEAD_STAGES = ("new", "contacted", "demo", "sent_invoice", "closed_won", "closed_lost")

class LeadCreateIn(BaseModel):
    company_name: str = Field(min_length=1)
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    website: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    notes: Optional[str] = None

class LeadStagePatch(BaseModel):
    stage: str = Field(pattern="^(new|contacted|demo|sent_invoice|closed_won|closed_lost)$")
    notes: Optional[str] = None

class LeadActivityIn(BaseModel):
    activity_type: str = Field(pattern="^(call|email|demo|note|text|other)$")
    notes: Optional[str] = None


@app.post("/sales/leads", tags=["Sales"], summary="Create a lead (sales rep)")
def create_lead(payload: LeadCreateIn, request: Request):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        lead_id = str(uuid.uuid4())
        row = conn.execute("""
            INSERT INTO sales_leads (
              id, rep_id, company_name, contact_name, contact_email, contact_phone,
              website, city, state, stage, notes, protection_expires_at
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'new',%s,(NOW() + INTERVAL '14 days'))
            RETURNING *
        """, (
            lead_id, rep["id"],
            payload.company_name,
            payload.contact_name,
            payload.contact_email,
            payload.contact_phone,
            payload.website,
            payload.city,
            payload.state,
            payload.notes
        )).fetchone()

        # audit trail (optional but very "Dossier")
        conn.execute(
            "INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,%s,%s)",
            (None, "sales_lead_created", json.dumps({"lead_id": lead_id, "rep_id": str(rep["id"]), "company_name": payload.company_name}))
        )
    return {"ok": True, "lead": row}


@app.get("/sales/leads", tags=["Sales"], summary="List my leads (sales rep)")
def list_my_leads(
    request: Request,
    stage: Optional[str] = Query(None, description="Filter by stage"),
    q: Optional[str] = Query(None, description="Search company/contact/email"),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)

        sql = """
            SELECT *
            FROM sales_leads
            WHERE rep_id=%s
        """
        vals = [rep["id"]]

        if stage:
            sql += " AND stage=%s"
            vals.append(stage)

        if q:
            sql += " AND (company_name ILIKE %s OR COALESCE(contact_name,'') ILIKE %s OR COALESCE(contact_email,'') ILIKE %s)"
            vals.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

        sql += " ORDER BY updated_at DESC, created_at DESC LIMIT %s OFFSET %s"
        vals.extend([limit, offset])

        rows = conn.execute(sql, tuple(vals)).fetchall()

    return {"ok": True, "leads": rows}


@app.patch("/sales/leads/{lead_id}", tags=["Sales"], summary="Update lead stage/notes (sales rep)")
def patch_lead(lead_id: str, patch: LeadStagePatch, request: Request):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)

        lead = conn.execute("SELECT id FROM sales_leads WHERE id=%s AND rep_id=%s", (lead_id, rep["id"])).fetchone()
        if not lead:
            raise HTTPException(404, "Lead not found")

        row = conn.execute("""
            UPDATE sales_leads
            SET stage=%s,
                notes=COALESCE(%s, notes),
                updated_at=NOW()
            WHERE id=%s AND rep_id=%s
            RETURNING *
        """, (patch.stage, patch.notes, lead_id, rep["id"])).fetchone()

        conn.execute(
            "INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,%s,%s)",
            (None, "sales_lead_updated", json.dumps({"lead_id": lead_id, "rep_id": str(rep["id"]), "stage": patch.stage}))
        )

    return {"ok": True, "lead": row}


@app.post("/sales/leads/{lead_id}/activity", tags=["Sales"], summary="Log lead activity (sales rep)")
def add_lead_activity(lead_id: str, payload: LeadActivityIn, request: Request):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)

        lead = conn.execute("SELECT id FROM sales_leads WHERE id=%s AND rep_id=%s", (lead_id, rep["id"])).fetchone()
        if not lead:
            raise HTTPException(404, "Lead not found")

        act_id = str(uuid.uuid4())
        row = conn.execute("""
            INSERT INTO sales_lead_activities (id, lead_id, rep_id, activity_type, notes)
            VALUES (%s,%s,%s,%s,%s)
            RETURNING *
        """, (act_id, lead_id, rep["id"], payload.activity_type, payload.notes)).fetchone()

        # bump lead updated_at
        conn.execute("UPDATE sales_leads SET updated_at=NOW() WHERE id=%s", (lead_id,))

    return {"ok": True, "activity": row}


@app.get("/sales/leads/{lead_id}/activity", tags=["Sales"], summary="List lead activity (sales rep)")
def list_lead_activity(lead_id: str, request: Request, limit: int = Query(200, ge=1, le=2000)):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)

        lead = conn.execute("SELECT id FROM sales_leads WHERE id=%s AND rep_id=%s", (lead_id, rep["id"])).fetchone()
        if not lead:
            raise HTTPException(404, "Lead not found")

        rows = conn.execute("""
            SELECT *
            FROM sales_lead_activities
            WHERE lead_id=%s AND rep_id=%s
            ORDER BY created_at DESC
            LIMIT %s
        """, (lead_id, rep["id"], limit)).fetchall()

    return {"ok": True, "activities": rows}

@app.get("/sales/me", tags=["Sales"], summary="Current sales rep profile")
def sales_me(request: Request):
    rep = require_sales_rep(request)
    return {"ok": True, "rep": rep}

@app.get("/sales/accounts", tags=["Sales"], summary="Accounts owned by current rep")
def sales_accounts(request: Request, limit: int = Query(200, ge=1, le=2000)):
    rep = require_sales_rep(request)
    with db() as conn:
        rows = conn.execute("""
            SELECT a.bridge_account_id, a.company_name, a.plan_tier, a.status, a.first_paid_at,
                   o.ownership_start, o.ownership_reason
            FROM account_ownership o
            JOIN sales_accounts a ON a.bridge_account_id = o.bridge_account_id
            WHERE o.sales_owner_rep_id=%s AND o.ownership_end IS NULL AND o.house_account=FALSE
            ORDER BY COALESCE(a.first_paid_at, o.ownership_start) DESC
            LIMIT %s
        """, (rep["id"], limit)).fetchall()
    return {"ok": True, "accounts": rows}

@app.get("/sales/ledger", tags=["Sales"], summary="Commission ledger for current rep")
def sales_ledger(request: Request, limit: int = Query(500, ge=1, le=5000)):
    rep = require_sales_rep(request)
    with db() as conn:
        rows = conn.execute("""
            SELECT bridge_account_id, line_type, amount_cents, vesting_status, scheduled_earn_date, created_at
            FROM commission_ledger
            WHERE rep_id=%s
            ORDER BY created_at DESC
            LIMIT %s
        """, (rep["id"], limit)).fetchall()
    return {"ok": True, "ledger": rows}
# --- Sales UI pages ---

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

class AtlasEvent(BaseModel):
    source_system: str   # e.g. "bridge"
    source_table: str    # e.g. "contracts", "bols"
    source_id: str       # UUID or PK from the source system
    event_type: str      # e.g. "CONTRACT_CREATED", "BOL_DELIVERED"
    payload: dict = {}   # free-form JSON from BRidge

@app.post("/atlas/ingest", tags=["Sync"], summary="Ingest single event from BRidge/Atlas queue")
async def atlas_ingest(
    request: Request,
    x_atlas_timestamp: Optional[str] = Header(None, alias="X-Atlas-Timestamp"),
    x_atlas_signature: Optional[str] = Header(None, alias="X-Atlas-Signature"),
):
    # 1) Get raw body and verify HMAC exactly like BRidge
    raw = await request.body()
    _verify_atlas_hmac(raw, x_atlas_timestamp, x_atlas_signature)

    # 2) Parse payload into a typed event
    try:
        data = json.loads(raw.decode() or "{}")
        ev = AtlasEvent(**data)
    except Exception:
        raise HTTPException(400, "Invalid Atlas payload")

    # 3) Store a durable log row + mirror into hr_records
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS atlas_ingest_log (
              id UUID PRIMARY KEY,
              source_system TEXT NOT NULL,
              source_table  TEXT NOT NULL,
              source_id     TEXT NOT NULL,
              event_type    TEXT NOT NULL,
              payload       JSONB,
              created_at    TIMESTAMP NOT NULL DEFAULT NOW()
            )
        """)

        conn.execute(
            """
            INSERT INTO atlas_ingest_log (
              id, source_system, source_table, source_id, event_type, payload
            ) VALUES (%s,%s,%s,%s,%s,%s)
            """,
            (
                str(uuid.uuid4()),
                ev.source_system,
                ev.source_table,
                ev.source_id,
                ev.event_type,
                json.dumps(ev.payload),
            ),
        )

        # For now, attach to a "global" profile (or None) and keep full context in payload.
        # Later you can resolve buyer/seller → profile_id if you want.
        conn.execute(
            """
            INSERT INTO hr_records (profile_id, event_type, payload)
            VALUES (%s,%s,%s)
            """,
            (
                None,
                f"{ev.source_system}:{ev.event_type}",
                json.dumps(
                    {
                        "source_table": ev.source_table,
                        "source_id": ev.source_id,
                        **(ev.payload or {}),
                    }
                ),
            ),
        )

    return {"ok": True}

# --------------------------
# BRidge ingest preview (read)
# --------------------------
@app.get("/ingest/recent_bridge", tags=["Sync"], summary="Recent BRidge events (atlas + hr mirror)")
def recent_bridge(limit: int = Query(25, ge=1, le=200)):
    with db() as conn:
        # atlas_ingest_log (authoritative when using /atlas/ingest)
        atlas = conn.execute("""
            SELECT created_at,
                   source_system || ':' || event_type AS event_type,
                   payload
            FROM atlas_ingest_log
            WHERE lower(source_system) = 'bridge'
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,)).fetchall()

        # hr_records (used by /sync/bridge)
        hr = conn.execute("""
            SELECT created_at,
                   event_type,
                   payload
            FROM hr_records
            WHERE lower(event_type) LIKE 'bridge%%'
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,)).fetchall()

    # merge, sort by created_at desc, then cap to limit
    rows = [
        {"created_at": r["created_at"], "event_type": r["event_type"], "payload": r["payload"], "src": "atlas"}
        for r in atlas
    ] + [
        {"created_at": r["created_at"], "event_type": r["event_type"], "payload": r["payload"], "src": "hr"}
        for r in hr
    ]
    rows.sort(key=lambda x: x["created_at"], reverse=True)
    return rows[:limit]

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
