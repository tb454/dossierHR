# dossier_hr_backend.py
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
from scraper_core import PoliteSyncCrawler
from scraper_router import router as scraper_router
from leads_ingest_router import router as leads_ingest_router
from sales_leads_router import router as sales_leads_router
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
app.include_router(sales_leads_router)
app.include_router(leads_ingest_router)

@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
def root():
    return RedirectResponse("/static/login.html", status_code=302)

# ----- BRidge Sales  -----
def ensure_sales_tables(conn):
    conn.execute("""
    -- reps
    CREATE TABLE IF NOT EXISTS sales_reps (
      id UUID PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'candidate', -- candidate/active/suspended/terminated
      legal_name TEXT,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      role TEXT NOT NULL DEFAULT 'sales_rep', -- admin/sales_manager/sales_rep/sdr
      territory TEXT NULL,
      vertical TEXT NULL, -- yard/mill/manufacturer/broker/other
      referral_code TEXT UNIQUE NOT NULL,
      agreement_signed_at TIMESTAMP NULL,
      w9_received_at TIMESTAMP NULL,
      payout_method TEXT NULL, -- manual/ach/stripe_connect
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    -- invites (optional; you wanted the page)
    CREATE TABLE IF NOT EXISTS sales_invites (
      id UUID PRIMARY KEY,
      email TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'sales_rep',
      invited_by_email TEXT NULL,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      accepted_at TIMESTAMP NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      UNIQUE(email, token_hash)
    );

    -- plan acceptance (versioned)
    CREATE TABLE IF NOT EXISTS commission_plans (
      id UUID PRIMARY KEY,
      version TEXT NOT NULL UNIQUE,   -- "v1.0"
      rules JSONB NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sales_rep_plan_acceptance (
      id UUID PRIMARY KEY,
      rep_id UUID NULL, -- NULL = house queue (unclaimed)
      plan_version TEXT NOT NULL,
      accepted_at TIMESTAMP NOT NULL DEFAULT NOW(),
      ip TEXT NULL,
      user_agent TEXT NULL
    );

    -- companies/accounts
    CREATE TABLE IF NOT EXISTS sales_companies (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL,
        domain TEXT NULL,
        website TEXT NULL,
        city TEXT NULL,
        state TEXT NULL,
        country TEXT NULL DEFAULT 'US',
        company_type TEXT NOT NULL DEFAULT 'yard',
        notes TEXT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        );

        CREATE UNIQUE INDEX IF NOT EXISTS ux_sales_companies_name_domain
        ON sales_companies (lower(name), coalesce(domain,''));

        CREATE INDEX IF NOT EXISTS idx_sales_companies_domain ON sales_companies(domain);
        CREATE INDEX IF NOT EXISTS idx_sales_companies_type ON sales_companies(company_type);

    -- contacts
    CREATE TABLE IF NOT EXISTS sales_contacts (
      id UUID PRIMARY KEY,
      company_id UUID NOT NULL,
      name TEXT NOT NULL,
      title TEXT NULL,
      email TEXT NULL,
      phone TEXT NULL,
      is_primary BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_sales_contacts_company ON sales_contacts(company_id);
    CREATE INDEX IF NOT EXISTS idx_sales_contacts_email ON sales_contacts(email);

    -- company ownership + house flag + audit
    CREATE TABLE IF NOT EXISTS sales_company_ownership (
      id UUID PRIMARY KEY,
      company_id UUID NOT NULL,
      owner_rep_id UUID NULL,
      assisting_rep_id UUID NULL,
      house_account BOOLEAN NOT NULL DEFAULT FALSE,
      protection_expires_at TIMESTAMP NULL,
      ownership_start TIMESTAMP NOT NULL DEFAULT NOW(),
      ownership_end TIMESTAMP NULL,
      ownership_reason TEXT NOT NULL DEFAULT 'unknown',
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_company_owner_company ON sales_company_ownership(company_id);
    CREATE INDEX IF NOT EXISTS idx_company_owner_owner ON sales_company_ownership(owner_rep_id);

    CREATE TABLE IF NOT EXISTS sales_ownership_audit (
      id UUID PRIMARY KEY,
      entity_type TEXT NOT NULL, -- company/deal/lead
      entity_id TEXT NOT NULL,
      action TEXT NOT NULL, -- assign/unassign/house/transfer
      from_rep_id UUID NULL,
      to_rep_id UUID NULL,
      reason TEXT NULL,
      actor_email TEXT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    -- leads
    CREATE TABLE IF NOT EXISTS sales_leads (
      id UUID PRIMARY KEY,
      rep_id UUID NOT NULL,
      company_id UUID NULL,
      company_name TEXT NOT NULL,
      domain TEXT NULL,
      website TEXT NULL,
      city TEXT NULL,
      state TEXT NULL,
      company_type TEXT NULL,   -- yard/mill/manufacturer/broker/other
      lead_source TEXT NULL,    -- cold_outbound/inbound/referral/conference/etc
      contact_name TEXT NULL,
      contact_title TEXT NULL,
      contact_email TEXT NULL,
      contact_phone TEXT NULL,
      stage TEXT NOT NULL DEFAULT 'new', -- new/contacted/qualified/demo_scheduled/demo_done/proposal/negotiation/closed_won/closed_lost
      notes TEXT NULL,
      duplicate_of UUID NULL,
      linked_company_id UUID NULL,
      linked_deal_id UUID NULL,
      last_activity_at TIMESTAMP NULL,
      next_follow_up_at TIMESTAMP NULL,
      protection_expires_at TIMESTAMP NOT NULL DEFAULT (NOW() + INTERVAL '14 days'),
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_sales_leads_rep ON sales_leads(rep_id);
    CREATE INDEX IF NOT EXISTS idx_sales_leads_stage ON sales_leads(stage);
    CREATE INDEX IF NOT EXISTS idx_sales_leads_domain ON sales_leads(domain);
    CREATE INDEX IF NOT EXISTS idx_sales_leads_company_id ON sales_leads(company_id);
    CREATE INDEX IF NOT EXISTS idx_sales_leads_followup ON sales_leads(next_follow_up_at);

    -- ---- house-queue + claim migration (safe to run repeatedly) ----
    ALTER TABLE sales_leads
      ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMP NULL;

    ALTER TABLE sales_leads
      ADD COLUMN IF NOT EXISTS claimed_by_email TEXT NULL;

    -- If this DB was created earlier with rep_id NOT NULL, drop the constraint safely.
    DO $$
    BEGIN
      BEGIN
        ALTER TABLE sales_leads ALTER COLUMN rep_id DROP NOT NULL;
      EXCEPTION WHEN others THEN
        -- already nullable or not present; ignore
      END;
    END $$;

    -- Optional: partial index for house queue scans
    CREATE INDEX IF NOT EXISTS idx_sales_leads_house_queue ON sales_leads(created_at DESC) WHERE rep_id IS NULL;

    -- activities (calls/emails/notes) with optional follow-up
    CREATE TABLE IF NOT EXISTS sales_activities (
      id UUID PRIMARY KEY,
      rep_id UUID NOT NULL,
      lead_id UUID NULL,
      company_id UUID NULL,
      deal_id UUID NULL,
      activity_type TEXT NOT NULL, -- call/email/demo/note/text/other
      notes TEXT NULL,
      follow_up_at TIMESTAMP NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_sales_activities_rep ON sales_activities(rep_id);
    CREATE INDEX IF NOT EXISTS idx_sales_activities_lead ON sales_activities(lead_id);
    CREATE INDEX IF NOT EXISTS idx_sales_activities_deal ON sales_activities(deal_id);

    -- tasks / reminders
    CREATE TABLE IF NOT EXISTS sales_tasks (
      id UUID PRIMARY KEY,
      rep_id UUID NOT NULL,
      lead_id UUID NULL,
      company_id UUID NULL,
      deal_id UUID NULL,
      title TEXT NOT NULL,
      due_at TIMESTAMP NOT NULL,
      status TEXT NOT NULL DEFAULT 'open', -- open/done/snoozed
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      completed_at TIMESTAMP NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sales_tasks_rep_due ON sales_tasks(rep_id, due_at);
    CREATE INDEX IF NOT EXISTS idx_sales_tasks_status ON sales_tasks(status);

    -- deals (pipeline)
    CREATE TABLE IF NOT EXISTS sales_deals (
      id UUID PRIMARY KEY,
      company_id UUID NOT NULL,
      owner_rep_id UUID NOT NULL,
      assisting_rep_id UUID NULL,
      proposed_plan TEXT NULL, -- starter/standard/enterprise
      expected_go_live DATE NULL,
      expected_mrr_cents BIGINT NULL,
      expected_tons_per_month BIGINT NULL,
      expected_bols_per_month BIGINT NULL,
      probability INT NOT NULL DEFAULT 20,
      stage TEXT NOT NULL DEFAULT 'new', -- new/contacted/qualified/demo_scheduled/demo_done/proposal/negotiation/closed_won/closed_lost
      stage_entered_at TIMESTAMP NOT NULL DEFAULT NOW(),
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
      closed_at TIMESTAMP NULL,
      notes TEXT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sales_deals_owner ON sales_deals(owner_rep_id);
    CREATE INDEX IF NOT EXISTS idx_sales_deals_stage ON sales_deals(stage);
    CREATE INDEX IF NOT EXISTS idx_sales_deals_company ON sales_deals(company_id);

    -- onboarding checklist per company
    CREATE TABLE IF NOT EXISTS onboarding_checklists (
      id UUID PRIMARY KEY,
      company_id UUID NOT NULL,
      deal_id UUID NULL,
      status TEXT NOT NULL DEFAULT 'yellow', -- green/yellow/red
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
      notes TEXT NULL
    );

    CREATE TABLE IF NOT EXISTS onboarding_steps (
      id UUID PRIMARY KEY,
      checklist_id UUID NOT NULL,
      step_key TEXT NOT NULL,
      label TEXT NOT NULL,
      is_required BOOLEAN NOT NULL DEFAULT TRUE,
      status TEXT NOT NULL DEFAULT 'todo', -- todo/doing/done/blocked
      updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
      blocker_notes TEXT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_onboarding_company ON onboarding_checklists(company_id);
    CREATE INDEX IF NOT EXISTS idx_onboarding_steps_checklist ON onboarding_steps(checklist_id);

    -- attachments (NDA/proposal/screenshots) - store URL/path reference only
    CREATE TABLE IF NOT EXISTS sales_attachments (
      id UUID PRIMARY KEY,
      rep_id UUID NOT NULL,
      lead_id UUID NULL,
      company_id UUID NULL,
      deal_id UUID NULL,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    -- assets / templates
    CREATE TABLE IF NOT EXISTS sales_assets (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      asset_type TEXT NOT NULL, -- pitch_deck/one_pager/fee_schedule/template/script/objections
      url TEXT NULL,
      notes TEXT NULL,
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    -- revenue events (manual now)
    CREATE TABLE IF NOT EXISTS revenue_events (
      id UUID PRIMARY KEY,
      company_id UUID NOT NULL,
      revenue_type TEXT NOT NULL, -- subscription/overage/addon/one_time
      amount_cents BIGINT NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD',
      collected_at TIMESTAMP NOT NULL,
      external_ref TEXT NULL,
      created_by_email TEXT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_revenue_company_collected ON revenue_events(company_id, collected_at);

    -- commission ledger (engine shaped)
    CREATE TABLE IF NOT EXISTS commission_ledger (
      id UUID PRIMARY KEY,
      rep_id UUID NOT NULL,
      company_id UUID NOT NULL,
      revenue_event_id UUID NULL,
      deal_id UUID NULL,
      line_type TEXT NOT NULL, -- activation_bonus/residual_mrr/overage_residual/adjustment
      amount_cents BIGINT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending', -- pending/earned/payable/paid/disputed
      net30_release_at TIMESTAMP NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      notes TEXT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_comm_ledger_rep ON commission_ledger(rep_id);
    CREATE INDEX IF NOT EXISTS idx_comm_ledger_status ON commission_ledger(status);

    CREATE TABLE IF NOT EXISTS commission_disputes (
      id UUID PRIMARY KEY,
      rep_id UUID NOT NULL,
      ledger_id UUID NOT NULL,
      reason TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open', -- open/resolved/rejected
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      resolved_at TIMESTAMP NULL,
      resolution_notes TEXT NULL
    );

    """)

# --------------------------
# Sales constants (your plan v1.0)
# --------------------------
COMMISSION_PLAN_VERSION = "v1.0"

PLAN_RULES_V1 = {
    "activation_bonus": {"starter": 25000, "standard": 75000, "enterprise": 250000},
    "activation_vesting": [
        {"pct": 0.50, "months": 1},
        {"pct": 0.25, "months": 3},
        {"pct": 0.25, "months": 6},
    ],
    "mrr": {"y1_pct": 0.15, "y2_pct": 0.05, "months_y1": 12, "months_y2": 24},
    "overage_pct": 0.02,
    "net30_days": 30,
}

DEAL_STAGES = ["new","contacted","qualified","demo_scheduled","demo_done","proposal","negotiation","closed_won","closed_lost"]
COMPANY_TYPES = ["yard","mill","manufacturer","broker","other"]
REVENUE_TYPES = ["subscription","overage","addon","one_time"]

# --------------------------
# Helpers
# --------------------------
def _new_ref_code() -> str:
    return uuid.uuid4().hex[:6].upper()

def _bcrypt_hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def _extract_domain(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    s = (s or "").strip().lower()
    if "@" in s and "://" not in s:
        return s.split("@")[-1].strip().strip(".")
    try:
        u = s if "://" in s else "https://" + s
        host = (urlparse(u).netloc or "").lower().split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        return host or None
    except Exception:
        return None

def _ensure_plan_row(conn):
    row = conn.execute("SELECT 1 FROM commission_plans WHERE version=%s", (COMMISSION_PLAN_VERSION,)).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO commission_plans (id, version, rules) VALUES (%s,%s,%s)",
            (str(uuid.uuid4()), COMMISSION_PLAN_VERSION, json.dumps(PLAN_RULES_V1))
        )

def _actor_email(request: Request) -> Optional[str]:
    return (request.session.get("user") or "").lower().strip() or None

def require_sales_role(request: Request, allowed: List[str]):
    role = request.session.get("role")
    if role not in allowed:
        raise HTTPException(403, "Not authorized")
    return True

def require_sales_rep(request: Request):
    role = request.session.get("role")
    if role not in ("sales_rep", "sales_manager", "admin"):
        raise HTTPException(403, "Sales only")

    email = (request.session.get("user") or "").lower().strip()
    if not email:
        raise HTTPException(401, "Not logged in")

    rep_id = request.session.get("sales_rep_id")

    with db() as conn:
        ensure_sales_tables(conn)

        # If mapped, use the FK link (correct path)
        if rep_id:
            rep = conn.execute("SELECT * FROM sales_reps WHERE id=%s", (rep_id,)).fetchone()
            if rep:
                return rep

        # Fallback: legacy behavior by email (keeps you unblocked)
        rep = conn.execute("SELECT * FROM sales_reps WHERE email=%s", (email,)).fetchone()
        if not rep:
            raise HTTPException(403, "No sales rep record (hr_users.sales_rep_id not mapped)")
        return rep

def require_sales_manager(request: Request):
    require_sales_role(request, ["sales_manager","admin"])
    return True
# --------------------------

# ------ UI routes (serve static pages, CSP-safe) -----
def _serve_sales_html(filename: str) -> HTMLResponse:
    p = STATIC_DIR / filename
    if not p.exists():
        raise HTTPException(404, "Page not found")
    return HTMLResponse(p.read_text(encoding="utf-8"))

@app.get("/apply/sales", tags=["UI"], summary="Public sales rep application page")
def ui_sales_apply():
    return _serve_sales_html("sales-apply.html")

@app.get("/apply/sales/invite", tags=["UI"], summary="Invite accept page (token)")
def ui_sales_invite_accept():
    return _serve_sales_html("sales-invite-accept.html")

@app.get("/dashboard/sales", tags=["UI"], summary="Sales portal")
def ui_sales_portal(request: Request):
    role = request.session.get("role")
    if role not in ("sales_rep","sales_manager","admin"):
        return RedirectResponse("/static/login.html", status_code=302)
    
    return _serve_sales_html("sales-portal.html")
@app.get("/dashboard/sales-manager", tags=["UI"], summary="Sales manager dashboard (role-gated)")
def ui_sales_manager_dash(request: Request):
    role = request.session.get("role")
    if role not in ("sales_manager", "admin"):
        return RedirectResponse("/static/login.html", status_code=302)
    return _serve_sales_html("sales-manager.html")

@app.get("/sales/leads/ui", tags=["UI"], summary="Leads UI")
def ui_sales_leads(request: Request):
    role = request.session.get("role")
    if role not in ("sales_rep","sales_manager","admin"):
        return RedirectResponse("/static/login.html", status_code=302)
    return _serve_sales_html("sales-leads.html")

@app.get("/sales/deals/ui", tags=["UI"], summary="Deals UI")
def ui_sales_deals(request: Request):
    role = request.session.get("role")
    if role not in ("sales_rep","sales_manager","admin"):
        return RedirectResponse("/static/login.html", status_code=302)
    return _serve_sales_html("sales-deals.html")

@app.get("/sales/onboarding/ui", tags=["UI"], summary="Onboarding UI")
def ui_sales_onboarding(request: Request):
    role = request.session.get("role")
    if role not in ("sales_rep","sales_manager","admin"):
        return RedirectResponse("/static/login.html", status_code=302)
    return _serve_sales_html("sales-onboarding.html")

@app.get("/sales/assets/ui", tags=["UI"], summary="Assets UI")
def ui_sales_assets(request: Request):
    role = request.session.get("role")
    if role not in ("sales_rep","sales_manager","admin"):
        return RedirectResponse("/static/login.html", status_code=302)
    return _serve_sales_html("sales-assets.html")

@app.get("/sales/admin/ui", tags=["UI"], summary="Sales admin UI")
def ui_sales_admin(request: Request):
    role = request.session.get("role")
    if role not in ("admin","sales_manager"):
        return RedirectResponse("/static/login.html", status_code=302)
    return _serve_sales_html("sales-admin.html")

@app.get("/sales/manager/ui", tags=["UI"], summary="Sales manager UI")
def ui_sales_manager_ui(request: Request):
    role = request.session.get("role")
    if role not in ("sales_manager","admin"):
        return RedirectResponse("/static/login.html", status_code=302)
    return _serve_sales_html("sales-manager.html")

# --------------------------
# Rep onboarding: open apply + admin approve + invite accept
# --------------------------
class SalesApplyIn(BaseModel):
    legal_name: str = Field(min_length=1)
    email: str = Field(min_length=3)
    phone: Optional[str] = None
    territory: Optional[str] = None
    vertical: Optional[str] = None  # yard/mill/manufacturer/broker/other

@app.post("/sales/apply", tags=["Sales"], summary="Sales rep applies (public)")
def sales_apply(payload: SalesApplyIn, request: Request):
    with db() as conn:
        ensure_sales_tables(conn)
        _ensure_plan_row(conn)

        email = payload.email.lower().strip()
        existing = conn.execute("SELECT id, referral_code, status FROM sales_reps WHERE email=%s", (email,)).fetchone()
        if existing:
            return {"ok": True, "already_exists": True, "status": existing["status"], "referral_code": existing["referral_code"]}

        rep_id = str(uuid.uuid4())
        code = _new_ref_code()
        role = "sales_rep"

        row = conn.execute("""
            INSERT INTO sales_reps (id, status, legal_name, email, phone, role, territory, vertical, referral_code)
            VALUES (%s,'candidate',%s,%s,%s,%s,%s,%s,%s)
            RETURNING id, status, legal_name, email, phone, role, territory, vertical, referral_code, created_at
        """, (rep_id, payload.legal_name, email, payload.phone, role, payload.territory, payload.vertical, code)).fetchone()

        conn.execute(
            "INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,%s,%s)",
            (None, "sales_rep_applied", json.dumps({"rep_id": rep_id, "email": email}))
        )

    return {"ok": True, "rep": row}

class SalesApproveIn(BaseModel):
    rep_role: str = Field(pattern="^(sales_rep|sales_manager|admin|sdr)$")
    temp_password: str = Field(min_length=8)

@app.post("/admin/sales/reps/{rep_id}/approve", tags=["Admin","Sales"], summary="Approve rep + create login user")
def approve_sales_rep(rep_id: str, payload: SalesApproveIn, request: Request):
    require_admin(request)
    actor = _actor_email(request)
    with db() as conn:
        ensure_sales_tables(conn)
        _ensure_plan_row(conn)

        rep = conn.execute("SELECT id, email, status FROM sales_reps WHERE id=%s", (rep_id,)).fetchone()
        if not rep:
            raise HTTPException(404, "rep not found")

        # ensure role exists in your existing hr roles table
        role_row = conn.execute("SELECT id FROM roles WHERE name=%s", (payload.rep_role,)).fetchone()
        if not role_row:
            role_id = str(uuid.uuid4())
            conn.execute("INSERT INTO roles (id, name) VALUES (%s,%s)", (role_id, payload.rep_role))
        else:
            role_id = role_row["id"]

        pw_hash = _bcrypt_hash(payload.temp_password)

        # create/update hr user login
        existing_user = conn.execute("SELECT id FROM hr_users WHERE email=%s", (rep["email"],)).fetchone()
        if existing_user:
            conn.execute(
                "UPDATE hr_users SET password_hash=%s, role_id=%s, is_active=TRUE, sales_rep_id=%s WHERE email=%s",
                (pw_hash, role_id, rep_id, rep["email"])
            )
        else:
            conn.execute("INSERT INTO hr_users (id, email, password_hash, role_id, is_active, sales_rep_id) VALUES (%s,%s,%s,%s,TRUE,%s)",
                         (str(uuid.uuid4()), rep["email"], pw_hash, role_id, rep_id))

        conn.execute("UPDATE sales_reps SET status='active', role=%s, updated_at=NOW() WHERE id=%s",
                     (payload.rep_role, rep_id))

        conn.execute("INSERT INTO sales_rep_plan_acceptance (id, rep_id, plan_version, ip, user_agent) VALUES (%s,%s,%s,%s,%s)",
                     (str(uuid.uuid4()), rep_id, COMMISSION_PLAN_VERSION, request.client.host if request.client else None, request.headers.get("user-agent")))

        conn.execute("INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,%s,%s)",
                     (None, "sales_rep_approved", json.dumps({"rep_id": rep_id, "actor": actor, "role": payload.rep_role})))

    return {"ok": True, "rep_id": rep_id, "status": "active"}

class InviteCreateIn(BaseModel):
    email: str
    role: str = Field(pattern="^(sales_rep|sales_manager|admin|sdr)$")
    expires_hours: int = Field(default=72, ge=1, le=168)

def _hash_invite_token(token: str) -> str:
    # stable hash, no raw token stored
    return hashlib.sha256((token + "|" + SESSION_SECRET).encode("utf-8")).hexdigest()

@app.post("/admin/sales/invite", tags=["Admin","Sales"], summary="Create invite link (admin)")
def create_sales_invite(payload: InviteCreateIn, request: Request):
    require_admin(request)
    actor = _actor_email(request)
    with db() as conn:
        ensure_sales_tables(conn)

        token = uuid.uuid4().hex
        token_hash = _hash_invite_token(token)
        inv_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=int(payload.expires_hours))

        conn.execute("""
            INSERT INTO sales_invites (id, email, role, invited_by_email, token_hash, expires_at)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (inv_id, payload.email.lower().strip(), payload.role, actor, token_hash, expires_at))

    # you can email this yourself for now
    invite_url = f"/static/sales-invite-accept.html?token={token}"
    return {"ok": True, "invite_url": invite_url, "expires_at": expires_at.isoformat()}

class InviteAcceptIn(BaseModel):
    token: str
    legal_name: str = Field(min_length=1)
    phone: Optional[str] = None
    territory: Optional[str] = None
    vertical: Optional[str] = None
    password: str = Field(min_length=8)

@app.post("/sales/invite/accept", tags=["Sales"], summary="Accept invite, create login + rep")
def accept_sales_invite(payload: InviteAcceptIn, request: Request):
    with db() as conn:
        ensure_sales_tables(conn)
        _ensure_plan_row(conn)

        token_hash = _hash_invite_token(payload.token)
        inv = conn.execute("""
            SELECT * FROM sales_invites
            WHERE token_hash=%s AND accepted_at IS NULL AND expires_at > NOW()
            LIMIT 1
        """, (token_hash,)).fetchone()
        if not inv:
            raise HTTPException(400, "Invalid or expired invite")

        email = inv["email"]
        role = inv["role"]

        # ensure role exists
        role_row = conn.execute("SELECT id FROM roles WHERE name=%s", (role,)).fetchone()
        if not role_row:
            role_id = str(uuid.uuid4())
            conn.execute("INSERT INTO roles (id, name) VALUES (%s,%s)", (role_id, role))
        else:
            role_id = role_row["id"]

        # create rep record if missing
        rep = conn.execute("SELECT id FROM sales_reps WHERE email=%s", (email,)).fetchone()
        if not rep:
            rep_id = str(uuid.uuid4())
            code = _new_ref_code()
            conn.execute("""
                INSERT INTO sales_reps (id, status, legal_name, email, phone, role, territory, vertical, referral_code)
                VALUES (%s,'active',%s,%s,%s,%s,%s,%s,%s)
            """, (rep_id, payload.legal_name, email, payload.phone, role, payload.territory, payload.vertical, code))
        else:
            rep_id = rep["id"]
            conn.execute("""
                UPDATE sales_reps SET status='active', legal_name=COALESCE(%s, legal_name),
                    phone=COALESCE(%s, phone), role=%s, territory=COALESCE(%s, territory),
                    vertical=COALESCE(%s, vertical), updated_at=NOW()
                WHERE id=%s
            """, (payload.legal_name, payload.phone, role, payload.territory, payload.vertical, rep_id))

        # create/update hr user
        pw_hash = _bcrypt_hash(payload.password)
        existing_user = conn.execute("SELECT id FROM hr_users WHERE email=%s", (email,)).fetchone()
        if existing_user:
            conn.execute("UPDATE hr_users SET password_hash=%s, role_id=%s, is_active=TRUE, sales_rep_id=%s WHERE email=%s",
                         (pw_hash, role_id, rep_id, email))
        else:
            conn.execute("INSERT INTO hr_users (id, email, password_hash, role_id, is_active, sales_rep_id) VALUES (%s,%s,%s,%s,TRUE,%s)",
                         (str(uuid.uuid4()), email, pw_hash, role_id, rep_id))

        conn.execute("UPDATE sales_invites SET accepted_at=NOW() WHERE id=%s", (inv["id"],))

        conn.execute("INSERT INTO sales_rep_plan_acceptance (id, rep_id, plan_version, ip, user_agent) VALUES (%s,%s,%s,%s,%s)",
                     (str(uuid.uuid4()), rep_id, COMMISSION_PLAN_VERSION, request.client.host if request.client else None, request.headers.get("user-agent")))

    return {"ok": True}

@app.get("/admin/sales/reps", tags=["Admin","Sales"], summary="List sales reps")
def list_sales_reps(request: Request, status: Optional[str]=None, limit: int = Query(500, ge=1, le=5000)):
    require_admin(request)
    with db() as conn:
        ensure_sales_tables(conn)
        sql = "SELECT * FROM sales_reps WHERE 1=1"
        vals = []
        if status:
            sql += " AND status=%s"; vals.append(status)
        sql += " ORDER BY created_at DESC LIMIT %s"
        vals.append(limit)
        rows = conn.execute(sql, tuple(vals)).fetchall()
    return {"ok": True, "reps": rows}

# --------------------------
# CRM: companies + contacts (dedupe)
# --------------------------
class CompanyUpsertIn(BaseModel):
    name: str = Field(min_length=1)
    website: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    company_type: str = Field(default="yard")
    notes: Optional[str] = None

@app.post("/sales/companies/upsert", tags=["Sales"], summary="Upsert company (dedupe by name+domain)")
def upsert_company(payload: CompanyUpsertIn, request: Request):
    rep = require_sales_rep(request)
    dom = _extract_domain(payload.website)
    with db() as conn:
        ensure_sales_tables(conn)

        # try existing by domain first
        row = None
        if dom:
            row = conn.execute("SELECT * FROM sales_companies WHERE domain=%s LIMIT 1", (dom,)).fetchone()

        if not row:
            row = conn.execute("SELECT * FROM sales_companies WHERE lower(name)=lower(%s) AND COALESCE(domain,'')=COALESCE(%s,'') LIMIT 1",
                               (payload.name, dom or "")).fetchone()

        if row:
            updated = conn.execute("""
                UPDATE sales_companies
                SET website=COALESCE(%s, website),
                    city=COALESCE(%s, city),
                    state=COALESCE(%s, state),
                    company_type=COALESCE(%s, company_type),
                    notes=COALESCE(%s, notes),
                    updated_at=NOW()
                WHERE id=%s
                RETURNING *
            """, (payload.website, payload.city, payload.state, payload.company_type, payload.notes, row["id"])).fetchone()
            return {"ok": True, "company": updated, "deduped": True}

        cid = str(uuid.uuid4())
        created = conn.execute("""
            INSERT INTO sales_companies (id, name, domain, website, city, state, company_type, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING *
        """, (cid, payload.name, dom, payload.website, payload.city, payload.state, payload.company_type, payload.notes)).fetchone()

        # default ownership = creating rep (14 day protection)
        conn.execute("""
            INSERT INTO sales_company_ownership (id, company_id, owner_rep_id, protection_expires_at, ownership_reason)
            VALUES (%s,%s,%s,%s,%s)
        """, (str(uuid.uuid4()), cid, rep["id"], datetime.utcnow() + timedelta(days=14), "lead_created"))

        conn.execute("""
            INSERT INTO sales_ownership_audit (id, entity_type, entity_id, action, from_rep_id, to_rep_id, reason, actor_email)
            VALUES (%s,'company',%s,'assign',NULL,%s,%s,%s)
        """, (str(uuid.uuid4()), cid, rep["id"], "auto-owner on create", (rep["email"] or "")))

        return {"ok": True, "company": created, "deduped": False}

@app.get("/sales/companies", tags=["Sales"], summary="Search companies")
def list_companies(request: Request, q: Optional[str]=None, limit: int = Query(200, ge=1, le=2000)):
    _ = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        sql = "SELECT * FROM sales_companies WHERE 1=1"
        vals = []
        if q:
            sql += " AND (name ILIKE %s OR COALESCE(domain,'') ILIKE %s)"
            vals.extend([f"%{q}%", f"%{q}%"])
        sql += " ORDER BY updated_at DESC LIMIT %s"
        vals.append(limit)
        rows = conn.execute(sql, tuple(vals)).fetchall()
    return {"ok": True, "companies": rows}

class ContactCreateIn(BaseModel):
    company_id: str
    name: str
    title: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    is_primary: bool = False

@app.post("/sales/contacts", tags=["Sales"], summary="Create contact")
def create_contact(payload: ContactCreateIn, request: Request):
    _ = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        cid = payload.company_id
        row = conn.execute("""
            INSERT INTO sales_contacts (id, company_id, name, title, email, phone, is_primary)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            RETURNING *
        """, (str(uuid.uuid4()), cid, payload.name, payload.title, payload.email, payload.phone, payload.is_primary)).fetchone()
    return {"ok": True, "contact": row}

@app.get("/sales/contacts", tags=["Sales"], summary="List contacts for a company")
def list_contacts(request: Request, company_id: str):
    _ = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        rows = conn.execute("SELECT * FROM sales_contacts WHERE company_id=%s ORDER BY is_primary DESC, created_at DESC", (company_id,)).fetchall()
    return {"ok": True, "contacts": rows}

# --------------------------
# Leads + tasks + activities
# --------------------------
class LeadCreateIn(BaseModel):
    company_name: str = Field(min_length=1)
    website: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    company_type: str = Field(default="yard")
    lead_source: Optional[str] = None
    contact_name: Optional[str] = None
    contact_title: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    notes: Optional[str] = None

@app.post("/sales/leads", tags=["Sales"], summary="Create lead (with duplicate detection)")
def create_lead(payload: LeadCreateIn, request: Request):
    rep = require_sales_rep(request)
    dom = _extract_domain(payload.contact_email) or _extract_domain(payload.website)
    with db() as conn:
        ensure_sales_tables(conn)

        # duplicate detection by domain (same rep scope) – prevent spam duplicates
        if dom:
            dup = conn.execute("""
                SELECT id FROM sales_leads
                WHERE rep_id=%s AND domain=%s AND stage NOT IN ('closed_won','closed_lost')
                ORDER BY created_at DESC LIMIT 1
            """, (rep["id"], dom)).fetchone()
            if dup:
                # still create but mark duplicate_of
                duplicate_of = dup["id"]
            else:
                duplicate_of = None
        else:
            duplicate_of = None

        # upsert company and link
        comp = conn.execute("SELECT * FROM sales_companies WHERE domain=%s LIMIT 1", (dom,)).fetchone() if dom else None
        if not comp:
            comp_id = str(uuid.uuid4())
            comp = conn.execute("""
                INSERT INTO sales_companies (id, name, domain, website, city, state, company_type)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                RETURNING *
            """, (comp_id, payload.company_name, dom, payload.website, payload.city, payload.state, payload.company_type)).fetchone()

            conn.execute("""
                INSERT INTO sales_company_ownership (id, company_id, owner_rep_id, protection_expires_at, ownership_reason)
                VALUES (%s,%s,%s,%s,%s)
            """, (str(uuid.uuid4()), comp_id, rep["id"], datetime.utcnow() + timedelta(days=14), "lead_created"))

        lead_id = str(uuid.uuid4())
        row = conn.execute("""
            INSERT INTO sales_leads (
              id, rep_id, company_id, company_name, domain, website, city, state,
              company_type, lead_source, contact_name, contact_title, contact_email, contact_phone,
              stage, notes, duplicate_of, linked_company_id
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'new',%s,%s,%s)
            RETURNING *
        """, (
            lead_id, rep["id"], comp["id"], payload.company_name, dom, payload.website, payload.city, payload.state,
            payload.company_type, payload.lead_source, payload.contact_name, payload.contact_title, payload.contact_email, payload.contact_phone,
            payload.notes, duplicate_of, comp["id"]
        )).fetchone()

        conn.execute("INSERT INTO hr_records (profile_id, event_type, payload) VALUES (%s,'sales_lead_created',%s)",
                     (None, json.dumps({"lead_id": lead_id, "rep_id": str(rep["id"]), "company": payload.company_name})))

    return {"ok": True, "lead": row, "duplicate_of": duplicate_of}
# --------------------------

# ------- House Queue (unassigned leads) + Claim -------
class HouseLeadIn(BaseModel):
    company_name: str = Field(min_length=1)
    website: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    company_type: str = Field(default="yard")
    lead_source: Optional[str] = "house_queue"
    contact_name: Optional[str] = None
    contact_title: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    notes: Optional[str] = None

@app.post("/admin/sales/leads/house_import", tags=["Admin","Sales"], summary="Import leads into House Queue (unassigned)")
def house_import(leads: List[HouseLeadIn], request: Request):
    require_admin(request)
    added = 0
    with db() as conn:
        ensure_sales_tables(conn)

        for payload in leads:
            dom = _extract_domain(payload.contact_email) or _extract_domain(payload.website)

            # Upsert company (by domain preferred)
            comp = conn.execute("SELECT * FROM sales_companies WHERE domain=%s LIMIT 1", (dom,)).fetchone() if dom else None
            if not comp:
                # try by name+domain
                comp = conn.execute(
                    "SELECT * FROM sales_companies WHERE lower(name)=lower(%s) AND COALESCE(domain,'')=COALESCE(%s,'') LIMIT 1",
                    (payload.company_name, dom or "")
                ).fetchone()

            if not comp:
                comp_id = str(uuid.uuid4())
                comp = conn.execute("""
                    INSERT INTO sales_companies (id, name, domain, website, city, state, company_type, notes)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING *
                """, (comp_id, payload.company_name, dom, payload.website, payload.city, payload.state, payload.company_type, payload.notes)).fetchone()

                # House ownership row (owner_rep_id NULL, house_account TRUE)
                conn.execute("""
                    INSERT INTO sales_company_ownership (id, company_id, owner_rep_id, house_account, protection_expires_at, ownership_reason)
                    VALUES (%s,%s,NULL,TRUE,%s,%s)
                """, (str(uuid.uuid4()), comp_id, datetime.utcnow() + timedelta(days=14), "house_queue_seed"))

            # Avoid duplicate open leads in house queue by domain
            if dom:
                dup = conn.execute("""
                    SELECT id FROM sales_leads
                    WHERE rep_id IS NULL AND domain=%s AND stage NOT IN ('closed_won','closed_lost')
                    ORDER BY created_at DESC LIMIT 1
                """, (dom,)).fetchone()
                if dup:
                    continue

            lead_id = str(uuid.uuid4())
            conn.execute("""
                INSERT INTO sales_leads (
                  id, rep_id, company_id, company_name, domain, website, city, state,
                  company_type, lead_source, contact_name, contact_title, contact_email, contact_phone,
                  stage, notes, duplicate_of, linked_company_id
                )
                VALUES (%s,NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'new',%s,NULL,%s)
            """, (
                lead_id, comp["id"], payload.company_name, dom, payload.website, payload.city, payload.state,
                payload.company_type, payload.lead_source, payload.contact_name, payload.contact_title, payload.contact_email, payload.contact_phone,
                payload.notes, comp["id"]
            ))
            added += 1

    return {"ok": True, "added": added}

@app.get("/sales/house_queue", tags=["Sales"], summary="List House Queue leads (unclaimed)")
def list_house_queue(request: Request, q: Optional[str]=None, stage: Optional[str]=None, limit: int = Query(50, ge=1, le=50)):
    _ = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        sql = "SELECT * FROM sales_leads WHERE rep_id IS NULL"
        vals = []
        if stage:
            sql += " AND stage=%s"
            vals.append(stage)
        if q:
            sql += " AND (company_name ILIKE %s OR COALESCE(contact_name,'') ILIKE %s OR COALESCE(contact_email,'') ILIKE %s OR COALESCE(domain,'') ILIKE %s)"
            vals.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])
        sql += " ORDER BY created_at DESC LIMIT %s"
        vals.append(limit)
        rows = conn.execute(sql, tuple(vals)).fetchall()
    return {"ok": True, "leads": rows}

@app.post("/sales/house_queue/{lead_id}/claim", tags=["Sales"], summary="Claim a House Queue lead (atomic)")
def claim_house_lead(lead_id: str, request: Request):
    rep = require_sales_rep(request)

    with db() as conn:
        ensure_sales_tables(conn)

        # Enforce max 50 active leads per rep (prevents hoarding)
        active = conn.execute("""
            SELECT COUNT(*)::int AS cnt
            FROM sales_leads
            WHERE rep_id=%s AND stage NOT IN ('closed_won','closed_lost')
        """, (rep["id"],)).fetchone()["cnt"]

        if active >= 50:
            raise HTTPException(409, "Lead limit reached (50 active). Close/win/lose some leads before claiming more.")

        # Atomic claim: only succeeds if rep_id is still NULL
        row = conn.execute("""
            UPDATE sales_leads
            SET rep_id=%s,
                claimed_at=NOW(),
                claimed_by_email=%s,
                protection_expires_at=(NOW() + INTERVAL '14 days'),
                updated_at=NOW()
            WHERE id=%s AND rep_id IS NULL
            RETURNING *
        """, (rep["id"], (rep.get("email") or "").lower().strip(), lead_id)).fetchone()

        if not row:
            raise HTTPException(409, "Already claimed (or not in house queue)")

        company_id = row.get("company_id") or row.get("linked_company_id")
        if company_id:
            # close any existing open ownership record (house or previous)
            conn.execute("""
                UPDATE sales_company_ownership
                SET ownership_end=NOW()
                WHERE company_id=%s AND ownership_end IS NULL
            """, (company_id,))

            # assign ownership to claiming rep
            conn.execute("""
                INSERT INTO sales_company_ownership (id, company_id, owner_rep_id, house_account, protection_expires_at, ownership_reason)
                VALUES (%s,%s,%s,FALSE,%s,%s)
            """, (str(uuid.uuid4()), company_id, rep["id"], datetime.utcnow() + timedelta(days=14), "house_queue_claim"))

            # audit
            conn.execute("""
                INSERT INTO sales_ownership_audit (id, entity_type, entity_id, action, from_rep_id, to_rep_id, reason, actor_email)
                VALUES (%s,'lead',%s,'claim',NULL,%s,%s,%s)
            """, (str(uuid.uuid4()), lead_id, rep["id"], "claimed from house queue", (rep.get("email") or "")))

            conn.execute("""
                INSERT INTO sales_ownership_audit (id, entity_type, entity_id, action, from_rep_id, to_rep_id, reason, actor_email)
                VALUES (%s,'company',%s,'assign',NULL,%s,%s,%s)
            """, (str(uuid.uuid4()), company_id, rep["id"], "ownership assigned via claim", (rep.get("email") or "")))

    return {"ok": True, "lead": row}

@app.get("/sales/leads", tags=["Sales"], summary="List my leads")
def list_leads(request: Request, q: Optional[str]=None, stage: Optional[str]=None, limit: int = Query(200, ge=1, le=2000)):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        sql = "SELECT * FROM sales_leads WHERE 1=1"
        vals = []

        if rep["role"] == "sales_rep":
            sql += " AND rep_id=%s"
            vals.append(rep["id"])
        if stage:
            sql += " AND stage=%s"; vals.append(stage)
        if q:
            sql += " AND (company_name ILIKE %s OR COALESCE(contact_name,'') ILIKE %s OR COALESCE(contact_email,'') ILIKE %s OR COALESCE(domain,'') ILIKE %s)"
            vals.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])
        sql += " ORDER BY updated_at DESC, created_at DESC LIMIT %s"
        vals.append(limit)
        rows = conn.execute(sql, tuple(vals)).fetchall()
    return {"ok": True, "leads": rows}

class LeadPatchIn(BaseModel):
    stage: Optional[str] = Field(default=None, pattern="^(new|contacted|qualified|demo_scheduled|demo_done|proposal|negotiation|closed_won|closed_lost)$")
    notes: Optional[str] = None
    next_follow_up_at: Optional[datetime] = None

@app.patch("/sales/leads/{lead_id}", tags=["Sales"], summary="Update lead")
def patch_lead(lead_id: str, payload: LeadPatchIn, request: Request):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        lead = conn.execute("SELECT id FROM sales_leads WHERE id=%s AND rep_id=%s", (lead_id, rep["id"])).fetchone()
        if not lead:
            raise HTTPException(404, "Lead not found")

        row = conn.execute("""
            UPDATE sales_leads
            SET stage=COALESCE(%s, stage),
                notes=COALESCE(%s, notes),
                next_follow_up_at=COALESCE(%s, next_follow_up_at),
                updated_at=NOW()
            WHERE id=%s AND rep_id=%s
            RETURNING *
        """, (payload.stage, payload.notes, payload.next_follow_up_at, lead_id, rep["id"])).fetchone()
    return {"ok": True, "lead": row}

class ActivityIn(BaseModel):
    activity_type: str = Field(pattern="^(call|email|demo|note|text|other)$")
    notes: Optional[str] = None
    follow_up_at: Optional[datetime] = None

@app.post("/sales/leads/{lead_id}/activity", tags=["Sales"], summary="Log activity on a lead")
def log_lead_activity(lead_id: str, payload: ActivityIn, request: Request):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        lead = conn.execute("SELECT id FROM sales_leads WHERE id=%s AND rep_id=%s", (lead_id, rep["id"])).fetchone()
        if not lead:
            raise HTTPException(404, "Lead not found")

        act = conn.execute("""
            INSERT INTO sales_activities (id, rep_id, lead_id, activity_type, notes, follow_up_at)
            VALUES (%s,%s,%s,%s,%s,%s)
            RETURNING *
        """, (str(uuid.uuid4()), rep["id"], lead_id, payload.activity_type, payload.notes, payload.follow_up_at)).fetchone()

        conn.execute("""
            UPDATE sales_leads
            SET last_activity_at=NOW(),
                next_follow_up_at=COALESCE(%s, next_follow_up_at),
                updated_at=NOW()
            WHERE id=%s
        """, (payload.follow_up_at, lead_id))

    return {"ok": True, "activity": act}

@app.get("/sales/followups/due", tags=["Sales"], summary="Leads due for follow-up")
def due_followups(request: Request, days_ahead: int = Query(0, ge=0, le=30)):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        rows = conn.execute("""
            SELECT *
            FROM sales_leads
            WHERE rep_id=%s
              AND stage NOT IN ('closed_won','closed_lost')
              AND next_follow_up_at IS NOT NULL
              AND next_follow_up_at <= (NOW() + (%s || ' days')::interval)
            ORDER BY next_follow_up_at ASC
            LIMIT 500
        """, (rep["id"], days_ahead)).fetchall()
    return {"ok": True, "leads": rows}

class TaskCreateIn(BaseModel):
    title: str
    due_at: datetime
    lead_id: Optional[str] = None
    company_id: Optional[str] = None
    deal_id: Optional[str] = None

@app.post("/sales/tasks", tags=["Sales"], summary="Create task")
def create_task(payload: TaskCreateIn, request: Request):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        row = conn.execute("""
            INSERT INTO sales_tasks (id, rep_id, lead_id, company_id, deal_id, title, due_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            RETURNING *
        """, (str(uuid.uuid4()), rep["id"], payload.lead_id, payload.company_id, payload.deal_id, payload.title, payload.due_at)).fetchone()
    return {"ok": True, "task": row}

@app.get("/sales/tasks/due", tags=["Sales"], summary="Tasks due today/soon")
def tasks_due(request: Request, days_ahead: int = Query(0, ge=0, le=30)):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        rows = conn.execute("""
            SELECT *
            FROM sales_tasks
            WHERE rep_id=%s AND status='open' AND due_at <= (NOW() + (%s || ' days')::interval)
            ORDER BY due_at ASC
            LIMIT 500
        """, (rep["id"], days_ahead)).fetchall()
    return {"ok": True, "tasks": rows}

@app.post("/sales/tasks/{task_id}/done", tags=["Sales"], summary="Complete task")
def complete_task(task_id: str, request: Request):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        row = conn.execute("""
            UPDATE sales_tasks
            SET status='done', completed_at=NOW()
            WHERE id=%s AND rep_id=%s
            RETURNING *
        """, (task_id, rep["id"])).fetchone()
        if not row:
            raise HTTPException(404, "Task not found")
    return {"ok": True, "task": row}

# --------------------------
# Deals pipeline
# --------------------------
class DealCreateIn(BaseModel):
    company_id: str
    proposed_plan: Optional[str] = None
    expected_go_live: Optional[str] = None  # YYYY-MM-DD
    expected_mrr_cents: Optional[int] = None
    expected_tons_per_month: Optional[int] = None
    expected_bols_per_month: Optional[int] = None
    probability: int = Field(default=20, ge=0, le=100)
    notes: Optional[str] = None

@app.post("/sales/deals", tags=["Sales"], summary="Create deal")
def create_deal(payload: DealCreateIn, request: Request):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        deal_id = str(uuid.uuid4())
        row = conn.execute("""
            INSERT INTO sales_deals (
              id, company_id, owner_rep_id, proposed_plan, expected_go_live, expected_mrr_cents,
              expected_tons_per_month, expected_bols_per_month, probability, notes
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING *
        """, (
            deal_id, payload.company_id, rep["id"], payload.proposed_plan,
            datetime.fromisoformat(payload.expected_go_live).date() if payload.expected_go_live else None,
            payload.expected_mrr_cents, payload.expected_tons_per_month, payload.expected_bols_per_month,
            payload.probability, payload.notes
        )).fetchone()
    return {"ok": True, "deal": row}

@app.get("/sales/deals", tags=["Sales"], summary="List deals (rep or manager)")
def list_deals(request: Request, stage: Optional[str]=None, q: Optional[str]=None, limit: int = Query(300, ge=1, le=5000)):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)

        sql = """
            SELECT d.*, c.name as company_name, c.company_type, c.domain
            FROM sales_deals d
            JOIN sales_companies c ON c.id=d.company_id
            WHERE 1=1
        """
        vals = []
        if rep["role"] == "sales_rep":
            sql += " AND d.owner_rep_id=%s"; vals.append(rep["id"])
        if stage:
            sql += " AND d.stage=%s"; vals.append(stage)
        if q:
            sql += " AND (c.name ILIKE %s OR COALESCE(c.domain,'') ILIKE %s)"
            vals.extend([f"%{q}%", f"%{q}%"])
        sql += " ORDER BY d.updated_at DESC LIMIT %s"; vals.append(limit)
        rows = conn.execute(sql, tuple(vals)).fetchall()
    return {"ok": True, "deals": rows}

class DealPatchIn(BaseModel):
    stage: Optional[str] = Field(default=None, pattern="^(new|contacted|qualified|demo_scheduled|demo_done|proposal|negotiation|closed_won|closed_lost)$")
    probability: Optional[int] = Field(default=None, ge=0, le=100)
    proposed_plan: Optional[str] = None
    expected_go_live: Optional[str] = None
    expected_mrr_cents: Optional[int] = None
    expected_tons_per_month: Optional[int] = None
    expected_bols_per_month: Optional[int] = None
    notes: Optional[str] = None

@app.patch("/sales/deals/{deal_id}", tags=["Sales"], summary="Update deal")
def patch_deal(deal_id: str, payload: DealPatchIn, request: Request):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)

        d = conn.execute("SELECT * FROM sales_deals WHERE id=%s", (deal_id,)).fetchone()
        if not d:
            raise HTTPException(404, "Deal not found")
        if rep["role"] == "sales_rep" and str(d["owner_rep_id"]) != str(rep["id"]):
            raise HTTPException(403, "Not your deal")

        new_stage = payload.stage
        stage_entered = datetime.utcnow() if new_stage and new_stage != d["stage"] else d["stage_entered_at"]

        row = conn.execute("""
            UPDATE sales_deals
            SET stage=COALESCE(%s, stage),
                stage_entered_at=%s,
                probability=COALESCE(%s, probability),
                proposed_plan=COALESCE(%s, proposed_plan),
                expected_go_live=COALESCE(%s, expected_go_live),
                expected_mrr_cents=COALESCE(%s, expected_mrr_cents),
                expected_tons_per_month=COALESCE(%s, expected_tons_per_month),
                expected_bols_per_month=COALESCE(%s, expected_bols_per_month),
                notes=COALESCE(%s, notes),
                closed_at=CASE WHEN COALESCE(%s, stage) IN ('closed_won','closed_lost') THEN NOW() ELSE closed_at END,
                updated_at=NOW()
            WHERE id=%s
            RETURNING *
        """, (
            payload.stage, stage_entered,
            payload.probability,
            payload.proposed_plan,
            datetime.fromisoformat(payload.expected_go_live).date() if payload.expected_go_live else None,
            payload.expected_mrr_cents,
            payload.expected_tons_per_month,
            payload.expected_bols_per_month,
            payload.notes,
            payload.stage,
            deal_id
        )).fetchone()
    return {"ok": True, "deal": row}

# --------------------------
# Onboarding checklists
# --------------------------
ONBOARDING_TEMPLATE = [
    ("business_verification", "Business verification"),
    ("contact_confirmed", "Contact confirmed"),
    ("plan_selected", "Plan selected"),
    ("billing_method_selected", "Billing method selected (ACH/card/manual)"),
    ("training_scheduled", "Training scheduled"),
    ("training_completed", "Training completed"),
    ("first_inventory_added", "First inventory added"),
    ("first_vendor_sheet_uploaded", "First vendor sheet uploaded"),
    ("first_contract_created", "First contract created"),
    ("first_bol_issued", "First BOL issued"),
]

def _compute_checklist_status(steps) -> str:
    # red if any required blocked; green if all required done; else yellow
    req = [s for s in steps if s["is_required"]]
    if any(s["status"] == "blocked" for s in req):
        return "red"
    if req and all(s["status"] == "done" for s in req):
        return "green"
    return "yellow"

@app.post("/sales/onboarding/create", tags=["Sales"], summary="Create onboarding checklist for company")
def create_onboarding(request: Request, company_id: str, deal_id: Optional[str]=None):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        existing = conn.execute("SELECT * FROM onboarding_checklists WHERE company_id=%s ORDER BY created_at DESC LIMIT 1", (company_id,)).fetchone()
        if existing:
            return {"ok": True, "checklist": existing, "created": False}

        cid = str(uuid.uuid4())
        chk = conn.execute("""
            INSERT INTO onboarding_checklists (id, company_id, deal_id, status)
            VALUES (%s,%s,%s,'yellow')
            RETURNING *
        """, (cid, company_id, deal_id)).fetchone()

        for key, label in ONBOARDING_TEMPLATE:
            conn.execute("""
                INSERT INTO onboarding_steps (id, checklist_id, step_key, label, is_required, status)
                VALUES (%s,%s,%s,%s,TRUE,'todo')
            """, (str(uuid.uuid4()), cid, key, label))

    return {"ok": True, "checklist": chk, "created": True}

@app.get("/sales/onboarding", tags=["Sales"], summary="Get onboarding checklist + steps for company")
def get_onboarding(company_id: str, request: Request):
    _ = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        chk = conn.execute("SELECT * FROM onboarding_checklists WHERE company_id=%s ORDER BY created_at DESC LIMIT 1", (company_id,)).fetchone()
        if not chk:
            return {"ok": True, "checklist": None, "steps": []}
        steps = conn.execute("SELECT * FROM onboarding_steps WHERE checklist_id=%s ORDER BY label ASC", (chk["id"],)).fetchall()
    return {"ok": True, "checklist": chk, "steps": steps}

class StepPatchIn(BaseModel):
    status: str = Field(pattern="^(todo|doing|done|blocked)$")
    blocker_notes: Optional[str] = None

@app.patch("/sales/onboarding/step/{step_id}", tags=["Sales"], summary="Update onboarding step")
def patch_onboarding_step(step_id: str, payload: StepPatchIn, request: Request):
    _ = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        step = conn.execute("SELECT * FROM onboarding_steps WHERE id=%s", (step_id,)).fetchone()
        if not step:
            raise HTTPException(404, "Step not found")

        updated = conn.execute("""
            UPDATE onboarding_steps
            SET status=%s, blocker_notes=COALESCE(%s, blocker_notes), updated_at=NOW()
            WHERE id=%s
            RETURNING *
        """, (payload.status, payload.blocker_notes, step_id)).fetchone()

        # recompute checklist status
        steps = conn.execute("SELECT * FROM onboarding_steps WHERE checklist_id=%s", (step["checklist_id"],)).fetchall()
        status = _compute_checklist_status(steps)
        conn.execute("UPDATE onboarding_checklists SET status=%s, updated_at=NOW() WHERE id=%s", (status, step["checklist_id"]))

    return {"ok": True, "step": updated, "checklist_status": status}

@app.get("/sales/onboarding/stuck", tags=["Sales"], summary="Onboarding stuck (red/yellow)")
def onboarding_stuck(request: Request, status: str = Query("red", pattern="^(red|yellow)$"), limit: int = Query(200, ge=1, le=2000)):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        sql = """
          SELECT o.*, c.name as company_name
          FROM onboarding_checklists o
          JOIN sales_companies c ON c.id=o.company_id
          WHERE o.status=%s
        """
        vals = [status]
        if rep["role"] == "sales_rep":
            sql += " AND EXISTS (SELECT 1 FROM sales_company_ownership co WHERE co.company_id=o.company_id AND co.owner_rep_id=%s AND co.ownership_end IS NULL)"
            vals.append(rep["id"])
        sql += " ORDER BY o.updated_at DESC LIMIT %s"
        vals.append(limit)
        rows = conn.execute(sql, tuple(vals)).fetchall()
    return {"ok": True, "checklists": rows}

# --------------------------
# Assets
# --------------------------
@app.get("/sales/assets", tags=["Sales"], summary="List sales collateral/templates")
def list_assets(request: Request):
    _ = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        rows = conn.execute("SELECT * FROM sales_assets ORDER BY updated_at DESC").fetchall()
    return {"ok": True, "assets": rows}

class AssetUpsertIn(BaseModel):
    name: str
    asset_type: str
    url: str
    notes: Optional[str] = None

@app.post("/admin/sales/assets", tags=["Admin","Sales"], summary="Add/update asset (admin)")
def upsert_asset(payload: AssetUpsertIn, request: Request):
    require_admin(request)
    with db() as conn:
        ensure_sales_tables(conn)
        existing = conn.execute("SELECT * FROM sales_assets WHERE name=%s AND asset_type=%s LIMIT 1", (payload.name, payload.asset_type)).fetchone()
        if existing:
            row = conn.execute("""
                UPDATE sales_assets SET url=%s, notes=COALESCE(%s, notes), updated_at=NOW()
                WHERE id=%s
                RETURNING *
            """, (payload.url, payload.notes, existing["id"])).fetchone()
            return {"ok": True, "asset": row, "updated": True}

        row = conn.execute("""
            INSERT INTO sales_assets (id, name, asset_type, url, notes)
            VALUES (%s,%s,%s,%s,%s)
            RETURNING *
        """, (str(uuid.uuid4()), payload.name, payload.asset_type, payload.url, payload.notes)).fetchone()
        return {"ok": True, "asset": row, "updated": False}

# --------------------------
# Manual revenue intake + commissions
# --------------------------
class RevenuePostIn(BaseModel):
    company_id: str
    revenue_type: str = Field(pattern="^(subscription|overage|addon|one_time)$")
    amount_cents: int = Field(ge=1)
    collected_at: datetime
    currency: str = "USD"
    external_ref: Optional[str] = None
    deal_id: Optional[str] = None
    proposed_plan: Optional[str] = None  # used for activation bonus if first payment

def _get_company_owner(conn, company_id: str) -> Optional[str]:
    row = conn.execute("""
        SELECT owner_rep_id, house_account
        FROM sales_company_ownership
        WHERE company_id=%s AND ownership_end IS NULL
        ORDER BY ownership_start DESC
        LIMIT 1
    """, (company_id,)).fetchone()
    if not row or row["house_account"]:
        return None
    return row["owner_rep_id"]

def _ensure_activation_tranches(conn, rep_id: str, company_id: str, plan_key: str, collected_at: datetime):
    # prevent duplicate activation bonus
    exists = conn.execute("""
        SELECT 1 FROM commission_ledger
        WHERE rep_id=%s AND company_id=%s AND line_type='activation_bonus'
        LIMIT 1
    """, (rep_id, company_id)).fetchone()
    if exists:
        return

    bonus_map = PLAN_RULES_V1["activation_bonus"]
    total = int(bonus_map.get((plan_key or "").lower(), 0))
    if total <= 0:
        return

    for tranche in PLAN_RULES_V1["activation_vesting"]:
        pct = tranche["pct"]
        months = tranche["months"]
        amt = int(round(total * pct))
        net30 = collected_at + timedelta(days=int(PLAN_RULES_V1["net30_days"])) + timedelta(days=30*months)
        conn.execute("""
            INSERT INTO commission_ledger (id, rep_id, company_id, revenue_event_id, deal_id, line_type, amount_cents, status, net30_release_at, notes)
            VALUES (%s,%s,%s,NULL,NULL,'activation_bonus',%s,'pending',%s,%s)
        """, (str(uuid.uuid4()), rep_id, company_id, amt, net30, f"Activation tranche {int(pct*100)}% @ month {months}"))

def _commission_for_revenue(revenue_type: str, amount_cents: int, month_index: int) -> int:
    if revenue_type == "overage":
        return int(round(amount_cents * float(PLAN_RULES_V1["overage_pct"])))
    if revenue_type == "subscription":
        if month_index <= int(PLAN_RULES_V1["mrr"]["months_y1"]):
            return int(round(amount_cents * float(PLAN_RULES_V1["mrr"]["y1_pct"])))
        if month_index <= int(PLAN_RULES_V1["mrr"]["months_y2"]):
            return int(round(amount_cents * float(PLAN_RULES_V1["mrr"]["y2_pct"])))
        return 0
    if revenue_type in ("addon","one_time"):
        # treat like subscription for now (you can change later)
        return int(round(amount_cents * float(PLAN_RULES_V1["mrr"]["y1_pct"])))
    return 0

def _month_index_from_first(conn, company_id: str, collected_at: datetime) -> int:
    # month index based on first subscription payment recorded
    first = conn.execute("""
        SELECT MIN(collected_at) AS first_at
        FROM revenue_events
        WHERE company_id=%s AND revenue_type='subscription'
    """, (company_id,)).fetchone()
    if not first or not first["first_at"]:
        return 1
    fa = first["first_at"]
    return (collected_at.year - fa.year) * 12 + (collected_at.month - fa.month) + 1

@app.post("/admin/sales/revenue/post", tags=["Admin","Sales"], summary="Manual revenue posting (admin)")
def post_revenue(payload: RevenuePostIn, request: Request):
    require_admin(request)
    actor = _actor_email(request)
    with db() as conn:
        ensure_sales_tables(conn)
        _ensure_plan_row(conn)

        # create revenue event
        ev_id = str(uuid.uuid4())
        ev = conn.execute("""
            INSERT INTO revenue_events (id, company_id, revenue_type, amount_cents, currency, collected_at, external_ref, created_by_email)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING *
        """, (ev_id, payload.company_id, payload.revenue_type, payload.amount_cents, payload.currency, payload.collected_at, payload.external_ref, actor)).fetchone()

        rep_id = _get_company_owner(conn, payload.company_id)
        if not rep_id:
            return {"ok": True, "revenue_event": ev, "commission_created": False, "reason": "No owner or house account"}

        mi = _month_index_from_first(conn, payload.company_id, payload.collected_at)
        comm_amt = _commission_for_revenue(payload.revenue_type, payload.amount_cents, mi)
        net30 = payload.collected_at + timedelta(days=int(PLAN_RULES_V1["net30_days"]))

        if comm_amt > 0:
            conn.execute("""
                INSERT INTO commission_ledger (id, rep_id, company_id, revenue_event_id, deal_id, line_type, amount_cents, status, net30_release_at, notes)
                VALUES (%s,%s,%s,%s,%s,%s,%s,'pending',%s,%s)
            """, (
                str(uuid.uuid4()),
                rep_id,
                payload.company_id,
                ev_id,
                payload.deal_id,
                "overage_residual" if payload.revenue_type == "overage" else "residual_mrr",
                comm_amt,
                net30,
                f"{payload.revenue_type} month_index={mi}"
            ))

        # activation schedule: only when first subscription is posted + plan_key provided
        if payload.revenue_type == "subscription" and payload.proposed_plan:
            first_sub = conn.execute("""
                SELECT COUNT(*)::int AS cnt
                FROM revenue_events
                WHERE company_id=%s AND revenue_type='subscription'
            """, (payload.company_id,)).fetchone()
            if first_sub and first_sub["cnt"] == 1:
                _ensure_activation_tranches(conn, rep_id, payload.company_id, payload.proposed_plan, payload.collected_at)

    return {"ok": True, "revenue_event": ev, "commission_created": True}

@app.get("/admin/sales/revenue", tags=["Admin","Sales"], summary="List revenue events (admin)")
def list_revenue(request: Request, limit: int = Query(500, ge=1, le=5000)):
    require_admin(request)
    with db() as conn:
        ensure_sales_tables(conn)
        rows = conn.execute("""
            SELECT r.*, c.name as company_name
            FROM revenue_events r
            JOIN sales_companies c ON c.id=r.company_id
            ORDER BY r.collected_at DESC
            LIMIT %s
        """, (limit,)).fetchall()
    return {"ok": True, "revenue": rows}

@app.get("/sales/ledger", tags=["Sales"], summary="My commission ledger")
def my_ledger(request: Request, limit: int = Query(500, ge=1, le=5000)):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        rows = conn.execute("""
            SELECT l.*, c.name as company_name
            FROM commission_ledger l
            JOIN sales_companies c ON c.id=l.company_id
            WHERE l.rep_id=%s
            ORDER BY l.created_at DESC
            LIMIT %s
        """, (rep["id"], limit)).fetchall()
    return {"ok": True, "ledger": rows}

# --------------------------
# Dashboards
# --------------------------
@app.get("/sales/dashboard", tags=["Sales"], summary="Rep dashboard summary")
def rep_dashboard(request: Request):
    rep = require_sales_rep(request)
    with db() as conn:
        ensure_sales_tables(conn)
        leads_due = conn.execute("""
            SELECT COUNT(*)::int AS cnt
            FROM sales_leads
            WHERE rep_id=%s AND stage NOT IN ('closed_won','closed_lost')
              AND next_follow_up_at IS NOT NULL AND next_follow_up_at <= NOW()
        """, (rep["id"],)).fetchone()["cnt"]

        tasks_due = conn.execute("""
            SELECT COUNT(*)::int AS cnt
            FROM sales_tasks
            WHERE rep_id=%s AND status='open' AND due_at <= NOW()
        """, (rep["id"],)).fetchone()["cnt"]

        pipeline = conn.execute("""
            SELECT stage, COUNT(*)::int AS cnt
            FROM sales_deals
            WHERE owner_rep_id=%s
            GROUP BY 1 ORDER BY 1
        """, (rep["id"],)).fetchall()

        onboarding_red = conn.execute("""
            SELECT COUNT(*)::int AS cnt
            FROM onboarding_checklists o
            WHERE o.status='red'
              AND EXISTS (SELECT 1 FROM sales_company_ownership co WHERE co.company_id=o.company_id AND co.owner_rep_id=%s AND co.ownership_end IS NULL)
        """, (rep["id"],)).fetchone()["cnt"]

        pending_comm = conn.execute("""
            SELECT COALESCE(SUM(amount_cents),0)::bigint AS cents
            FROM commission_ledger
            WHERE rep_id=%s AND status='pending'
        """, (rep["id"],)).fetchone()["cents"]

    return {"ok": True, "leads_due": leads_due, "tasks_due": tasks_due, "pipeline": pipeline, "onboarding_red": onboarding_red, "pending_commission_cents": pending_comm}

@app.get("/admin/sales/dashboard", tags=["Admin","Sales"], summary="Manager/admin dashboard summary")
def admin_dashboard_sales(request: Request):
    require_sales_manager(request)
    with db() as conn:
        ensure_sales_tables(conn)

        pipeline = conn.execute("""
            SELECT stage, COUNT(*)::int AS cnt
            FROM sales_deals
            GROUP BY 1 ORDER BY 1
        """).fetchall()

        onboarding = conn.execute("""
            SELECT status, COUNT(*)::int AS cnt
            FROM onboarding_checklists
            GROUP BY 1 ORDER BY 1
        """).fetchall()

        pending = conn.execute("""
            SELECT COALESCE(SUM(amount_cents),0)::bigint AS cents
            FROM commission_ledger
            WHERE status='pending'
        """).fetchone()["cents"]

    return {"ok": True, "pipeline": pipeline, "onboarding": onboarding, "pending_commission_cents": pending}

# ----- BRidge Sales -----

# ------ App --------
# Serve /static/* (HTML/JS/JSON)
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

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
    allow_origins=["*"] if ENV!="production" else ["https://dossierdating.com","https://atlasipholdingsllc.com","https://dossierhr.onrender.com","https://hr.dossierdating.com"],
    allow_credentials=True,
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allow_headers=["*"],
)

# Rate limit
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response

# Prometheus
if PROM_ENABLED:
    Instrumentator().instrument(app).expose(app)


# ---- DB helper ----
def db():
    if not DB_URL:
        raise RuntimeError("DATABASE_URL missing")
    return psycopg.connect(DB_URL, autocommit=True, row_factory=dict_row)
# ---- DB helper ----

# ------ ingest scraper to raw entities ------
def _sha256(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()

def _fingerprint_for_entity(entity_type: str, payload: dict, source_url: str) -> str:
    """
    Stable dedupe key.
    Preference order:
      domain -> phone_e164 -> website host -> contact_email domain -> source_url host -> name+city+state
    """
    p = payload or {}
    dom = _extract_domain(p.get("domain")) or _extract_domain(p.get("website")) or _extract_domain(p.get("url")) or _extract_domain(p.get("contact_email"))
    phone = (p.get("phone_e164") or p.get("phone") or "").strip()
    host = _extract_domain(source_url)

    name = (p.get("name") or p.get("company_name") or "").strip().lower()
    city = (p.get("city") or "").strip().lower()
    state = (p.get("state") or "").strip().lower()

    key = None
    if dom:
        key = f"dom:{dom}"
    elif phone:
        key = f"ph:{phone}"
    elif host:
        key = f"host:{host}"
    elif name:
        key = f"name:{name}|{city}|{state}"
    else:
        key = f"fallback:{entity_type}|{source_url}"

    return _sha256(f"{entity_type}|{key}")

def _require_ingest_token(request: Request):
    """
    Allows scraper (non-session) pushes.
    Header: X-Ingest-Token: <INGEST_WEBHOOK_SECRET>
    """
    if ENV != "production" and (INGEST_WEBHOOK_SECRET or "") == "dev_ingest":
        # dev default: allow without token if you want; comment this out to force token
        return True

    tok = request.headers.get("X-Ingest-Token") or ""
    if not INGEST_WEBHOOK_SECRET:
        raise HTTPException(500, "INGEST_WEBHOOK_SECRET not configured")
    if not hmac.compare_digest(tok, INGEST_WEBHOOK_SECRET):
        raise HTTPException(401, "Invalid ingest token")
    return True


class IngestStartOut(BaseModel):
    run_id: str
    started_at: str
    source: str


@app.post("/admin/ingest/start", tags=["Admin","Scraper"], summary="Start an ingest run (admin)")
def ingest_start(request: Request, source: str = Query("yard_crawler")):
    require_admin(request)
    run_id = str(uuid.uuid4())
    with db() as conn:
        conn.execute("""
            INSERT INTO ingest_runs (id, source, status)
            VALUES (%s,%s,'running')
        """, (run_id, source))
        row = conn.execute("SELECT started_at FROM ingest_runs WHERE id=%s", (run_id,)).fetchone()
    return IngestStartOut(run_id=run_id, started_at=str(row["started_at"]), source=source)


class RawEntityIn(BaseModel):
    entity_type: str = Field(pattern="^(company|contact|location)$")
    source_url: Optional[str] = None
    payload: dict


class IngestPushIn(BaseModel):
    run_id: str
    source: Optional[str] = None
    entities: List[RawEntityIn]


@app.post("/ingest/raw_entities", tags=["Scraper"], summary="Push raw entities into raw_entities")
def ingest_raw_entities(payload: IngestPushIn, request: Request):
    _require_ingest_token(request)

    inserted = 0
    updated = 0

    with db() as conn:
        # validate run exists
        run = conn.execute("SELECT id FROM ingest_runs WHERE id=%s", (payload.run_id,)).fetchone()
        if not run:
            raise HTTPException(404, "run_id not found (call /admin/ingest/start or create ingest_runs row)")

        for e in payload.entities:
            src_url = e.source_url or ""
            fp = _fingerprint_for_entity(e.entity_type, e.payload, src_url)

            # use your upsert-y insert_raw_entity
            before = conn.execute(
                "SELECT id FROM raw_entities WHERE entity_type=%s AND fingerprint=%s",
                (e.entity_type, fp)
            ).fetchone()

            rid = insert_raw_entity(conn, payload.run_id, e.entity_type, src_url, fp, e.payload)
            if before:
                updated += 1
            else:
                inserted += 1

        # update ingest run stats
        conn.execute("""
            UPDATE ingest_runs
            SET stats = jsonb_set(
              COALESCE(stats,'{}'::jsonb),
              '{raw_entities}',
              to_jsonb(COALESCE((stats->>'raw_entities')::int,0) + %s),
              true
            )
            WHERE id=%s
        """, (inserted, payload.run_id))

    return {"ok": True, "run_id": payload.run_id, "inserted": inserted, "updated": updated}
# ------ ingest scraper to raw entities ------

# ----- startup events -----
@app.on_event("startup")
def _startup_sales_tables():
    try:
        with db() as conn:
            ensure_sales_tables(conn)
            _ensure_plan_row(conn)
    except Exception as e:
        if ENV == "production":
            raise
        log.warning("sales_startup_tables_failed", err=str(e))
# ----- startup events -----

# ----------- Passive ingestion -----------
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

def redirect_for_role(r: str) -> str:
    r = (r or "").strip().lower().replace("-", "_")
    
    if r == "admin":
        return "/static/admin.html"
    if r == "manager":
        return "/static/manager.html"
    if r == "sales_manager":
        return "/static/sales-manager.html"
    if r in ("sales_rep", "sdr"):
        return "/static/sales-portal.html"
    return "/static/employee.html"


# -------- Health -----------
@app.get("/health", tags=["System"], summary="Healthcheck")
def health():
    return {"ok": True, "env": ENV, "ts": datetime.utcnow().isoformat()}

# -------- Auth --------------
@app.post("/login", tags=["Auth"], summary="Login")
@limiter.limit("10/minute")
def login(payload: LoginIn, request: Request):
    # Quick admin fallback
    if (payload.email or "").lower().strip() == (ADMIN_EMAIL or "").lower().strip() and ADMIN_PASSWORD_HASH and verify_password(payload.password, ADMIN_PASSWORD_HASH):
        request.session["user"] = ADMIN_EMAIL
        request.session["role"] = "admin"
        request.session["hr_user_id"] = None
        request.session["sales_rep_id"] = None
        request.session["profile_id"] = None
        return {"ok": True, "role": "admin", "redirect": redirect_for_role("admin")}

    # DB lookup
    with db() as conn:
        row = conn.execute(
            "SELECT u.id, u.email, u.password_hash, u.sales_rep_id, u.profile_id, r.name as role "
            "FROM hr_users u JOIN roles r ON u.role_id=r.id "
            "WHERE lower(u.email)=lower(%s) AND u.is_active=TRUE",
            ((payload.email or "").lower().strip(),)
        ).fetchone()
        if not row:
            raise HTTPException(401, "Invalid credentials")
        if not verify_password(payload.password, row["password_hash"]):
            raise HTTPException(401, "Invalid credentials")
    request.session["user"] = row["email"]
    request.session["role"] = row["role"]
    request.session["hr_user_id"] = str(row["id"])
    request.session["sales_rep_id"] = str(row["sales_rep_id"]) if row.get("sales_rep_id") else None
    request.session["profile_id"] = str(row["profile_id"]) if row.get("profile_id") else None

    role = row["role"]

    return {
        "ok": True,
        "role": role,
        "redirect": redirect_for_role(role),
        "hr_user_id": request.session.get("hr_user_id"),
        "sales_rep_id": request.session.get("sales_rep_id"),
        "profile_id": request.session.get("profile_id"),
    }

@app.post("/logout", tags=["Auth"], summary="Logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}

@app.get("/me", tags=["Auth"], summary="Return current session identity")
def me(request: Request):
    email = request.session.get("user")
    role = request.session.get("role")
    if not email or not role:
        return {"ok": False}

    return {
        "ok": True,
        "email": email,
        "role": role,
        "redirect": redirect_for_role(role),
        "hr_user_id": request.session.get("hr_user_id"),
        "sales_rep_id": request.session.get("sales_rep_id"),
        "profile_id": request.session.get("profile_id"),
    }

@app.get("/whoami", tags=["Auth"], summary="Alias of /me for frontend routing")
def whoami(request: Request):
    return me(request)

class LinkUserIn(BaseModel):
    email: str
    profile_id: Optional[str] = None
    sales_rep_id: Optional[str] = None

@app.post("/admin/hr_users/link", tags=["Admin"], summary="Link an hr_user to a profile_id and/or sales_rep_id")
def admin_link_hr_user(payload: LinkUserIn, request: Request):
    require_admin(request)
    email = payload.email.lower().strip()

    with db() as conn:
        row = conn.execute("SELECT id FROM hr_users WHERE email=%s", (email,)).fetchone()
        if not row:
            raise HTTPException(404, "hr_user not found")

        conn.execute(
            "UPDATE hr_users SET profile_id=COALESCE(%s, profile_id), sales_rep_id=COALESCE(%s, sales_rep_id) WHERE email=%s",
            (payload.profile_id, payload.sales_rep_id, email)
        )
    
    # If you're linking the currently logged-in user, refresh session claims
    if (request.session.get("user") or "").lower().strip() == email:
        with db() as conn:
            fresh = conn.execute(
                "SELECT id, email, sales_rep_id, profile_id "
                "FROM hr_users WHERE email=%s",
                (email,)
            ).fetchone()
        if fresh:
            request.session["hr_user_id"] = str(fresh["id"])
            request.session["sales_rep_id"] = str(fresh["sales_rep_id"]) if fresh.get("sales_rep_id") else None
            request.session["profile_id"] = str(fresh["profile_id"]) if fresh.get("profile_id") else None

    return {"ok": True}
# ------ Auth --------------

# ------- UI aliases (NO dashboard logic; just redirect to static pages) -------
def _ui_to(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=302)

@app.get("/dashboard/employee", include_in_schema=False)
def ui_employee_alias():
    return _ui_to("/static/employee.html")

@app.get("/dashboard/manager", include_in_schema=False)
def ui_manager_alias():
    return _ui_to("/static/manager.html")

@app.get("/dashboard/admin", include_in_schema=False)
def ui_admin_alias():
    return _ui_to("/static/admin.html")

@app.get("/dashboard/sales", include_in_schema=False)
def ui_sales_portal_alias():
    return _ui_to("/static/sales-portal.html")

@app.get("/dashboard/sales-manager", include_in_schema=False)
def ui_sales_manager_alias():
    return _ui_to("/static/sales-manager.html")

@app.get("/sales/admin/ui", include_in_schema=False)
def ui_sales_admin_alias():
    return _ui_to("/static/sales-admin.html")

@app.get("/sales/manager/ui", include_in_schema=False)
def ui_sales_manager_ui_alias():
    return _ui_to("/static/sales-manager.html")

@app.get("/sales/leads/ui", include_in_schema=False)
def ui_sales_leads_alias():
    return _ui_to("/static/sales-leads.html")

@app.get("/sales/deals/ui", include_in_schema=False)
def ui_sales_deals_alias():
    return _ui_to("/static/sales-deals.html")

@app.get("/sales/onboarding/ui", include_in_schema=False)
def ui_sales_onboarding_alias():
    return _ui_to("/static/sales-onboarding.html")

@app.get("/sales/assets/ui", include_in_schema=False)
def ui_sales_assets_alias():
    return _ui_to("/static/sales-assets.html")

@app.get("/apply/sales", include_in_schema=False)
def ui_sales_apply_alias():
    return _ui_to("/static/sales-apply.html")

@app.get("/apply/sales/invite", include_in_schema=False)
def ui_sales_invite_alias():
    return _ui_to("/static/sales-invite-accept.html")
# ------- /UI aliases -------

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

# -------- HR Records by linked profile_id --------
@app.get("/hr/me/profile", tags=["HR"], summary="Return my linked profile (if any)")
def hr_me_profile(request: Request):
    role = request.session.get("role")
    if role not in ("employee", "manager", "admin"):
        raise HTTPException(403, "HR only")
    pid = request.session.get("profile_id")
    if not pid:
        return {"ok": True, "profile": None}

    with db() as conn:
        prof = conn.execute("SELECT * FROM profiles WHERE id=%s AND deleted_at IS NULL", (pid,)).fetchone()
    return {"ok": True, "profile": prof}

@app.get("/hr/me/records", tags=["HR"], summary="Return my HR records (by linked profile_id)")
def hr_me_records(request: Request, limit: int = Query(200, ge=1, le=2000)):
    role = request.session.get("role")
    if role not in ("employee", "manager", "admin"):
        raise HTTPException(403, "HR only")
    pid = request.session.get("profile_id")
    if not pid:
        return {"ok": True, "records": []}

    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM hr_records WHERE profile_id=%s ORDER BY created_at DESC LIMIT %s",
            (pid, limit)
        ).fetchall()
    return {"ok": True, "records": rows}
# ------- HR Records by linked profile_id --------

# -------- Profiles ---------
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
# ------- Profiles -----------

# -------- insert_raw_entity -----------
def insert_raw_entity(conn, run_id, entity_type, source_url, fingerprint, payload: dict):
    row_id = str(uuid.uuid4())
    with conn.cursor() as cur:
        cur.execute("""
            insert into raw_entities (id, run_id, entity_type, source_url, fingerprint, payload)
            values (%s,%s,%s,%s,%s,%s::jsonb)
            on conflict (entity_type, fingerprint) do update
              set payload = excluded.payload,
                  source_url = excluded.source_url,
                  fetched_at = now()
            returning id
        """, (row_id, run_id, entity_type, source_url, fingerprint, json.dumps(payload)))
        row = cur.fetchone()
        return row["id"] if row else None
    
def upsert_company(conn, payload: dict):
    company_id = str(uuid.uuid4())

    name = payload.get("name")
    domain = (payload.get("domain") or "").lower() or None
    phone = payload.get("phone_e164")
    website = payload.get("website")
    address1 = payload.get("address1")
    city = payload.get("city")
    state = payload.get("state")
    postal = payload.get("postal")

    with conn.cursor() as cur:
        # match by domain first (strongest)
        if domain:
            cur.execute("select id from companies where domain=%s", (domain,))
            row = cur.fetchone()
            if row:
                company_id = row["id"]

        # upsert
        cur.execute("""
            insert into companies (id,name,domain,phone_e164,website,address1,city,state,postal,updated_at)
            values (%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
            on conflict (domain) do update set
              name=coalesce(excluded.name, companies.name),
              phone_e164=coalesce(excluded.phone_e164, companies.phone_e164),
              website=coalesce(excluded.website, companies.website),
              address1=coalesce(excluded.address1, companies.address1),
              city=coalesce(excluded.city, companies.city),
              state=coalesce(excluded.state, companies.state),
              postal=coalesce(excluded.postal, companies.postal),
              updated_at=now()
            returning id
        """, (company_id,name,domain,phone,website,address1,city,state,postal))

        row = cur.fetchone()
        return row["id"] if row else None

def ensure_lead(conn, company_id: str):
    lead_id = str(uuid.uuid4())
    with conn.cursor() as cur:
        cur.execute("""
          insert into leads (id, company_id)
          values (%s,%s)
          on conflict (company_id) do update set updated_at=now()
          returning id
        """, (lead_id, company_id))
        row = cur.fetchone()
        return row["id"] if row else None

def attach_source(conn, company_id, raw_entity_id, source, source_url):
    with conn.cursor() as cur:
        cur.execute("""
          insert into company_sources (company_id, raw_entity_id, source, source_url)
          values (%s,%s,%s,%s)
          on conflict do nothing
        """, (company_id, raw_entity_id, source, source_url))

def _sales_upsert_company_from_payload(conn, p: dict) -> str:
    """
    Upsert into sales_companies (CRM) using best available fields.
    Returns sales_companies.id
    """
    name = (p.get("name") or p.get("company_name") or "").strip() or "Unknown"
    website = (p.get("website") or p.get("url") or p.get("source_url") or "").strip() or None
    dom = _extract_domain(p.get("domain")) or _extract_domain(website) or _extract_domain(p.get("contact_email"))

    city = p.get("city")
    state = p.get("state")
    ctype = p.get("company_type") or p.get("type") or "yard"
    notes = p.get("notes")

    # 1) try by domain
    row = None
    if dom:
        row = conn.execute("SELECT * FROM sales_companies WHERE domain=%s LIMIT 1", (dom,)).fetchone()

    # 2) fallback by name+domain
    if not row:
        row = conn.execute(
            "SELECT * FROM sales_companies WHERE lower(name)=lower(%s) AND COALESCE(domain,'')=COALESCE(%s,'') LIMIT 1",
            (name, dom or "")
        ).fetchone()

    if row:
        updated = conn.execute("""
            UPDATE sales_companies
            SET website=COALESCE(%s, website),
                city=COALESCE(%s, city),
                state=COALESCE(%s, state),
                company_type=COALESCE(%s, company_type),
                notes=COALESCE(%s, notes),
                updated_at=NOW()
            WHERE id=%s
            RETURNING id
        """, (website, city, state, ctype, notes, row["id"])).fetchone()
        return str(updated["id"])

    cid = str(uuid.uuid4())
    conn.execute("""
        INSERT INTO sales_companies (id, name, domain, website, city, state, company_type, notes)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """, (cid, name, dom, website, city, state, ctype, notes))

    # default ownership = house (NULL owner, house_account TRUE)
    conn.execute("""
        INSERT INTO sales_company_ownership (id, company_id, owner_rep_id, house_account, protection_expires_at, ownership_reason)
        VALUES (%s,%s,NULL,TRUE,%s,%s)
    """, (str(uuid.uuid4()), cid, datetime.utcnow() + timedelta(days=14), "normalized_house_seed"))

    return cid


def _ensure_house_sales_lead(conn, sales_company_id: str, p: dict) -> Optional[str]:
    """
    Create an unassigned (house queue) sales_leads row if not already present.
    Returns lead_id or None if deduped.
    """
    website = (p.get("website") or p.get("url") or "").strip() or None
    dom = _extract_domain(p.get("domain")) or _extract_domain(website) or _extract_domain(p.get("contact_email"))

    # dedupe: avoid duplicate open house leads by domain
    if dom:
        dup = conn.execute("""
            SELECT id
            FROM sales_leads
            WHERE rep_id IS NULL AND domain=%s AND stage NOT IN ('closed_won','closed_lost')
            ORDER BY created_at DESC
            LIMIT 1
        """, (dom,)).fetchone()
        if dup:
            return None

    lead_id = str(uuid.uuid4())
    conn.execute("""
        INSERT INTO sales_leads (
          id, rep_id, company_id, company_name, domain, website, city, state,
          company_type, lead_source, contact_name, contact_title, contact_email, contact_phone,
          stage, notes, duplicate_of, linked_company_id
        )
        VALUES (%s,NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'new',%s,NULL,%s)
    """, (
        lead_id,
        sales_company_id,
        (p.get("name") or p.get("company_name") or "Unknown"),
        dom,
        website,
        p.get("city"),
        p.get("state"),
        p.get("company_type") or p.get("type") or "yard",
        p.get("lead_source") or "normalized",
        p.get("contact_name"),
        p.get("contact_title"),
        p.get("contact_email"),
        p.get("contact_phone") or p.get("phone_e164") or p.get("phone"),
        p.get("notes"),
        sales_company_id
    ))
    return lead_id


@app.post("/admin/normalize/run", tags=["Admin","Scraper"], summary="Normalize raw_entities into Sales House Queue")
def normalize_run_to_house_queue(request: Request, run_id: str = Query(..., description="ingest_runs.id")):
    require_admin(request)

    created_companies = 0
    created_house_leads = 0
    skipped = 0

    with db() as conn:
        ensure_sales_tables(conn)

        rows = conn.execute("""
            SELECT id, entity_type, source_url, payload
            FROM raw_entities
            WHERE run_id=%s
            ORDER BY fetched_at ASC
        """, (run_id,)).fetchall()

        for r in rows:
            if r["entity_type"] not in ("company", "location"):
                skipped += 1
                continue

            # payload may already be dict (psycopg jsonb) or string
            p = r["payload"]
            if isinstance(p, str):
                try:
                    p = json.loads(p)
                except Exception:
                    p = {"raw": p}

            # 1) (optional) canonical company spine
            try:
                canon_company_id = upsert_company(conn, {
                    "name": p.get("name") or p.get("company_name"),
                    "domain": _extract_domain(p.get("domain")) or _extract_domain(p.get("website")) or _extract_domain(p.get("contact_email")),
                    "phone_e164": p.get("phone_e164"),
                    "website": p.get("website"),
                    "address1": p.get("address1"),
                    "city": p.get("city"),
                    "state": p.get("state"),
                    "postal": p.get("postal"),
                })
                attach_source(conn, canon_company_id, r["id"], "raw_entities", r.get("source_url"))
                ensure_lead(conn, canon_company_id)
            except Exception:
                # don't block sales CRM if spine insert fails
                pass

            # 2) sales CRM company + house lead
            sales_company_id = _sales_upsert_company_from_payload(conn, p)
            created_companies += 1

            lead_id = _ensure_house_sales_lead(conn, sales_company_id, p)
            if lead_id:
                created_house_leads += 1

    return {
        "ok": True,
        "run_id": run_id,
        "sales_companies_touched": created_companies,
        "house_leads_created": created_house_leads,
        "skipped": skipped
    }
# -------- insert_raw_entity -----------

# -------- Reviews (with moderation pipeline) ---------
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
