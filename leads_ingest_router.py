# leads_ingest_router.py
import os, hmac, hashlib, json
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel, Field

router = APIRouter(prefix="/leads", tags=["Leads"])

LEADS_INGEST_SECRET = os.getenv("LEADS_INGEST_SECRET", "")

class LeadIn(BaseModel):
    company_name: str = Field(..., min_length=1)
    website: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    source: Optional[str] = "crawler"
    notes: Optional[str] = None

class LeadsIngestPayload(BaseModel):
    leads: List[LeadIn]

def _verify_hmac(raw_body: bytes, signature: str) -> None:
    if not LEADS_INGEST_SECRET:
        raise HTTPException(status_code=500, detail="LEADS_INGEST_SECRET not set on server")
    mac = hmac.new(LEADS_INGEST_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, (signature or "").strip()):
        raise HTTPException(status_code=401, detail="Invalid signature")

@router.post("/ingest")
async def ingest_leads(request: Request):
    """
    Ingest leads from crawler (JSON) into DB.
    Security: HMAC SHA256 of raw body in header `X-Leads-Signature`.
    """
    raw = await request.body()
    sig = request.headers.get("X-Leads-Signature", "")
    _verify_hmac(raw, sig)

    payload = LeadsIngestPayload.model_validate_json(raw)

    # NOTE: replace this with real DB insert/upsert logic
    # For now, return the count so your crawler knows it worked
    return {"ok": True, "ingested": len(payload.leads), "ts": datetime.utcnow().isoformat() + "Z"}
