import os, json, hmac, hashlib
import httpx

API_BASE = os.getenv("DOSSIER_API_BASE", "https://your-render-service.onrender.com")
SECRET = os.getenv("LEADS_INGEST_SECRET", "")
INPUT_JSON = os.getenv("LEADS_INPUT_JSON", "leads.json")

def sign(body: bytes) -> str:
    return hmac.new(SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()

def main():
    if not SECRET:
        raise SystemExit("Set LEADS_INGEST_SECRET in your environment (must match server).")

    with open(INPUT_JSON, "rb") as f:
        raw_leads = json.load(f)

    payload = {"leads": raw_leads}
    body = json.dumps(payload).encode("utf-8")

    headers = {"X-Leads-Signature": sign(body)}

    url = f"{API_BASE}/leads/ingest"
    r = httpx.post(url, content=body, headers=headers, timeout=60)
    print(r.status_code, r.text)
    r.raise_for_status()

if __name__ == "__main__":
    main()
