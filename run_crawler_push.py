import os, json, time, uuid
from typing import List, Dict, Any, Optional
import requests

# ---- CONFIG ----
API_BASE = os.getenv("DOSSIER_API_BASE", "http://127.0.0.1:8081").rstrip("/")
INGEST_TOKEN = os.getenv("INGEST_WEBHOOK_SECRET", "")  # must match backend env
RUN_ID = os.getenv("INGEST_RUN_ID", "")               # set this from /admin/ingest/start
BATCH_SIZE = int(os.getenv("INGEST_BATCH_SIZE", "50"))
SLEEP_BETWEEN = float(os.getenv("INGEST_SLEEP", "0.2"))

# If your crawler outputs a JSON file already, set this path:
INPUT_JSONL = os.getenv("CRAWLER_JSONL", "crawler_out.jsonl")  # one JSON object per line


def die(msg: str):
    raise SystemExit(msg)


def post_batch(run_id: str, entities: List[Dict[str, Any]]):
    url = f"{API_BASE}/ingest/raw_entities"
    headers = {
        "Content-Type": "application/json",
        "X-Ingest-Token": INGEST_TOKEN,
    }
    payload = {"run_id": run_id, "entities": entities}
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)
    if r.status_code >= 400:
        raise RuntimeError(f"POST {url} failed {r.status_code}: {r.text}")
    return r.json()


def to_entity(rec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize your crawler record into the ingestion schema.
    This is intentionally tolerant: just pass what you have in payload.
    """
    source_url = rec.get("source_url") or rec.get("website") or rec.get("url") or ""
    payload = dict(rec)

    # minimal: make sure "name" exists if possible
    if "name" not in payload and "company_name" in payload:
        payload["name"] = payload["company_name"]

    return {
        "entity_type": "company",
        "source_url": source_url,
        "payload": payload,
    }


def read_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def main():
    if not RUN_ID:
        die("Missing INGEST_RUN_ID env var (set it to the run_id from /admin/ingest/start).")
    if not INGEST_TOKEN:
        die("Missing INGEST_WEBHOOK_SECRET env var (must match backend INGEST_WEBHOOK_SECRET).")

    # Load records produced by your crawler
    records = list(read_jsonl(INPUT_JSONL))
    if not records:
        die(f"No records found in {INPUT_JSONL}")

    entities = [to_entity(r) for r in records]

    # Push in batches
    sent = 0
    for i in range(0, len(entities), BATCH_SIZE):
        batch = entities[i:i+BATCH_SIZE]
        out = post_batch(RUN_ID, batch)
        sent += len(batch)
        print(f"[OK] pushed {len(batch)} (total {sent}) -> {out}")
        time.sleep(SLEEP_BETWEEN)

    print(f"DONE. Pushed {sent} entities into run_id={RUN_ID}.")


if __name__ == "__main__":
    main()
