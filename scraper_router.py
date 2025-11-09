# scraper_router.py
from __future__ import annotations
import uuid, os
from typing import Optional, List
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, Depends
from pydantic import BaseModel, AnyUrl
from datetime import datetime, timedelta

from scraper_core import PoliteSyncCrawler, STORE_HTML, RETENTION_DAYS
from psycopg.rows import dict_row
import psycopg
import json
from urllib.parse import urlparse

# --- add imports ---
from datetime import datetime, timedelta
from urllib.parse import urlparse
import random

GLOBAL_DAILY = int(os.getenv("SCRAPER_GLOBAL_MAX_DAILY_PAGES", "10000"))
PER_HOST_DAILY = int(os.getenv("SCRAPER_PER_HOST_DAILY_PAGES", "50"))
JOB_SHARD = os.getenv("SCRAPER_JOB_SHARD", "0/1")  # "k/n"

def _in_optout(host: str) -> bool:
    with db() as conn:
        r = conn.execute("SELECT 1 FROM scraper_optouts WHERE host=%s", (host,)).fetchone()
        return bool(r)

@router.post("/seeds", dependencies=[Depends(require_admin_dep)], summary="Add crawl seed(s)")
def add_seeds(urls: list[str], scope: str = "host", reason: str | None = None):
    inserted = 0
    with db() as conn:
        for u in urls:
            sid = str(uuid.uuid4())
            conn.execute("INSERT INTO scrape_seeds (id, url, scope, reason) VALUES (%s,%s,%s,%s)", (sid, u, scope, reason))
            pu = urlparse(u)
            conn.execute(
                "INSERT INTO scrape_frontier (id, seed_id, url, host, scope, priority) VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (str(uuid.uuid4()), sid, u, pu.netloc.lower(), scope, 50)
            )
            inserted += 1
    return {"ok": True, "inserted": inserted, "scope": scope}

@router.post("/optout/{host}", dependencies=[Depends(require_admin_dep)], summary="Opt-out a host globally")
def optout(host: str, reason: str | None = None):
    with db() as conn:
        conn.execute("INSERT INTO scraper_optouts (host, reason) VALUES (%s,%s) ON CONFLICT (host) DO UPDATE SET reason=EXCLUDED.reason", (host.lower(), reason))
        conn.execute("DELETE FROM scrape_frontier WHERE host=%s", (host.lower(),))
    return {"ok": True}

def _take_shard(host: str) -> bool:
    k, n = JOB_SHARD.split("/", 1)
    k, n = int(k), int(n)
    return (hash(host) % n) == k

@router.post("/run_scheduler", dependencies=[Depends(require_admin_dep)], summary="Run scheduled crawl (budgeted, polite)")
def run_scheduler(batch: int = 500):
    """Pulls a budgeted set of URLs from frontier, crawls, and enqueues discovered same-scope links."""
    # 1) select candidates within schedule window, respecting shard
    now = datetime.utcnow()
    taken = 0
    with db() as conn:
        # global budget (simple)
        today = conn.execute("SELECT COUNT(*) AS c FROM scrape_results WHERE fetched_at::date = CURRENT_DATE").fetchone()["c"]
        remaining = max(GLOBAL_DAILY - int(today or 0), 0)
        if remaining <= 0:
            return {"ok": True, "skipped": "daily budget reached"}

        rows = conn.execute("""
           SELECT id, seed_id, url, host, scope
             FROM scrape_frontier
            WHERE next_earliest <= NOW()
            ORDER BY priority ASC, next_earliest ASC
            LIMIT %s
        """, (min(batch, remaining),)).fetchall()

    crawler = PoliteSyncCrawler()
    enqueued = 0
    crawled = 0
    for r in rows:
        if not _take_shard(r["host"]): 
            continue
        if _in_optout(r["host"]): 
            continue

        rec, err = crawler.fetch(r["url"])
        crawled += 1 if rec else 0

        with db() as conn:
            # remove from frontier
            conn.execute("DELETE FROM scrape_frontier WHERE id=%s", (r["id"],))
            if rec:
                _insert_result(r["seed_id"], rec)  # reuse existing helper with task_id=seed_id

                # host/day budget check
                dayhost = conn.execute("""
                    SELECT COUNT(*) AS c FROM scrape_results 
                     WHERE host=%s AND fetched_at::date = CURRENT_DATE
                """, (r["host"],)).fetchone()["c"]
                if dayhost and int(dayhost) >= PER_HOST_DAILY:
                    continue

                # enqueue same-scope discoveries
                from .scraper_router import _within_scope  # if same file, remove this import
                for link in (rec.get("links_sample") or []):
                    if _within_scope(r["url"], link, r["scope"]):
                        pu = urlparse(link)
                        if _in_optout(pu.netloc.lower()):
                            continue
                        conn.execute("""
                           INSERT INTO scrape_frontier (id, seed_id, url, host, scope, priority, next_earliest)
                           VALUES (%s,%s,%s,%s,%s,%s,%s)
                           ON CONFLICT DO NOTHING
                        """, (str(uuid.uuid4()), r["seed_id"], link, pu.netloc.lower(), r["scope"], 100, now + timedelta(minutes=random.randint(1,60))))
                        enqueued += 1

    return {"ok": True, "crawled": crawled, "enqueued": enqueued, "shard": JOB_SHARD}

# We'll use the same env DATABASE_URL as your app
DATABASE_URL = os.getenv("DATABASE_URL")

router = APIRouter(prefix="/scraper", tags=["Scraper"])

def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL missing")
    return psycopg.connect(DATABASE_URL, autocommit=True, row_factory=dict_row)

# ---- Admin dependency (imported from main file in-wire, see patch step) ----
def require_admin_dep(req: Request):
    role = req.session.get("role")
    if role != "admin":
        raise HTTPException(403, "Admin only")
    return True

# ---- Schemas ----
class TaskCreate(BaseModel):
    seed_url: AnyUrl
    max_pages: int = 10
    scope: str = "host"     # host | domain | path | any
    notes: Optional[str] = None

class Task(BaseModel):
    id: str
    seed_url: str
    status: str
    max_pages: int
    scope: str
    notes: Optional[str] = None

class Result(BaseModel):
    url: str
    status_code: int | None
    title: str | None
    description: str | None
    canonical_url: str | None
    robots_allowed: bool
    fetched_at: str
    host: str

# ---- Helpers ----
def _insert_task(task_id, seed_url, max_pages, scope, notes):
    with db() as conn:
        conn.execute("""
            INSERT INTO scrape_tasks (id, seed_url, max_pages, scope, notes, status)
            VALUES (%s,%s,%s,%s,%s,'queued')
        """, (task_id, seed_url, max_pages, scope, notes))

def _update_task_status(task_id, status, error=None):
    with db() as conn:
        conn.execute("UPDATE scrape_tasks SET status=%s, error=%s WHERE id=%s", (status, error, task_id))

def _insert_result(task_id, rec):
    with db() as conn:
        try:
            conn.execute("""
                INSERT INTO scrape_results
                  (id, task_id, url, host, status_code, fetched_at, robots_allowed, robots_txt,
                   user_agent_used, content_hash, title, description, canonical_url, meta, links_sample, stored_html, html)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                f"{task_id}:{rec['url']}", task_id, rec["url"], rec["host"], rec["status_code"],
                rec["fetched_at"], rec["robots_allowed"], rec["robots_txt"],
                rec["user_agent_used"], rec["content_hash"], rec["title"], rec["description"],
                rec["canonical_url"], json.dumps(rec["meta"]), json.dumps(rec["links_sample"]),
                rec["stored_html"], rec["html"]
            ))
        except Exception:
            # dedupe or harmless failures
            pass

def _purge_old_html():
    if not STORE_HTML or RETENTION_DAYS <= 0:
        return
    cutoff = datetime.utcnow() - timedelta(days=RETENTION_DAYS)
    with db() as conn:
        conn.execute("""
            UPDATE scrape_results
               SET html=NULL, stored_html=FALSE
             WHERE stored_html=TRUE AND fetched_at < %s
        """, (cutoff,))

def _within_scope(seed: str, link: str, scope: str) -> bool:
    s = urlparse(seed)
    u = urlparse(link)
    if scope == "any": return True
    if scope == "host":
        return u.netloc == s.netloc
    if scope == "domain":
        sh = s.netloc.split(".")
        uh = u.netloc.split(".")
        return sh[-1:] == uh[-1:] and (sh[-2:] == uh[-2:] if len(sh)>1 and len(uh)>1 else u.netloc==s.netloc)
    if scope == "path":
        return str(link).startswith(str(seed).rstrip("/") + "/")
    return False

# ---- Crawl runner ----
def run_task(task_id: str, seed_url: str, max_pages: int, scope: str):
    crawler = PoliteSyncCrawler()
    seen: set[str] = set()
    queue: List[str] = [seed_url]

    _update_task_status(task_id, "running")
    try:
        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            rec, err = crawler.fetch(url)
            if rec:
                _insert_result(task_id, rec)
                for link in (rec.get("links_sample") or []):
                    if _within_scope(seed_url, link, scope):
                        queue.append(link)
        _update_task_status(task_id, "done")
    except Exception as e:
        _update_task_status(task_id, "error", error=str(e)[:2000])
    finally:
        _purge_old_html()

# ---- Routes (admin only) ----
@router.post("/tasks", response_model=Task, dependencies=[Depends(require_admin_dep)], summary="Queue a compliant crawl task")
def create_task(body: TaskCreate, bg: BackgroundTasks):
    tid = str(uuid.uuid4())
    _insert_task(tid, str(body.seed_url), body.max_pages, body.scope, body.notes)
    bg.add_task(run_task, tid, str(body.seed_url), body.max_pages, body.scope)
    with db() as conn:
        row = conn.execute("SELECT * FROM scrape_tasks WHERE id=%s", (tid,)).fetchone()
    return Task(id=row["id"], seed_url=row["seed_url"], status=row["status"],
                max_pages=row["max_pages"], scope=row["scope"], notes=row["notes"])

@router.get("/tasks/{task_id}", response_model=Task, dependencies=[Depends(require_admin_dep)], summary="Get task status")
def get_task(task_id: str):
    with db() as conn:
        row = conn.execute("SELECT * FROM scrape_tasks WHERE id=%s", (task_id,)).fetchone()
    if not row: raise HTTPException(404, "task not found")
    return Task(id=row["id"], seed_url=row["seed_url"], status=row["status"],
                max_pages=row["max_pages"], scope=row["scope"], notes=row["notes"])

@router.get("/tasks/{task_id}/results", response_model=list[Result], dependencies=[Depends(require_admin_dep)], summary="List crawl results")
def list_results(task_id: str, limit: int = Query(200, le=1000)):
    with db() as conn:
        rows = conn.execute(
            "SELECT url,status_code,title,description,canonical_url,robots_allowed,fetched_at,host FROM scrape_results WHERE task_id=%s ORDER BY fetched_at DESC LIMIT %s",
            (task_id, limit)
        ).fetchall()
    return [
        Result(url=r["url"], status_code=r["status_code"], title=r["title"], description=r["description"],
               canonical_url=r["canonical_url"], robots_allowed=r["robots_allowed"],
               fetched_at=r["fetched_at"].isoformat() + "Z", host=r["host"])
        for r in rows
    ]
