import csv, io, json, asyncio, time
from typing import Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, Query, Request
from psycopg.rows import dict_row
import psycopg

from yard_crawler import crawl_from_rows, summarize_for_sales  # <-- from your crawler module

router = APIRouter(prefix="/sales", tags=["Sales Leads"])

def canon_host(url: str) -> str:
    url = (url or "").strip()
    url = url.replace("https://", "").replace("http://", "")
    url = url.split("/")[0].lower()
    if url.startswith("www."):
        url = url[4:]
    return url

def canon_root(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith("http"):
        url = "https://" + url
    host = canon_host(url)
    return f"https://{host}" if host else ""

def region_from_state(state: str) -> str:
    s = (state or "").upper().strip()
    PAC = {"CA","OR","WA","HI","AK"}
    MTN = {"AZ","NV","UT","CO","NM","ID","WY","MT"}
    TXG = {"TX","OK","LA","AR"}
    MW  = {"ND","SD","NE","KS","MN","IA","MO"}
    GL  = {"IL","IN","MI","OH","WI"}
    MANE= {"NY","NJ","PA","CT","RI","MA","VT","NH","ME","DE","MD","DC"}
    SE  = {"VA","WV","NC","SC","GA","FL","AL","MS","TN","KY"}
    if s in PAC: return "PAC"
    if s in MTN: return "MTN"
    if s in TXG: return "TXG"
    if s in MW:  return "MW-WNC"
    if s in GL:  return "GL-ENC"
    if s in MANE:return "MANE"
    if s in SE:  return "SE"
    return "?"

def get_db():
    # You already use psycopg in this repo; keep it consistent.
    # Expect DATABASE_URL in env like your other backends.
    import os
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg.connect(dsn, row_factory=dict_row)

def require_sales_role(request: Request):
    # Adjust these keys to match how you store session auth in dossier_hr_backend.py
    role = (request.session.get("role") or "").lower()
    if role not in ("admin","sales_manager","sales_rep"):
        raise HTTPException(status_code=403, detail="Sales access required")
    return role

@router.post("/seeds/import")
async def import_seeds(request: Request, file: UploadFile = File(...)):
    require_sales_role(request)

    raw = await file.read()
    try:
        rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8"))))
    except Exception:
        raise HTTPException(400, "CSV parse failed (need header: Name,Website)")

    to_upsert = []
    for r in rows:
        name = (r.get("Name") or "").strip()
        site = canon_root(r.get("Website") or "")
        if not site:
            continue
        host = canon_host(site)
        to_upsert.append((host, site, name))

    if not to_upsert:
        return {"inserted": 0}

    with get_db() as conn:
        with conn.cursor() as cur:
            for host, root, name_seed in to_upsert:
                cur.execute("""
                  insert into sales_sites (host, root, name_seed, crawl_status, updated_at)
                  values (%s,%s,%s,'new', now())
                  on conflict (host) do update set
                    root=excluded.root,
                    name_seed=coalesce(sales_sites.name_seed, excluded.name_seed),
                    updated_at=now();
                """, (host, root, name_seed))
        conn.commit()

    return {"inserted": len(to_upsert)}

@router.post("/crawl/run")
async def crawl_run(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    region: Optional[str] = Query(None),
):
    require_sales_role(request)

    # pick next batch from DB
    with get_db() as conn:
        with conn.cursor() as cur:
            if region:
                cur.execute("""
                  select host, coalesce(name_seed, root) as name, root
                  from sales_sites
                  where (
                    crawl_status in ('new','error')
                    or (crawl_status='queued' and updated_at < now() - interval '30 minutes')
                  ) and region=%s
                  order by updated_at asc
                  limit %s
                """, (region, limit))
            else:
                cur.execute("""
                  select host, coalesce(name_seed, root) as name, root
                  from sales_sites
                  where (
                    crawl_status in ('new','error')
                    or (crawl_status='queued' and updated_at < now() - interval '30 minutes')
                  )
                  order by updated_at asc
                  limit %s
                """, (limit,))
            batch = cur.fetchall()

        if not batch:
            return {"status": "nothing_to_crawl", "picked": 0}

        # mark queued immediately
        with conn.cursor() as cur:
            for r in batch:
                cur.execute("update sales_sites set crawl_status='queued', updated_at=now() where host=%s", (r["host"],))
        conn.commit()

    # run crawl async (keeps request quick)
    async def _do():
        # convert to (Name, Website) rows
        rows = [(r["name"], r["root"]) for r in batch]
        results = await crawl_from_rows(rows)

        with get_db() as conn2:
            with conn2.cursor() as cur2:
                for rec in results:
                    sales = summarize_for_sales(rec)
                    host = sales["host"]
                    if not host:
                        continue

                    # infer region from first address state if present
                    final_region = sales.get("region") or "?"
                    addrs = sales.get("addresses") or []
                    if final_region == "?" and addrs:
                        st = (addrs[0].get("region") or "").upper()
                        final_region = region_from_state(st)

                    status = "done" if (sales.get("emails") or sales.get("phones") or addrs) else "done"

                    cur2.execute("""
                      update sales_sites set
                        root=%s,
                        name_seed=coalesce(name_seed, %s),
                        region=%s,
                        contact_page=%s,
                        emails=%s::jsonb,
                        phones=%s::jsonb,
                        socials=%s::jsonb,
                        addresses=%s::jsonb,
                        hours=%s::jsonb,
                        also_known_as=%s::jsonb,
                        crawl_status=%s,
                        last_error=null,
                        last_crawled_at=now(),
                        updated_at=now()
                      where host=%s
                    """, (
                        sales.get("root"),
                        sales.get("name_guess"),
                        final_region,
                        sales.get("contact_page"),
                        json.dumps(sales.get("emails") or []),
                        json.dumps(sales.get("phones") or []),
                        json.dumps(sales.get("socials") or {}),
                        json.dumps(addrs),
                        json.dumps(sales.get("hours") or []),
                        json.dumps(rec.get("also_known_as") or []),
                        status,
                        host
                    ))

                    # pages (optional)
                    for p in rec.get("pages", []):
                        cur2.execute("""
                          insert into sales_pages (host, url, title, emails, phones)
                          values (%s,%s,%s,%s::jsonb,%s::jsonb)
                        """, (
                            host,
                            p.get("url"),
                            p.get("title"),
                            json.dumps(p.get("emails") or []),
                            json.dumps(p.get("phones") or [])
                        ))

            conn2.commit()

    asyncio.create_task(_do())
    return {"status": "started", "picked": len(batch)}

@router.get("/leads")
async def list_leads(
    request: Request,
    region: Optional[str] = None,
    status: Optional[str] = None,
    has_email: Optional[bool] = None,
    has_phone: Optional[bool] = None,
    q: Optional[str] = None,
):
    require_sales_role(request)

    where = []
    args = []

    if region:
        where.append("s.region=%s")
        args.append(region)
    if status:
        where.append("s.crawl_status=%s")
        args.append(status)
    if has_email is True:
        where.append("jsonb_array_length(s.emails) > 0")
    if has_email is False:
        where.append("jsonb_array_length(s.emails) = 0")
    if has_phone is True:
        where.append("jsonb_array_length(s.phones) > 0")
    if has_phone is False:
        where.append("jsonb_array_length(s.phones) = 0")
    if q:
        where.append("(coalesce(s.name_seed,'') ilike %s or s.root ilike %s)")
        args.extend([f"%{q}%", f"%{q}%"])

    sql = """
      select
        s.host, s.root, s.name_seed, s.region, s.contact_page,
        s.emails, s.phones, s.socials, s.addresses, s.hours,
        s.crawl_status, s.last_crawled_at,
        w.assigned_to, w.stage, w.notes
      from sales_sites s
      left join sales_lead_work w on w.host = s.host
    """
    if where:
        sql += " where " + " and ".join(where)
    sql += " order by s.region, coalesce(s.name_seed, s.root) limit 2000"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, args)
            rows = cur.fetchall()
    return {"rows": rows}

@router.post("/leads/{host}/assign")
async def assign_lead(request: Request, host: str, assigned_to: str):
    role = require_sales_role(request)
    if role not in ("admin","sales_manager"):
        raise HTTPException(403, "sales_manager or admin required")

    host = host.lower().strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
              insert into sales_lead_work (host, assigned_to, updated_at)
              values (%s,%s, now())
              on conflict (host) do update set assigned_to=excluded.assigned_to, updated_at=now()
            """, (host, assigned_to))
        conn.commit()
    return {"ok": True}

@router.patch("/leads/{host}")
async def update_lead(request: Request, host: str, stage: Optional[str]=None, notes: Optional[str]=None):
    require_sales_role(request)
    host = host.lower().strip()

    sets = []
    args = []

    if stage:
        sets.append("stage=%s")
        args.append(stage)
    if notes is not None:
        sets.append("notes=%s")
        args.append(notes)

    if not sets:
        return {"ok": True}

    args.append(host)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
              insert into sales_lead_work (host, stage, notes, updated_at)
              values (%s, coalesce(%s,'new'), %s, now())
              on conflict (host) do update set {", ".join(sets)}, updated_at=now()
            """, (host, stage or "new", notes))
        conn.commit()

    return {"ok": True}
