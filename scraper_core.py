# scraper_core.py (sync + psycopg friendly)
from __future__ import annotations
import os, time, json, hashlib, re
from datetime import datetime, timedelta
from typing import Tuple, List, Dict, Optional
from urllib.parse import urlparse, urljoin

import httpx
from bs4 import BeautifulSoup
from robotexclusionrulesparser import RobotExclusionRulesParser as Rerp

UA = os.getenv("SCRAPER_USER_AGENT", "DossierBot/1.0 (+contact: legal@localhost)")
MAX_RPS = float(os.getenv("SCRAPER_MAX_RPS_PER_HOST", "1.0"))
CONNECT_TIMEOUT = float(os.getenv("SCRAPER_CONNECT_TIMEOUT", "10"))
READ_TIMEOUT = float(os.getenv("SCRAPER_READ_TIMEOUT", "20"))
BACKOFF_BASE = float(os.getenv("SCRAPER_BACKOFF_BASE", "0.5"))
STORE_HTML = os.getenv("SCRAPER_STORE_FULL_HTML", "0") == "1"
RETENTION_DAYS = int(os.getenv("SCRAPER_HTML_RETENTION_DAYS", "7"))
ALLOWLIST = {d.strip().lower() for d in os.getenv("SCRAPER_ALLOWLIST_DOMAINS", "").split(",") if d.strip()}
BLOCKLIST = {d.strip().lower() for d in os.getenv("SCRAPER_BLOCKLIST_DOMAINS", "").split(",") if d.strip()}

class PoliteSyncCrawler:
    def __init__(self):
        self.client = httpx.Client(follow_redirects=True, timeout=httpx.Timeout(CONNECT_TIMEOUT, read=READ_TIMEOUT))
        self.robots_cache: Dict[str, Tuple[Rerp, str, float]] = {}  # host -> (parser, txt, fetched_ts)
        self.last_hit: Dict[str, float] = {}  # host -> epoch seconds

    def _allowed_by_domain_policies(self, host: str) -> bool:
        h = host.lower()
        if BLOCKLIST and (h in BLOCKLIST or any(h.endswith("." + b) for b in BLOCKLIST)):
            return False
        if ALLOWLIST and not (h in ALLOWLIST or any(h.endswith("." + a) for a in ALLOWLIST)):
            return False
        return True

    def _throttle(self, host: str):
        if MAX_RPS <= 0: return
        min_interval = 1.0 / max(0.1, MAX_RPS)
        last = self.last_hit.get(host, 0.0)
        now = time.time()
        wait = (last + min_interval) - now
        if wait > 0:
            time.sleep(wait)
        self.last_hit[host] = time.time()

    def _get_robots(self, scheme: str, host: str) -> Tuple[Rerp, str]:
        if host in self.robots_cache and (time.time() - self.robots_cache[host][2]) < 3600:
            rp, txt, _ = self.robots_cache[host]
            return rp, txt
        robots_url = f"{scheme}://{host}/robots.txt"
        txt = ""
        try:
            r = self.client.get(robots_url, headers={"User-Agent": UA})
            if r.status_code == 200 and r.text:
                txt = r.text
        except Exception:
            txt = ""
        rp = Rerp(); rp.user_agent = UA; rp.parse(txt or "")
        self.robots_cache[host] = (rp, txt, time.time())
        return rp, txt

    def _extract(self, url: str, html: str):
        soup = BeautifulSoup(html, "html.parser")
        # meta robots
        meta_robots = ",".join([m.get("content","") for m in soup.find_all("meta", attrs={"name": re.compile(r"robots", re.I)})]).lower()

        title = soup.title.string.strip() if soup.title and soup.title.string else None
        desc = None
        m = soup.find("meta", attrs={"name":"description"})
        if m and m.get("content"): desc = m["content"].strip()[:1024]

        # og/twitter
        meta = {}
        for p in soup.find_all("meta"):
            k = p.get("property") or p.get("name")
            v = p.get("content")
            if k and v:
                k = k.strip().lower()
                if k.startswith(("og:", "twitter:", "article:", "profile:", "product:")):
                    meta[k] = v.strip()

        # canonical
        canonical_url = None
        lc = soup.find("link", rel=lambda x: x and "canonical" in x.lower())
        if lc and lc.get("href"):
            canonical_url = urljoin(url, lc["href"])

        # json-ld types sample
        ld_types = []
        for s in soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(s.string or "")
                if isinstance(data, dict) and "@type" in data:
                    ld_types.append(data["@type"])
                elif isinstance(data, list):
                    for it in data:
                        if isinstance(it, dict) and "@type" in it:
                            ld_types.append(it["@type"])
            except Exception:
                pass
        if ld_types:
            meta["ld_types"] = ld_types[:10]

        links = []
        for a in soup.find_all("a", href=True):
            href = urljoin(url, a["href"])
            if href.startswith(("mailto:", "javascript:")):
                continue
            links.append(href)
            if len(links) >= 20:
                break

        return {
            "title": (title or "")[:512] or None,
            "description": desc,
            "canonical_url": canonical_url,
            "meta": meta,
            "meta_robots": meta_robots
        }, links

    def fetch(self, url: str):
        pu = urlparse(url)
        if pu.scheme not in ("http", "https"):
            return None, "unsupported_scheme"
        host = pu.netloc.lower()
        if not self._allowed_by_domain_policies(host):
            return None, "blocked_by_domain_policy"

        rp, robots_txt = self._get_robots(pu.scheme, host)
        path = pu.path or "/"
        if not rp.is_allowed(UA, path):
            # no fetch; return provenance only
            return {
                "url": url, "host": host, "status_code": None, "fetched_at": datetime.utcnow(),
                "robots_allowed": False, "robots_txt": robots_txt, "user_agent_used": UA,
                "content_hash": None, "title": None, "description": None, "canonical_url": None,
                "meta": {}, "links_sample": [], "stored_html": False, "html": None
            }, "robots_disallow"

        backoff = BACKOFF_BASE
        for _ in range(4):
            try:
                self._throttle(host)
                r = self.client.get(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml"})
                status = r.status_code
                html = r.text if r.headers.get("content-type","").startswith("text/html") else ""
                content_hash = hashlib.sha256(html.encode("utf-8")).hexdigest() if html else None
                rec = {
                    "url": str(r.request.url), "host": host, "status_code": status, "fetched_at": datetime.utcnow(),
                    "robots_allowed": True, "robots_txt": robots_txt, "user_agent_used": UA,
                    "content_hash": content_hash, "title": None, "description": None, "canonical_url": None,
                    "meta": {}, "links_sample": [], "stored_html": False, "html": None
                }
                if html:
                    meta, links = self._extract(str(r.request.url), html)
                    rec["title"] = meta["title"]
                    rec["description"] = meta["description"]
                    rec["canonical_url"] = meta["canonical_url"]
                    rec["meta"] = meta["meta"]
                    rec["links_sample"] = links
                    if STORE_HTML:
                        rec["stored_html"] = True
                        rec["html"] = html[:1_000_000]
                return rec, None
            except Exception:
                time.sleep(backoff)
                backoff *= 2
        return None, "fetch_failed"
