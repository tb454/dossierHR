# seed_extractors.py
import asyncio, csv, re, json, sys, itertools, os
from typing import List, Dict
import httpx
from selectolax.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, unquote

UA = "DossierSeeder/1.1 (+contact: sales@yourdomain.tld)"
TIMEOUT = float(os.getenv("SEED_TIMEOUT", "12"))
CONC = 10

SLEEP = float(os.getenv("SEED_SLEEP", "0.2"))         # request pacing (avoid DDG bans)
MAX_SITES_PER_STATE = int(os.getenv("SEED_MAX_SITES_PER_STATE", "250"))  # cap DDG output per state

def env_flag(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

STATE_TO_REGION = {
  "CA":"PAC","OR":"PAC","WA":"PAC","HI":"PAC","AK":"PAC",
  "AZ":"MTN","NV":"MTN","UT":"MTN","CO":"MTN","NM":"MTN","ID":"MTN","WY":"MTN","MT":"MTN",
  "TX":"TXG","OK":"TXG","LA":"TXG","AR":"TXG",
  "ND":"MW-WNC","SD":"MW-WNC","NE":"MW-WNC","KS":"MW-WNC","MN":"MW-WNC","IA":"MW-WNC","MO":"MW-WNC",
  "IL":"GL-ENC","IN":"GL-ENC","MI":"GL-ENC","OH":"GL-ENC","WI":"GL-ENC",
  "NY":"MANE","NJ":"MANE","PA":"MANE","CT":"MANE","RI":"MANE","MA":"MANE","VT":"MANE","NH":"MANE","ME":"MANE","DE":"MANE","MD":"MANE","DC":"MANE",
  "VA":"SE","WV":"SE","NC":"SE","SC":"SE","GA":"SE","FL":"SE","AL":"SE","MS":"SE","TN":"SE","KY":"SE",
}

def canon(url:str)->str:
    url = (url or "").strip()
    if not url: return ""
    if not re.match(r"^https?://", url): url = "https://" + url
    p = urlparse(url)
    if not p.netloc: return ""
    host = p.netloc.lower()
    if host.startswith("www."): host = host[4:]
    return f"https://{host}"

def clean_text(s:str)->str:
    return re.sub(r"\s+", " ", (s or "").strip())

def region_from_text(txt:str)->str:
    m = re.search(r"\b(AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|IA|ID|IL|IN|KS|KY|LA|MA|MD|ME|MI|MN|MO|MS|MT|NC|ND|NE|NH|NJ|NM|NV|NY|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VA|VT|WA|WI|WV)\b", (txt or "").upper())
    if m: return STATE_TO_REGION.get(m.group(1), "")
    return ""

def dedupe_by_host(rows:List[Dict]):
    seen=set(); out=[]
    for r in rows:
        try:
            host = urlparse(r["Website"]).netloc.lower()
            if host.startswith("www."): host = host[4:]
        except Exception:
            continue
        if not host or host in seen: 
            continue
        seen.add(host); out.append(r)
    return out

async def fetch(client, url):
    try:
        # small pacing/jitter so DDG + directories don't ban you
        await asyncio.sleep(SLEEP)
        r = await client.get(url, timeout=TIMEOUT, headers={"User-Agent": UA}, follow_redirects=True)
        if r.status_code != 200:
            return ""
        ct = (r.headers.get("content-type", "") or "").lower()
        if "text/html" not in ct:
            return ""
        return r.text
    except Exception:
        return ""

# ---------- Existing adapters (kept) ----------
def state_slug(st: str) -> str:
    """
    Converts state code -> iscrap slug, e.g. IN -> indiana, TX -> texas.
    Falls back to STATE_TOKENS if available.
    """
    st = (st or "").upper().strip()
    # Preferred: use full state name token if present
    toks = STATE_TOKENS.get(st, [])
    # pick the longest token that isn't the 2-letter code
    cand = ""
    for t in toks:
        if len(t) > len(cand) and t.upper() != st:
            cand = t
    if not cand:
        # last resort: just return empty
        return ""
    return cand.lower().replace(" ", "-")

def scrapmonster_state_slug(st: str) -> str:
    st = (st or "").upper().strip()
    toks = STATE_TOKENS.get(st, [])
    # pick longest token that isn't just "TX"
    cand = ""
    for t in toks:
        if t.upper() != st and len(t) > len(cand):
            cand = t
    if not cand:
        return ""
    return cand.lower().replace(" ", "-")

async def scrape_iscrap(client):
    seeds = [
        "https://iscrapapp.com/yards/metal/",
        "https://iscrapapp.com/yards/usa/",
    ]
    rows=[]
    for url in seeds:
        html = await fetch(client, url)
        if not html: continue
        doc = HTMLParser(html)
        for a in doc.css("a[href]"):
            href = a.attributes.get("href","")
            if "/yard/" in href or "/company/" in href:
                name = clean_text(a.text())
                sub_html = await fetch(client, urljoin(url, href))
                if not sub_html: continue
                sub = HTMLParser(sub_html)
                site = ""
                for ext in sub.css("a[href]"):
                    h = ext.attributes.get("href","")
                    if h and h.startswith("http") and ("iscrapapp.com" not in h):
                        site = canon(h); break
                if site:
                    rows.append({"Name": name or site, "Website": site, "Region":"", "Source":"directory:iscrap"})
    return rows

async def scrape_iscrap_states(client, states: List[str]) -> List[Dict]:
    """
    Pull yard/company profile pages from iScrap per-state, then extract the official website from each profile page.
    This yields real crawlable websites for your yard_crawler.
    """
    rows: List[Dict] = []
    per_state_cap = int(os.getenv("SEED_ISCRAP_STATE_MAX", "400"))
    sem = asyncio.Semaphore(int(os.getenv("SEED_ISCRAP_PROFILE_CONC", str(CONC))))

    async def extract_site_from_profile(base_url: str, prof_url: str) -> str:
        sub_html = await fetch(client, prof_url)
        if not sub_html:
            return ""
        sub = HTMLParser(sub_html)
        for ext in sub.css("a[href]"):
            h = (ext.attributes.get("href", "") or "").strip()
            if h and h.startswith("http") and ("iscrapapp.com" not in h):
                site = canon(h)
                if site and likely_company_site(site):
                    return site
        return ""

    async def one_profile(st: str, name: str, prof_url: str):
        async with sem:
            site = await extract_site_from_profile(st, prof_url)
            if site:
                rows.append({
                    "Name": name or site.replace("https://", ""),
                    "Website": site,
                    "Region": STATE_TO_REGION.get(st.upper(), ""),
                    "Source": f"directory:iscrap_state:{st}"
                })

    for st in [s.upper().strip() for s in states]:
        slug = state_slug(st)
        if not slug:
            continue
        url = f"https://iscrapapp.com/yards-in/{slug}/"
        html = await fetch(client, url)
        if not html:
            continue

        doc = HTMLParser(html)
        profiles = []
        for a in doc.css("a[href]"):
            href = (a.attributes.get("href", "") or "").strip()
            if "/yard/" in href or "/company/" in href:
                name = clean_text(a.text())
                prof = urljoin(url, href)
                profiles.append((name, prof))

        # de-dupe profile URLs + cap
        seen = set()
        deduped = []
        for name, prof in profiles:
            if prof in seen:
                continue
            seen.add(prof)
            deduped.append((name, prof))
            if len(deduped) >= per_state_cap:
                break

        await asyncio.gather(*(one_profile(st, name, prof) for (name, prof) in deduped))

    return rows

async def scrape_scrapmonster(client):
    list_pages = [f"https://www.scrapmonster.com/companies/country/united-states/metal-recycling/{i}" for i in range(1,8)]
    rows=[]
    for url in list_pages:
        html = await fetch(client, url)
        if not html: continue
        doc = HTMLParser(html)
        for li in doc.css("div.company-info a[href]"):
            href = li.attributes.get("href","")
            if not href or "/company/" not in href: continue
            prof = urljoin(url, href)
            sub_html = await fetch(client, prof)
            if not sub_html: continue
            sub = HTMLParser(sub_html)
            name = clean_text(sub.css_first("h1").text()) if sub.css_first("h1") else ""
            site = ""
            for a in sub.css("a[href]"):
                h=a.attributes.get("href","")
                if h and h.startswith("http") and ("scrapmonster.com" not in h):
                    site = canon(h); break
            if site:
                rows.append({"Name": name or site, "Website": site, "Region":"", "Source":"directory:scrapmonster"})
    return rows

async def scrape_scrapmonster_states(client, states: List[str]) -> List[Dict]:
    """
    ScrapMonster has per-state yard pages. We grab yard names+cities, then resolve official websites via DDG.
    """
    out: List[Dict] = []
    per_state_cap = int(os.getenv("SEED_SCRAPMONSTER_STATE_MAX", "300"))
    resolve_conc = int(os.getenv("SEED_SCRAPMONSTER_RESOLVE_CONC", "8"))
    sem = asyncio.Semaphore(resolve_conc)

    async def resolve_and_add(st: str, name: str, city: str):
        async with sem:
            site = await resolve_company_site(client, name, city, st)
            if site:
                out.append({
                    "Name": clean_text(name) or site.replace("https://", ""),
                    "Website": site,
                    "Region": STATE_TO_REGION.get(st, ""),
                    "Source": f"directory:scrapmonster_state:{st}"
                })

    for st in [s.upper().strip() for s in states]:
        slug = scrapmonster_state_slug(st)
        if not slug:
            continue

        url = f"https://www.scrapmonster.com/scrap-yard/united-states/{slug}/"
        html = await fetch(client, url)
        if not html:
            continue

        doc = HTMLParser(html)

        # Heuristic: yard cards have a main yard link, and usually a city link right after.
        # We'll walk anchors and pair yard name with nearest city text in the same block.
        candidates = []
        for a in doc.css('a[href]'):
            href = (a.attributes.get("href", "") or "").strip()
            txt = clean_text(a.text())
            if not txt:
                continue
            # yard detail links are typically internal /scrap-yard/<slug>
            if href.startswith("/scrap-yard/") and "/united-states/" not in href and "/accepting-material/" not in href:
                # try to find city in nearby container
                city = ""
                box = a.parent
                # climb a bit
                for _ in range(4):
                    if not box:
                        break
                    # look for a city link inside this container
                    for b in box.css("a[href]"):
                        btxt = clean_text(b.text())
                        bhref = (b.attributes.get("href", "") or "").strip()
                        if not btxt or btxt == txt:
                            continue
                        # city links are often short and not "Contact Now"
                        if btxt.lower() in ("contact now", "view more yards"):
                            continue
                        if len(btxt) <= 30:
                            city = btxt
                            break
                    if city:
                        break
                    box = box.parent

                candidates.append((txt, city))

        # de-dupe + cap
        seen = set()
        deduped = []
        for name, city in candidates:
            key = (name.lower(), (city or "").lower())
            if key in seen:
                continue
            seen.add(key)
            deduped.append((name, city))
            if len(deduped) >= per_state_cap:
                break

        await asyncio.gather(*(resolve_and_add(st, n, c) for (n, c) in deduped))

    return out

async def scrape_rema_members(client) -> List[Dict]:
    """
    ReMA Member Directory is member-only, so we seed from public Chapter pages (leadership/company names),
    then resolve official websites via DDG.
    """
    # Only do this for states you actually care about; we’ll key off SEED_STATES if set.
    states_env = os.getenv("SEED_STATES", "").strip()
    wanted = [s.strip().upper() for s in states_env.split(",") if s.strip()] if states_env else []
    wanted = wanted or ["IN", "TX"]  # fallback

    # Chapter pages we can use (public)
    chapter_urls = []
    if "IN" in wanted:
        chapter_urls.append(("IN", "https://www.isri.org/chapter/indiana-chapter/"))
    if "TX" in wanted:
        # Gulf Coast Region covers TX
        chapter_urls.append(("TX", "https://info.isri2.org/chapter/gulf-coast-chapter/"))

    per_chapter_cap = int(os.getenv("SEED_REMA_MAX_PER_CHAPTER", "80"))
    sem = asyncio.Semaphore(int(os.getenv("SEED_REMA_RESOLVE_CONC", "8")))
    out: List[Dict] = []

    def looks_like_company(line: str) -> bool:
        t = (line or "").lower()
        return any(k in t for k in ("recycling", "scrap", "metals", "iron", "salvage", "alloy", "steel", "llc", "inc", "corp", "co."))

    async def resolve_and_add(st: str, company: str):
        async with sem:
            site = await resolve_company_site(client, company, "", st)
            if site:
                out.append({
                    "Name": company,
                    "Website": site,
                    "Region": STATE_TO_REGION.get(st, ""),
                    "Source": f"directory:rema_chapter:{st}"
                })

    for st, url in chapter_urls:
        html = await fetch(client, url)
        if not html:
            continue
        doc = HTMLParser(html)

        # Strategy: company names appear near mailto links or in leadership blocks.
        # We grab text blocks around mailto anchors and extract the best “company-like” line.
        companies = []
        for a in doc.css('a[href^="mailto:"]'):
            box = a.parent
            for _ in range(3):
                if not box:
                    break
                txt = clean_text(box.text())
                if txt and len(txt) < 400:
                    # split into lines-ish chunks
                    parts = [p.strip() for p in re.split(r"\s{2,}|\n|\r|\t", txt) if p.strip()]
                    # pick a company-like candidate that isn't an email
                    for p in parts:
                        if "@" in p:
                            continue
                        if looks_like_company(p) and len(p) <= 80:
                            companies.append(p)
                            break
                box = box.parent

        # de-dupe + cap
        seen = set()
        deduped = []
        for c in companies:
            k = c.lower()
            if k in seen:
                continue
            seen.add(k)
            deduped.append(c)
            if len(deduped) >= per_chapter_cap:
                break

        await asyncio.gather(*(resolve_and_add(st, c) for c in deduped))

    return out

# ---------- NEW adapter 1: Open-web search seeder ----------
# We’ll use DuckDuckGo’s HTML endpoint (lightweight & TOS-friendly scraping) to pull result links.
# Queries look like:  site:.com "scrap metal" (AL|Alabama) contact
DDG_HTML = "https://duckduckgo.com/html/"

SEARCH_TERMS = [
    # core
    '"scrap metal" "contact"',
    '"metal recycling" "contact"',
    '"scrap yard" "contact"',
    '"scrap yard" "phone"',
    '"metal recycling" "phone"',
    '"scrap metal recycling" "hours"',
    '"sell scrap" "phone"',
    '"sell scrap" "contact us"',
    # common business phrases
    '"iron and metal" recycling contact',
    '"scrap iron" "contact"',
    '"aluminum recycling" "contact"',
    '"copper recycling" "contact"',
    '"steel recycling" "contact"',
    '"salvage yard" "scrap metal" contact',
    # patterns likely to expose contact info
    'site:*/contact "scrap" "metal"',
    'site:*/contact "recycling" "metal"',
]

STATE_TOKENS = {
  # 2-letter → printable token combos to bias location
  "AL":["AL","Alabama"], "AK":["AK","Alaska"], "AZ":["AZ","Arizona"], "AR":["AR","Arkansas"],
  "CA":["CA","California"], "CO":["CO","Colorado"], "CT":["CT","Connecticut"], "DE":["DE","Delaware"],
  "DC":["DC","District of Columbia","Washington DC"], "FL":["FL","Florida"], "GA":["GA","Georgia"],
  "HI":["HI","Hawaii"], "ID":["ID","Idaho"], "IL":["IL","Illinois"], "IN":["IN","Indiana"],
  "IA":["IA","Iowa"], "KS":["KS","Kansas"], "KY":["KY","Kentucky"], "LA":["LA","Louisiana"],
  "ME":["ME","Maine"], "MD":["MD","Maryland"], "MA":["MA","Massachusetts"], "MI":["MI","Michigan"],
  "MN":["MN","Minnesota"], "MS":["MS","Mississippi"], "MO":["MO","Missouri"],
  "MT":["MT","Montana"], "NE":["NE","Nebraska"], "NV":["NV","Nevada"], "NH":["NH","New Hampshire"],
  "NJ":["NJ","New Jersey"], "NM":["NM","New Mexico"], "NY":["NY","New York"], "NC":["NC","North Carolina"],
  "ND":["ND","North Dakota"], "OH":["OH","Ohio"], "OK":["OK","Oklahoma"], "OR":["OR","Oregon"],
  "PA":["PA","Pennsylvania"], "RI":["RI","Rhode Island"], "SC":["SC","South Carolina"], "SD":["SD","South Dakota"],
  "TN":["TN","Tennessee"], "TX":["TX","Texas"], "UT":["UT","Utah"], "VT":["VT","Vermont"],
  "VA":["VA","Virginia"], "WA":["WA","Washington"], "WV":["WV","West Virginia"], "WI":["WI","Wisconsin"],
  "WY":["WY","Wyoming"],
}

BLOCKED_DOMAINS = (
    "facebook.com","linkedin.com","instagram.com","x.com","twitter.com","youtube.com",
    "yelp.com","google.com","maps.google","bing.com","wikipedia.org","reddit.com",
    "yellowpages","angi.com","bbb.org"
)

def likely_company_site(url:str)->bool:
    host = urlparse(url).netloc.lower()
    if not host: return False
    if any(b in host for b in BLOCKED_DOMAINS): return False
    return True

async def ddg_search(client, query: str, max_pages: int = 2) -> List[str]:
    """
    DuckDuckGo HTML results sometimes return direct target URLs, and sometimes
    a redirect wrapper like:
      https://duckduckgo.com/l/?uddg=<urlencoded_target>
    This function normalizes both into real target URLs.
    """
    links: List[str] = []
    seen: set[str] = set()

    params = {"q": query}
    for page in range(max_pages):
        html = await fetch(client, f"{DDG_HTML}?{urlencode(params)}")
        if not html:
            break

        doc = HTMLParser(html)

        for a in doc.css("a.result__a"):
            href = (a.attributes.get("href", "") or "").strip()
            if not href:
                continue

            # If it’s a relative link, make it absolute
            if href.startswith("/"):
                href = urljoin("https://duckduckgo.com", href)

            # Handle DDG redirect wrapper
            if "duckduckgo.com/l/" in href:
                try:
                    q = urlparse(href).query
                    uddg = parse_qs(q).get("uddg", [""])[0]
                    if uddg:
                        href = unquote(uddg)
                except Exception:
                    continue

            # Only keep http(s) targets
            if not href.startswith("http"):
                continue

            # De-dupe exact URLs
            if href in seen:
                continue
            seen.add(href)
            links.append(href)

        # pagination link
        nextbtn = doc.css_first("a.result--more__btn")
        if not nextbtn:
            break
        params["s"] = str((page + 1) * 30)

    return links

async def resolve_company_site(client, name: str, city: str, st: str) -> str:
    name = clean_text(name)
    city = clean_text(city)
    st = (st or "").upper().strip()

    if not name:
        return ""

    queries = [
        f"\"{name}\" {city} {st} scrap metal",
        f"\"{name}\" {city} {st} metal recycling",
        f"\"{name}\" {city} {st} contact",
        f"{name} {city} {st} scrap yard",
    ]

    for q in queries:
        hits = await ddg_search(client, q, max_pages=1)
        for h in hits:
            site = canon(h)
            if site and likely_company_site(site):
                return site

    return ""

async def scrape_az_dps_stores(client) -> List[Dict]:
    url = "https://www.azdps.gov/services/enforcement-services/scrap/stores"
    html = await fetch(client, url)
    if not html:
        return []

    doc = HTMLParser(html)
    candidates = []

    # The page is a table; store links are internal, so we resolve websites via DDG.
    for a in doc.css('a[href^="/scrap-metal-store/"], a[href^="/content/scrap-metal-dealer/"]'):
        name = clean_text(a.text())
        if not name:
            continue

        # climb to <tr> then grab TDs for city (2nd cell usually)
        tr = a.parent
        while tr and getattr(tr, "tag", None) != "tr":
            tr = tr.parent

        city = ""
        if tr:
            tds = tr.css("td")
            if len(tds) >= 2:
                city = clean_text(tds[1].text())

        candidates.append((name, city))

    # de-dupe name+city
    seen = set()
    deduped = []
    for n, c in candidates:
        key = (n.lower(), c.lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append((n, c))

    deduped = deduped[:int(os.getenv("SEED_AZ_MAX", "250"))]

    sem = asyncio.Semaphore(int(os.getenv("SEED_AZ_RESOLVE_CONC", "8")))
    out: List[Dict] = []

    async def worker(nm, ct):
        async with sem:
            site = await resolve_company_site(client, nm, ct, "AZ")
            if site:
                out.append({
                    "Name": nm,
                    "Website": site,
                    "Region": STATE_TO_REGION.get("AZ", ""),
                    "Source": "state:AZ:azdps+ddg"
                })

    await asyncio.gather(*(worker(n, c) for (n, c) in deduped))
    return out

async def scrape_openweb_search(client, states:List[str])->List[Dict]:
    rows=[]
    ddg_pages = int(os.getenv("SEED_DDG_PAGES", "2"))  # default DOWN from 5 to avoid bans

    for st in states:
        st = st.upper()
        st_count = 0
        tokens = STATE_TOKENS.get(st, [st])

        for term in SEARCH_TERMS:
            if st_count >= MAX_SITES_PER_STATE:
                break
        for tok in tokens:
            if st_count >= MAX_SITES_PER_STATE:
                break
            for tok in tokens:
                if st_count >= MAX_SITES_PER_STATE:
                    break
            
                q = f"{term} {tok}"
                hits = await ddg_search(client, q, max_pages=ddg_pages)

                for h in hits:
                    if st_count >= MAX_SITES_PER_STATE:
                        break

                    site = canon(h)
                    if not site or not likely_company_site(site):
                        continue

                    rows.append({
                        "Name": site.replace("https://",""),
                        "Website": site,
                        "Region": STATE_TO_REGION.get(st, ""),
                        "Source": f"search:ddg:{st}:{tok}"
                    })
                    st_count += 1

    return rows

# ---------- Scrape ----------
async def scrape_state_lists(client, states: List[str]) -> List[Dict]:
    rows = []
    for st in states:
        st = st.upper()

        # Real public list we can parse → resolve dealer sites
        if st == "AZ":
            rows.extend(await scrape_az_dps_stores(client))
            continue

        # For other states: these pages are compliance/registry info, NOT dealer websites.
        # Don’t treat them as crawlable company sites.
        continue

    return rows

# ---------- Orchestrator ----------
async def build_master_seeds(extra_csv=None, out_csv="seeds_all.csv", states_filter:List[str]=None, include_openweb=True, include_state=True):
    rows=[]
    states = [s.upper() for s in (states_filter or STATE_TO_REGION.keys()) if s.upper() in STATE_TO_REGION]

    async with httpx.AsyncClient(http2=True, headers={"User-Agent":UA}) as client:
        tasks = [
            scrape_iscrap(client),
            scrape_iscrap_states(client, states),
            scrape_scrapmonster(client),
            scrape_scrapmonster_states(client, states),
            scrape_rema_members(client),                    
        ]
        if include_openweb:
            tasks.append(scrape_openweb_search(client, states))
        if include_state:
            tasks.append(scrape_state_lists(client, states))
        batches = await asyncio.gather(*tasks, return_exceptions=True)

        for b in batches:
            if isinstance(b, Exception): 
                continue
            rows.extend(b)

    # merge with any existing seeds you have
    if extra_csv and os.path.exists(extra_csv):
        with open(extra_csv, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                rows.append({
                    "Name": r.get("Name","").strip(),
                    "Website": canon(r.get("Website","").strip()),
                    "Region": (r.get("Region","").strip() or ""),
                    "Source": r.get("Source","seed:manual")
                })

    rows = [r for r in rows if r["Website"]]
    rows = dedupe_by_host(rows)

    # region guess from name if still empty
    for r in rows:
        if not r["Region"]:
            r["Region"] = region_from_text(r["Name"])

    # write CSV
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["Name","Website","Region","Source"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return out_csv, len(rows)

if __name__ == "__main__":
    # Usage:
    #   python seed_extractors.py
    #   python seed_extractors.py my_existing_seeds.csv
    # Env flags:
    #   SEED_STATES="TX,OK,LA,AR"   (limit to states)
    #   SEED_NO_OPENWEB=1           (disable DDG search)
    #   SEED_NO_STATE=1             (disable state list seeder)
    extra = sys.argv[1] if len(sys.argv)>1 else None
    states_env = os.getenv("SEED_STATES","").strip()
    states = [s.strip() for s in states_env.split(",") if s.strip()] if states_env else None
    include_openweb = not env_flag("SEED_NO_OPENWEB")
    include_state   = not env_flag("SEED_NO_STATE")
    out_csv, n = asyncio.run(build_master_seeds(extra_csv=extra, states_filter=states, include_openweb=include_openweb, include_state=include_state))
    print(json.dumps({"out_csv": out_csv, "count": n}, indent=2))
