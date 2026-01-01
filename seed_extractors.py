# seed_extractors.py
import asyncio, csv, re, json, sys, itertools, os
from typing import List, Dict
import httpx
from selectolax.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlencode

UA = "DossierSeeder/1.1 (+contact: sales@yourdomain.tld)"
TIMEOUT = 20
CONC = 10

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
        r = await client.get(url, timeout=TIMEOUT, headers={"User-Agent":UA}, follow_redirects=True)
        if r.status_code != 200: return ""
        if "text/html" not in r.headers.get("content-type",""):
            return ""
        return r.text
    except Exception:
        return ""

# ---------- Existing adapters (kept) ----------
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

async def scrape_rema_members(client):
    base = "https://isri.org"
    html = await fetch(client, base)
    if not html: return []
    doc = HTMLParser(html)
    rows=[]
    for a in doc.css("a[href]"):
        h=a.attributes.get("href","")
        if h and h.startswith("http") and ("isri.org" not in h) and (".pdf" not in h):
            site=canon(h)
            if site:
                rows.append({"Name": clean_text(a.text()) or site, "Website": site, "Region":"", "Source":"directory:rema"})
    return rows

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
    "iscrapapp.com","scrapmonster.com","yellowpages","angi.com","bbb.org"
)

def likely_company_site(url:str)->bool:
    host = urlparse(url).netloc.lower()
    if not host: return False
    if any(b in host for b in BLOCKED_DOMAINS): return False
    return True

async def ddg_search(client, query:str, max_pages:int=2)->List[str]:
    links=[]
    params={"q":query}
    for page in range(max_pages):
        html = await fetch(client, f"{DDG_HTML}?{urlencode(params)}")
        if not html: break
        doc = HTMLParser(html)
        for a in doc.css("a.result__a"):
            h = a.attributes.get("href","")
            if h and h.startswith("http"):
                links.append(h)
        # pagination link
        nextbtn = doc.css_first("a.result--more__btn")
        if not nextbtn: break
        params["s"] = str((page+1)*30)
    return links

async def scrape_openweb_search(client, states:List[str])->List[Dict]:
    rows=[]
    for st in states:
        tokens = STATE_TOKENS.get(st.upper(), [st])
        for term in SEARCH_TERMS:
            for tok in tokens:
                q = f"{term} {tok}"
                hits = await ddg_search(client, q, max_pages=int(os.getenv("SEED_DDG_PAGES","5")))
                for h in hits:
                    site = canon(h)
                    if not site or not likely_company_site(site):
                        continue
                    rows.append({
                        "Name": site.replace("https://",""),
                        "Website": site,
                        "Region": STATE_TO_REGION.get(st.upper(), ""),
                        "Source": f"search:ddg:{st}:{tok}"
                    })
    return rows

# ---------- NEW adapter 2: State list seeder ----------
# Config of state-level pages that list scrap dealers / recyclers. This is a sampler; extend as you find more.
STATE_LIST_PAGES: Dict[str, List[str]] = {
  "AZ": ["https://www.azdps.gov/services/public/scrap-metal-dealers"],
  "DE": ["https://dsp.delaware.gov/pawnbrokers-secondhand-dealers-scrap-metal-processors/"],
  "GA": ["https://gbi.georgia.gov/services/secondary-metals-recycling"],
  "KS": ["https://www.ag.ks.gov/divisions/civil/licensing-inspections/scrap-metal-dealers"],
  "KY": ["https://metalrecycling.ky.gov/"],
  "MN": ["https://dps.mn.gov/divisions/bca/bca-divisions/investigative-services/scrap-metal"],
  "MS": ["https://www.sos.ms.gov/regulation-enforcement/scrap-metal"],
  "ND": ["https://apps.attorneygeneral.nd.gov/scrap-metal"],
  "OH": ["https://services.dps.ohio.gov/ScrapDealer/Home/FAQ"],
  "TN": ["https://www.tn.gov/commerce/regboards/scrap.html"],
  "WA": ["https://dor.wa.gov/manage-business/state-endorsements/scrap-metal"],
  "WV": ["https://apps.sos.wv.gov/business/scrapmetaldealers/"],
  "TX": ["https://www.tceq.texas.gov/permitting/waste_permits/recycling/scrap_metals.html"],
  "FL": ["https://floridadep.gov/waste/waste-reduction/content/recycling-and-waste-reduction"],
  "CA": ["https://calrecycle.ca.gov/homehazwaste/metal"],
}

def extract_external_sites_from_html(html:str, base:str)->List[Dict]:
    out=[]
    doc = HTMLParser(html)
    for a in doc.css("a[href]"):
        h=a.attributes.get("href","").strip()
        if not h: continue
        if h.startswith("mailto:") or h.startswith("tel:"): continue
        full = urljoin(base, h)
        site = canon(full)
        if not site: continue
        # skip self-domain / social / nav noise
        if urlparse(base).netloc.split(":")[0].lower() in site: 
            continue
        if not likely_company_site(site): 
            continue
        name = clean_text(a.text()) or site.replace("https://","")
        out.append({"Name": name, "Website": site})
    return out

async def scrape_state_lists(client, states:List[str])->List[Dict]:
    rows=[]
    for st in states:
        for url in STATE_LIST_PAGES.get(st.upper(), []):
            html = await fetch(client, url)
            if not html: continue
            ex = extract_external_sites_from_html(html, url)
            for r in ex:
                rows.append({"Name": r["Name"], "Website": r["Website"], "Region": STATE_TO_REGION.get(st.upper(), ""), "Source": f"state:{st}"})
    return rows

# ---------- Orchestrator ----------
async def build_master_seeds(extra_csv=None, out_csv="seeds_all.csv", states_filter:List[str]=None, include_openweb=True, include_state=True):
    rows=[]
    states = [s.upper() for s in (states_filter or STATE_TO_REGION.keys()) if s.upper() in STATE_TO_REGION]

    async with httpx.AsyncClient(http2=True, headers={"User-Agent":UA}) as client:
        tasks = [
            scrape_iscrap(client),
            scrape_scrapmonster(client),
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
    include_openweb = not bool(os.getenv("SEED_NO_OPENWEB"))
    include_state   = not bool(os.getenv("SEED_NO_STATE"))
    out_csv, n = asyncio.run(build_master_seeds(extra_csv=extra, states_filter=states, include_openweb=include_openweb, include_state=include_state))
    print(json.dumps({"out_csv": out_csv, "count": n}, indent=2))
