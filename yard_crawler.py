# yard_crawler.py
import asyncio, re, json, time, itertools
from typing import List, Dict, Optional, Set, Tuple
import httpx
import tldextract
from selectolax.parser import HTMLParser
import extruct
from w3lib.html import get_base_url
import phonenumbers
from urllib.parse import urljoin, urlparse
from slugify import slugify

# ----------------------------
# Config
# ----------------------------
MAX_PAGES_PER_SITE = 12            # keep light; bump if needed
CONCURRENT_SITES    = 12
PER_DOMAIN_RPS      = 1.0          # polite throttle
REQUEST_TIMEOUT_S   = 20
UA = "DossierCrawler/1.0 (+contact: sales@yourdomain.tld)"
RESPECT_ROBOTS = True              # flip False if you truly want "least invasive"

# Pages to try first (most yield):
SEED_PATHS = ["/", "/contact", "/contact-us", "/about", "/locations", "/location", "/services", "/recycling", "/metals", "/sell-to-us", "/hours"]

# Simple sitemap hints:
SITEMAP_PATHS = ["/sitemap.xml", "/sitemap_index.xml"]

# Region mapping ----
STATE_TO_REGION = {
    # PAC
    "CA":"PAC","OR":"PAC","WA":"PAC","HI":"PAC","AK":"PAC",
    # MTN
    "AZ":"MTN","NV":"MTN","UT":"MTN","CO":"MTN","NM":"MTN","ID":"MTN","WY":"MTN","MT":"MTN",
    # TXG
    "TX":"TXG","OK":"TXG","LA":"TXG","AR":"TXG",
    # MW-WNC
    "ND":"MW-WNC","SD":"MW-WNC","NE":"MW-WNC","KS":"MW-WNC","MN":"MW-WNC","IA":"MW-WNC","MO":"MW-WNC",
    # GL-ENC
    "IL":"GL-ENC","IN":"GL-ENC","MI":"GL-ENC","OH":"GL-ENC","WI":"GL-ENC",
    # MANE
    "NY":"MANE","NJ":"MANE","PA":"MANE","CT":"MANE","RI":"MANE","MA":"MANE","VT":"MANE","NH":"MANE","ME":"MANE","DE":"MANE","MD":"MANE","DC":"MANE",
    # SE
    "VA":"SE","WV":"SE","NC":"SE","SC":"SE","GA":"SE","FL":"SE","AL":"SE","MS":"SE","TN":"SE","KY":"SE",
}
NATIONAL_KWS = ("SA RECYCLING","SIMS METAL","RADIUS","SCHNITZER","EMR","OMNISOURCE","ALTER TRADING","PADNOS","PACIFIC STEEL & RECYCLING","CMC RECYCLING","METALX","MERVIS","BEHR IRON","RMG","DJJ","TMS INTERNATIONAL","AMG RESOURCES","GFL")

EMAIL_PAT = re.compile(
    r"((?:[A-Z0-9._%+\-]+|\b[A-Z0-9._%+\-]+\s*(?:\[at\]|\(at\)|\{at\}| at )\s*"
    r"[A-Z0-9.\-]+)\s*(?:@|\[at\]|\(at\)|\{at\}| at )\s*[A-Z0-9.\-]+\.[A-Z]{2,})",
    re.IGNORECASE
)
DEOBF = [(r"\s*\[at\]\s*","@"),(r"\s*\(at\)\s*","@"),(r"\s*\{at\}\s*","@"),(r"\sat\s","@"),(r"\s*\[dot\]\s*","."),(r"\s*\(dot\)\s*",".")]

SOC_KWS = {
    "facebook.com":"facebook","linkedin.com":"linkedin","instagram.com":"instagram",
    "x.com":"twitter","twitter.com":"twitter","youtube.com":"youtube","tiktok.com":"tiktok"
}

CONTACT_KWS = ("contact","locations","location","about","sell","hours","where","visit","yard")

# ----------------------------
# Utils
# ----------------------------
def canon_hostname(url:str)->str:
    p=urlparse(url)
    host=p.netloc.lower()
    if host.startswith("www."): host=host[4:]
    return host

def norm_url(base:str, href:str)->str:
    return urljoin(base, href)

def is_same_site(seed:str, candidate:str)->bool:
    return canon_hostname(seed)==canon_hostname(candidate)

def dedupe(seq): 
    seen=set()
    for x in seq:
        if x not in seen:
            seen.add(x); 
            yield x

def deobfuscate_email(s:str)->str:
    out=s
    for a,b in DEOBF: out=re.sub(a,b,out,flags=re.IGNORECASE)
    return out.replace("(","").replace(")","").replace(" ","")

def extract_emails(text:str)->List[str]:
    raw = [m.group(1) for m in EMAIL_PAT.finditer(text or "")]
    out = []
    bad_prefix = ("your@", "example@", "name@", "test@", "hello@localhost")
    bad_domain = ("example.com", "email.com", "domain.com", "localhost")

    for e in map(deobfuscate_email, raw):
        e = (e or "").strip().lower()
        if "@" not in e:
            continue
        dom = e.split("@")[-1]
        if any(e.startswith(p) for p in bad_prefix):
            continue
        if dom in bad_domain:
            continue
        if "." not in dom:
            continue
        out.append(e)

    return list(dedupe(out))

def extract_phones(text:str)->List[str]:
    nums=set()
    for m in phonenumbers.PhoneNumberMatcher(text or "", "US"):
        nums.add(phonenumbers.format_number(m.number, phonenumbers.PhoneNumberFormat.E164))
    return sorted(nums)

def extract_schema(html:str, url:str)->Dict:
    base = get_base_url(html, url)
    data = extruct.extract(html, base_url=base, syntaxes=["json-ld","microdata","opengraph"], errors="ignore")
    return data or {}

def find_links(doc:HTMLParser, base_url:str)->Tuple[List[str],List[str]]:
    # returns (internal_links, out_links)
    intern, out=[],[]
    for a in doc.css("a[href]"):
        href=a.attributes.get("href","").strip()
        if not href or href.startswith("mailto:"): continue
        u=norm_url(base_url, href)
        (intern if is_same_site(base_url,u) else out).append(u)
    return list(dedupe(intern)), list(dedupe(out))

def score_contact_link(u:str)->int:
    t=u.lower()
    return sum( 1 for k in CONTACT_KWS if f"/{k}" in t or t.endswith(k) )

def guess_region_from_name(name:str)->Optional[str]:
    up=name.upper()
    if any(k in up for k in NATIONAL_KWS): return "NA"
    # quick state code in name "(TX)"
    m=re.search(r"\((AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|IA|ID|IL|IN|KS|KY|LA|MA|MD|ME|MI|MN|MO|MS|MT|NC|ND|NE|NH|NJ|NM|NV|NY|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VA|VT|WA|WI|WV)\)", up)
    if m: return STATE_TO_REGION.get(m.group(1))
    return None

def region_from_address(addr:Dict)->Optional[str]:
    # schema.org postalAddress or text parse for state code
    state = (addr.get("addressRegion") or addr.get("addressRegionCode") or addr.get("region") or "").upper()
    if not state:
        # fallback: try to pull a 2-letter region token
        m=re.search(r"\b(AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|IA|ID|IL|IN|KS|KY|LA|MA|MD|ME|MI|MN|MO|MS|MT|NC|ND|NE|NH|NJ|NM|NV|NY|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VA|VT|WA|WI|WV)\b", " ".join(addr.values()) )
        if m: state=m.group(1)
    return STATE_TO_REGION.get(state) if state else None

# ----------------------------
# Crawl
# ----------------------------
class DomainBucket:
    def __init__(self, host:str):
        self.host=host; self.last=0.0
    async def wait(self):
        delay=max(0.0, (1.0/PER_DOMAIN_RPS) - (time.time()-self.last))
        if delay>0: await asyncio.sleep(delay)
    def stamp(self): self.last=time.time()

async def fetch(client:httpx.AsyncClient, url:str, bucket:DomainBucket)->Optional[str]:
    try:
        await bucket.wait()
        r = await client.get(url, timeout=REQUEST_TIMEOUT_S, headers={"User-Agent":UA})
        bucket.stamp()
        if r.status_code>=400: return None
        ctype=r.headers.get("content-type","")
        if "text/html" not in ctype and "application/xhtml" not in ctype: return None
        return r.text
    except Exception:
        return None

async def robots_ok(client:httpx.AsyncClient, root:str)->bool:
    if not RESPECT_ROBOTS: return True
    robots=urljoin(root, "/robots.txt")
    try:
        r=await client.get(robots, timeout=10, headers={"User-Agent":UA})
        if r.status_code!=200: return True
        # extremely simple: block if a Disallow:/ for '*' covers everything
        if "Disallow: /" in r.text and "User-agent: *" in r.text:
            return False
    except Exception: pass
    return True

async def try_sitemap(client:httpx.AsyncClient, root:str)->List[str]:
    urls=[]
    for path in SITEMAP_PATHS:
        try:
            r=await client.get(urljoin(root, path), timeout=10)
            if r.status_code==200 and "<urlset" in r.text:
                urls += re.findall(r"<loc>(.*?)</loc>", r.text)
        except Exception: pass
    return [u for u in urls if is_same_site(root,u)]

def pick_internal_targets(internal_links:List[str])->List[str]:
    # prioritize contact/locations/about pages
    ranked = sorted(internal_links, key=lambda u: score_contact_link(u), reverse=True)
    out = list(itertools.islice(ranked, 0, MAX_PAGES_PER_SITE-1))
    return out

def parse_company(doc:HTMLParser, url:str)->Dict:
    text = doc.text(separator=" ")
    emails = extract_emails(text)
    phones = extract_phones(text)

    # links: socials + mailto + tel
    socials = {}
    mailto_emails: Set[str] = set()

    for a in doc.css("a[href]"):
        href = a.attributes.get("href")

        if not href or not isinstance(href, str):
            continue
        href = href.strip()
        if not href:
            continue

        low = href.lower()

        # mailto capture
        if low.startswith("mailto:"):
            e = href.split(":", 1)[1].split("?", 1)[0].strip().lower()
            if e and "@" in e:
                mailto_emails.add(e)
            continue

        # tel capture
        if low.startswith("tel:"):
            tel = href.split(":", 1)[1].split("?", 1)[0].strip()
            tel = re.sub(r"[^\d\+]", "", tel)
            if tel:
                try:
                    n = phonenumbers.parse(tel, "US")
                    phones.append(phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164))
                except Exception:
                    pass
            continue

        # socials
        for dom, label in SOC_KWS.items():
            if dom in href:
                socials[label] = href

    # merge mailto emails into extracted emails
    if mailto_emails:
        emails = sorted(set(emails) | set(mailto_emails))

    # normalize phones after tel: additions
    phones = sorted(set(phones))

    # schema.org
    data = extract_schema(doc.html or "", url)
    items = data.get("json-ld", []) + data.get("microdata", [])  # list

    org_names=set()
    addresses=[]
    hours=[]
    locs=[]

    def push_addr(addr):
        if not addr: return
        addresses.append({
            "street": addr.get("streetAddress"),
            "city": addr.get("addressLocality"),
            "region": addr.get("addressRegion"),
            "postal": addr.get("postalCode"),
            "country": addr.get("addressCountry"),
        })

    for it in items:
        if isinstance(it, dict):
            graph = it.get("@graph", [])
            objs = graph if isinstance(graph, list) else [it]
            for obj in objs:
                typ = obj.get("@type")
                if typ in ("Organization","LocalBusiness","AutoRepair","RecyclingCenter","Corporation","Thing"):
                    n=obj.get("name") or obj.get("legalName")
                    if n: org_names.add(n)
                    addr=obj.get("address")
                    if isinstance(addr, dict): push_addr(addr)
                    if "openingHours" in obj:
                        ho = obj.get("openingHours")
                        if isinstance(ho, list): hours += ho
                        elif isinstance(ho, str): hours.append(ho)
                    if "geo" in obj and isinstance(obj["geo"], dict):
                        locs.append({"lat":obj["geo"].get("latitude"),"lon":obj["geo"].get("longitude")})

    return {
        "emails": emails,
        "phones": phones,
        "socials": socials,
        "schema_names": sorted(org_names),
        "addresses": addresses,
        "hours": hours,
        "geos": locs,
    }

def region_from_company(name:str, parsed_blocks:List[Dict])->str:
    # prefer postal address region
    for blk in parsed_blocks:
        for a in blk.get("addresses", []):
            r = region_from_address(a)
            if r: return r
    # fallback on company name hints
    r = guess_region_from_name(name or "")
    return r or "?"

async def crawl_site(client:httpx.AsyncClient, name:str, root:str)->Dict:
    root = root.strip().rstrip("/")
    if not root.startswith("http"): root = "https://" + root
    bucket = DomainBucket(canon_hostname(root))
    result = {
        "seed_name": name,
        "root": root,
        "pages": [],
        "contacts": {"emails":[], "phones":[], "socials":{}},
        "company": {"names":[], "addresses":[], "hours":[], "geos":[]},
        "region": "?",
    }

    if not await robots_ok(client, root):
        result["error"]="robots_disallow"
        return result

    seen: Set[str] = set()
    queue: List[str] = list(dedupe([root] + [urljoin(root,p) for p in SEED_PATHS]))
    # sitemap URLs first
    try:
        sm = await try_sitemap(client, root)
        queue += sm[:8]
    except Exception: pass

    while queue and len(result["pages"]) < MAX_PAGES_PER_SITE:
        url = queue.pop(0)
        if url in seen or not is_same_site(root,url): 
            continue
        seen.add(url)
        html = await fetch(client, url, bucket)
        if not html: 
            continue
        doc = HTMLParser(html)
        text = doc.text(separator=" ")
        parsed = parse_company(doc, url)
        result["pages"].append({"url": url, "title": (doc.css_first("title").text() if doc.css_first("title") else ""), "emails": parsed["emails"], "phones": parsed["phones"]})

        # aggregate
        result["contacts"]["emails"] += parsed["emails"]
        result["contacts"]["phones"] += parsed["phones"]
        result["contacts"]["socials"] |= parsed["socials"]
        result["company"]["names"] += parsed["schema_names"]
        result["company"]["addresses"] += parsed["addresses"]
        result["company"]["hours"] += parsed["hours"]
        result["company"]["geos"] += parsed["geos"]

        # more internal targets (force root + best contact + best about early, but keep full 12-page budget)
        intern, _ = find_links(doc, url)

        def is_contactish(u: str) -> bool:
            t = u.lower()
            return any(k in t for k in ("/contact", "contact-us", "/locations", "/location", "/yards", "/visit", "/hours"))

        def is_aboutish(u: str) -> bool:
            t = u.lower()
            return any(k in t for k in ("/about", "about-us", "/company", "who-we-are", "/team", "/history"))

        if url == root:
            ranked = sorted(intern, key=lambda u: score_contact_link(u), reverse=True)

            best_contact = next((u for u in ranked if is_contactish(u)), None)
            best_about   = next((u for u in ranked if is_aboutish(u)), None)

            # If not discovered as a link, fall back to conventional paths
            if not best_contact:
                best_contact = urljoin(root, "/contact")
            if not best_about:
                best_about = urljoin(root, "/about")

            # Prepend them so they are crawled next (don’t duplicate if already queued/seen)
            prepend = []
            for u in (best_contact, best_about):
                if u and (u not in seen) and (u not in queue) and is_same_site(root, u):
                    prepend.append(u)
            queue = prepend + queue

        # Now keep filling the remaining budget with best-scoring internal links
        remaining = MAX_PAGES_PER_SITE - len(result["pages"])
        if remaining > 0:
            ranked = sorted(intern, key=lambda u: score_contact_link(u), reverse=True)
            ranked = [u for u in ranked if (u not in seen) and (u not in queue)]
            queue += list(itertools.islice(ranked, 0, remaining))

    # finalize
    result["contacts"]["emails"] = sorted(set(result["contacts"]["emails"]))
    result["contacts"]["phones"] = sorted(set(result["contacts"]["phones"]))
    result["company"]["names"] = sorted(set(result["company"]["names"]))
    result["company"]["hours"] = sorted(set(result["company"]["hours"]))
    uniq = {}
    for a in result["company"]["addresses"]:
        key = "|".join([str(a.get("street") or ""), str(a.get("city") or ""), str(a.get("region") or ""), str(a.get("postal") or "")]).lower()
        uniq[key] = a
    result["company"]["addresses"] = list(uniq.values())
    result["region"] = region_from_company(name, [ {"addresses":result["company"]["addresses"]} ]) or "?"

    return result

# ----------------------------
# Public entry points
# ----------------------------
async def crawl_from_rows(rows:List[Tuple[str,str]])->List[Dict]:
    """rows: [(Name, Website), ...]"""
    # group by host (avoid multiple crawls of same domain)
    by_host={}
    for name,site in rows:
        site = site.strip()
        if not site: continue
        if not site.startswith("http"): site="https://"+site
        host = canon_hostname(site)
        by_host.setdefault(host, []).append((name, site))

    sem = asyncio.Semaphore(CONCURRENT_SITES)
    results=[]

    async with httpx.AsyncClient(follow_redirects=True, http2=True, headers={"User-Agent":UA}) as client:
        async def one(host, representative):
            async with sem:
                name, site = representative
                out = await crawl_site(client, name, site)
                # attach host and dedup name if multiple names map to same site
                out["host"]=host
                out["also_known_as"] = sorted({n for n,_ in by_host[host]})
                results.append(out)

        tasks=[]
        for host, tuples in by_host.items():
            # pick first as representative
            tasks.append(asyncio.create_task(one(host, tuples[0])))

        await asyncio.gather(*tasks)
    return results

def summarize_for_sales(rec:Dict)->Dict:
    """Flatten what a rep needs."""
    root = rec["root"]
    phones = rec["contacts"]["phones"]
    emails = rec["contacts"]["emails"]
    socials = rec["contacts"]["socials"]
    names = rec["company"]["names"] or rec["also_known_as"]
    # key contact page
    contact_page = ""
    # Prefer true contact/location pages over "about"
    for p in rec["pages"]:
        u = (p.get("url") or "").lower()
        if any(k in u for k in ("/contact", "contact-us", "/locations", "/location", "/yards", "/visit", "/hours")):
            contact_page = p["url"]; break
    if not contact_page:
        for p in rec["pages"]:
            if score_contact_link(p["url"]) > 0:
                contact_page = p["url"]; break
    return {
        "host": rec.get("host"),
        "root": root,
        "name_guess": (names[0] if names else rec["also_known_as"][0] if rec["also_known_as"] else ""),
        "region": rec["region"],
        "contact_page": contact_page or root,
        "emails": emails,
        "phones": phones,
        "socials": socials,
        "addresses": rec["company"]["addresses"],
        "hours": rec["company"]["hours"],
    }

# CLI helper
if __name__ == "__main__":
    import csv, sys, asyncio, json
    inp = sys.argv[1] if len(sys.argv)>1 else "scrap_yards_full_dedup.csv"
    rows=[]
    with open(inp, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for line in r:
            rows.append((line["Name"], line["Website"]))
    data = asyncio.run(crawl_from_rows(rows))
    sales = [summarize_for_sales(d) for d in data]
    print(json.dumps(sales, indent=2))
