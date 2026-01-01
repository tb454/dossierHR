# prep_companies.py
import json, uuid, re

IN = "companies.txt"
OUT = "companies_seed_template.json"

rows = []
with open(IN, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line: continue
        # expected "Name — City" or "Name - City"
        m = re.split(r"\s+—\s+|\s+-\s+", line, maxsplit=1)
        if not m: continue
        name = m[0].strip()
        city = m[1].strip() if len(m) > 1 else None
        rows.append({
            "name": name,
            "city": city,
            "state": "AZ" if city else None,   # default for the first block you pasted; edit as needed
            "notes": None,
            "seeds": [
                # Fill 1–N concrete listing URLs per company, e.g.:
                # {"url": "https://www.example.com/", "scope": "host", "source": "official"},
                # {"url": "https://yelp.com/biz/ez-money-recycling-phoenix", "scope": "host", "source": "yelp"},
                # {"url": "https://www.scrapmonster.com/company/...", "scope": "host", "source": "scrapmonster"},
                # {"url": "https://www.azdps.gov/services/enforcement-services/scrap/stores?...", "scope": "host", "source": "dps"},
            ]
        })

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(rows, f, indent=2)
print(f"Wrote template: {OUT}  (now add URLs under 'seeds' and POST to /admin/companies/bulk_upsert)")
