import os, csv, re
from collections import defaultdict

# =========================
# 1. Canonical patterns
# =========================

CANONICAL_PATTERNS = [
    # --- Mining / majors ---
    ("Freeport",            "Freeport-McMoRan",                 "Mining"),
    ("Pinto Valley",        "Capstone Copper",                  "Mining"),
    ("Capstone Copper",     "Capstone Copper",                  "Mining"),
    ("Barrick",             "Barrick Gold Corporation",         "Mining"),
    ("Nevada Gold Mines",   "Nevada Gold Mines",                "Mining"),
    ("Rio Tinto",           "Rio Tinto",                        "Mining"),
    ("Kennecott",           "Rio Tinto",                        "Mining"),
    ("Climax Molybdenum",   "Freeport-McMoRan",                 "Mining"),
    ("Henderson Molybdenum","Freeport-McMoRan",                 "Mining"),
    ("Stillwater Mine",     "Sibanye-Stillwater",               "Mining"),
    ("Red Dog Mine",        "Teck Resources",                   "Mining"),
    ("Hycroft Mine",        "Hycroft Mining Holding Corporation","Mining"),
    ("Kinross",             "Kinross Gold",                     "Mining"),
    ("KGHM",                "KGHM Polska Miedź",                "Mining"),
    ("North Antelope Rochelle", "Peabody Energy",               "Mining"),
    ("Black Thunder Mine",  "Arch Resources",                   "Mining"),
    ("Aurubis",             "Aurubis AG",                      "Mining"),

    # --- Steel / mills ---
    ("Nucor Steel",         "Nucor Corporation",                "Steel Mill"),
    ("Nucor",               "Nucor Corporation",                "Steel Mill"),
    ("Steel Dynamics",      "Steel Dynamics, Inc.",             "Steel Mill"),
    ("SDI",                 "Steel Dynamics, Inc.",             "Steel Mill"),
    ("CMC Steel",           "Commercial Metals Company",        "Steel Mill"),
    ("CMC Recycling",       "Commercial Metals Company",        "Scrap Yard"),
    ("U.S. Steel",          "United States Steel Corporation",  "Steel Mill"),
    ("US Steel",            "United States Steel Corporation",  "Steel Mill"),
    ("Big River Steel",     "United States Steel Corporation",  "Steel Mill"),
    ("Granite City Works",  "United States Steel Corporation",  "Steel Mill"),
    ("Keetac Mine",         "United States Steel Corporation",  "Mining"),
    ("Minntac Mine",        "United States Steel Corporation",  "Mining"),

    ("Indiana Harbor Works","Cleveland-Cliffs Inc.",            "Steel Mill"),
    ("Burns Harbor Works",  "Cleveland-Cliffs Inc.",            "Steel Mill"),
    ("Cleveland Works",     "Cleveland-Cliffs Inc.",            "Steel Mill"),
    ("Dearborn Works",      "Cleveland-Cliffs Inc.",            "Steel Mill"),
    ("Middletown Works",    "Cleveland-Cliffs Inc.",            "Steel Mill"),
    ("Butler Works",        "Cleveland-Cliffs Inc.",            "Steel Mill"),
    ("Hibbing Taconite",    "Cleveland-Cliffs Inc.",            "Mining"),
    ("Tilden Mine",         "Cleveland-Cliffs Inc.",            "Mining"),
    ("Northshore Mining",   "Cleveland-Cliffs Inc.",            "Mining"),
    ("Empire Mine",         "Cleveland-Cliffs Inc.",            "Mining"),

    ("Novelis",             "Novelis Inc.",                     "Aluminum"),
    ("Aleris",             "Novelis Inc.",                      "Aluminum"),
    ("JW Aluminum",         "JW Aluminum",                      "Aluminum"),
    ("Arconic",             "Arconic Corporation",              "Aluminum"),
    ("Constellium",         "Constellium SE",                   "Aluminum"),
    ("Kaiser Aluminum",     "Kaiser Aluminum",                  "Aluminum"),
    ("California Steel Industries", "California Steel Industries", "Steel Mill"),

    # --- Scrap / yards ---
    ("SA Recycling",        "SA Recycling",                     "Scrap Yard"),
    ("Schnitzer",           "Radius Recycling (Schnitzer Steel)","Scrap Yard"),
    ("Radius Recycling",    "Radius Recycling (Schnitzer Steel)","Scrap Yard"),
    ("OmniSource",          "OmniSource, LLC",                  "Scrap Yard"),
    ("Alter Trading",       "Alter Trading Corporation",        "Scrap Yard"),
    ("River Metals Recycling","River Metals Recycling (RMR)",   "Scrap Yard"),
    ("Metalico",            "Metalico, Inc.",                   "Scrap Yard"),
    ("Sims Metal",          "Sims Limited",                     "Scrap Yard"),
    ("EMR",                 "EMR (European Metal Recycling)",   "Scrap Yard"),
    ("PADNOS",              "PADNOS",                           "Scrap Yard"),
    ("GLR Advanced Recycling","GLR Advanced Recycling",         "Scrap Yard"),
    ("Huron Valley Steel",  "Huron Valley Steel",               "Scrap Yard"),

    # --- Auto U-Pull chains ---
    ("LKQ Pick Your Part",  "LKQ Pick Your Part",               "Auto U-Pull"),
    ("LKQ Self-Service",    "LKQ Pick Your Part",               "Auto U-Pull"),
    ("LKQ Pull-A-Part",     "LKQ Corporation",                  "Auto U-Pull"),
    ("LKQ",                 "LKQ Corporation",                  "Auto U-Pull"),
    ("Pull-A-Part",         "Pull-A-Part, LLC",                 "Auto U-Pull"),
    ("U-Pull-And-Pay",      "U-Pull-&-Pay (Radius / Schnitzer)","Auto U-Pull"),
    ("U-Pull-It",           "Independent U-Pull-It",            "Auto U-Pull"),
    ("Pick-N-Pull",         "Pick-n-Pull (Radius / Schnitzer)", "Auto U-Pull"),
    ("Pick-A-Part",         "Independent Pick-A-Part",          "Auto U-Pull"),
    ("U-Pick-It",           "U-Pick-It",                        "Auto U-Pull"),
    ("Pull-N-Save",         "Pull-N-Save",                      "Auto U-Pull"),
    ("Wrench-A-Part",       "Wrench-A-Part",                    "Auto U-Pull"),

    # --- Brokers / futures / refiners (examples) ---
    ("StoneX",              "StoneX Group Inc.",                "Futures Desk"),
    ("Marex",               "Marex Group",                      "Futures Desk"),
    ("Glencore",            "Glencore",                         "Broker"),
    ("Trafigura",           "Trafigura",                        "Broker"),
    ("Cargill Metals",      "Cargill, Inc.",                    "Broker"),
    ("Umicore",             "Umicore",                          "Refiner"),
    ("Heraeus",             "Heraeus",                          "Refiner"),
    ("Asahi Refining",      "Asahi Refining",                   "Refiner"),
]

# Homepages you *already know* (no API needed)
CANONICAL_HOMEPAGES = {
    # --- Mining / Majors ---
    "Freeport-McMoRan":                 "https://www.fcx.com/",
    "Capstone Copper":                  "https://capstonecopper.com/",
    "Barrick Gold Corporation":         "https://www.barrick.com/",
    "Nevada Gold Mines":                "https://www.nevadagoldmines.com/",
    "Rio Tinto":                        "https://www.riotinto.com/",
    "Teck Resources":                   "https://www.teck.com/",
    "Hycroft Mining Holding Corporation":"https://www.hycroftmining.com/",
    "Kinross Gold":                     "https://www.kinross.com/",
    "KGHM Polska Miedź":                "https://kghm.com/",
    "Peabody Energy":                   "https://www.peabodyenergy.com/",
    "Arch Resources":                   "https://www.archrsc.com/",
    "Sibanye-Stillwater":              "https://www.sibanyestillwater.com/",

    # --- Integrated / Steel / Mills ---
    "Nucor Corporation":                "https://www.nucor.com/",
    "Steel Dynamics, Inc.":             "https://www.steeldynamics.com/",
    "Commercial Metals Company":        "https://www.cmc.com/",
    "United States Steel Corporation":  "https://www.ussteel.com/",
    "Cleveland-Cliffs Inc.":           "https://www.clevelandcliffs.com/",
    "California Steel Industries":      "https://www.californiasteel.com/",
    "Novelis Inc.":                     "https://novelis.com/",
    "JW Aluminum":                      "https://www.jwaluminum.com/",
    "Arconic Corporation":              "https://www.arconic.com/",
    "Constellium SE":                   "https://www.constellium.com/",
    "Kaiser Aluminum":                  "https://www.kaiseraluminum.com/",
    "Revere Copper Products (NY)":      "https://reverecopper.com/",
    "Southwire":                        "https://www.southwire.com/",
    "NLMK USA":                         "https://us.nlmk.com/",
    "Gerdau":                           "https://www2.gerdau.com/",

    # --- Scrap / Yard Chains & Majors ---
    "SA Recycling":                     "https://www.sarecycling.com/",
    "Radius Recycling (Schnitzer Steel)": "https://www.radiusrecycling.com/",
    "OmniSource, LLC":                  "https://www.omnisource.com/",
    "Alter Trading Corporation":        "https://www.altertrading.com/",
    "River Metals Recycling (RMR)":     "https://www.rmrecycling.com/",
    "Metalico, Inc.":                   "https://www.metalico.com/",
    "Sims Limited":                     "https://www.simsltd.com/",
    "EMR (European Metal Recycling)":   "https://us.emrgroup.com/",
    "PADNOS":                           "https://www.padnos.com/",
    "GLR Advanced Recycling":           "https://www.glradvanced.com/",
    "Huron Valley Steel":               "https://www.hvss.net/",
    "PSC Metals":                       "https://www.pscmetals.com/",
    "Cohen Recycling":                  "https://www.cohenusa.com/",
    "Ferrous Processing & Trading (FPT)":"https://www.ferrousprocessing.com/",
    "Schupan":                          "https://www.schupan.com/",
    "MetalX":                           "https://www.metalx.com/",
    "Newco Metals":                     "https://www.newcometals.com/",
    "Sadoff Iron & Metal":              "https://www.sadoff.com/",
    "Behr Iron & Metal":                "https://www.behrim.com/",
    "Scrap Metal Services":             "https://www.scrapmetalservices.com/",
    "Upstate Shredding – Weitsman Recycling": "https://www.upstateshredding.com/",
    "Trademark Metals Recycling":       "https://www.tmrecycling.com/",
    "Northern Metal Recycling":         "https://www.northernmetalrecycling.com/",
    "Pacific Steel & Recycling":        "https://www.pacific-steel.com/",
    "Calbag Metals":                    "https://www.calbag.com/",
    "Cherry City Metals":               "https://cherrycitymetals.com/",
    "SA Recycling trading division":    "https://www.sarecycling.com/",
    "EMR Global Trading":               "https://us.emrgroup.com/",

    # --- Auto U-Pull / Self-service chains ---
    "LKQ Corporation":                  "https://www.lkqcorp.com/",
    "LKQ Pick Your Part":               "https://www.lkqpickyourpart.com/",
    "Pick-n-Pull (Radius / Schnitzer)": "https://www.picknpull.com/",
    "Pull-A-Part, LLC":                 "https://www.pullapart.com/",
    "U-Pull-&-Pay (Radius / Schnitzer)":"https://upullandpay.com/",
    "Wrench-A-Part":                    "https://www.wrenchapart.com/",
    # For the “Independent U-Pull-It” / “Independent Pick-A-Part” buckets,
    # you’ll likely leave canonical_homepage_url blank and fill manually per yard.

    # --- Brokers / Trading / Futures / Refiners ---
    "Glencore":                         "https://www.glencore.com/",
    "Trafigura":                        "https://www.trafigura.com/",
    "Cargill, Inc.":                    "https://www.cargill.com/",
    "Gerald Metals":                    "https://www.gerald.com/",
    "Cronimet Specialty Metals":        "https://www.cronimet.com/",
    "Metal Exchange Corp.":             "https://metalexchangecorp.com/",
    "Henschel Trade Group":             "https://henschel.com/",
    "Derichebourg Recycling USA Trading":"https://www.derichebourg.com/",
    "StoneX Group Inc.":                "https://www.stonex.com/",
    "Marex Group":                      "https://www.marex.com/",
    "ED&F Man":                         "https://www.edfman.com/",
    "Sucden Financial":                 "https://www.sucdenfinancial.com/",
    "TP ICAP":                          "https://www.tpicap.com/",
    "Concord Resources":                "https://www.concordresources.com/",
    "TransMarket Group (TMG Metals)":   "https://www.transmarketgroup.com/",
    "Mitsui & Co. Metals":              "https://www.mitsui.com/",
    "Sumitomo Corporation of Americas": "https://www.sumitomocorp.com/en/us",

    # --- Precious / PGM / Refiners ---
    "Umicore":                          "https://www.umicore.com/",
    "Heraeus":                          "https://www.heraeus.com/",
    "Asahi Refining":                   "https://www.asahirefining.com/",
    "Metalor":                          "https://www.metalor.com/",
    "Dillon Gage Metals":               "https://dillongage.com/",
    "Scottsdale Mint":                  "https://www.scottsdalemint.com/",
    "APMEX Industrial":                 "https://www.apmex.com/",
    "PGM Recovery Systems":             "https://pgmrecoverysystems.com/",
    "Red Fox Resources":                "https://www.redfoxresources.com/",
    "United Catalyst Corporation (UCC)":"https://unitedcatalystcorporation.com/",

    # --- E-Scrap / Electronics ---
    "ERI":                              "https://eridirect.com/",
    "Sunnking":                         "https://www.sunnking.com/",
    "Cal Micro Recycling":              "https://calmicrorecycling.com/",
    "Regency Technologies":             "https://www.regencytechnologies.com/",
    "Interco Trading":                  "https://intercotradingco.com/",
    "HOBI International":               "https://hobi.com/",
    "AER Worldwide":                    "https://aerworldwide.com/",
    "Clover Technologies":              "https://www.clovertech.com/",
    "Dynamic Lifecycle":                "https://www.dlrenew.com/",

    "Freeport-McMoRan":                 "https://www.fcx.com/",
    "Capstone Copper":                  "https://capstonecopper.com/",
    "Barrick Gold Corporation":         "https://www.barrick.com/",
    "Nevada Gold Mines":                "https://www.nevadagoldmines.com/",
    "Rio Tinto":                        "https://www.riotinto.com/",
    "Cleveland-Cliffs Inc.":           "https://www.clevelandcliffs.com/",
    "United States Steel Corporation":  "https://www.ussteel.com/",
    "Nucor Corporation":                "https://www.nucor.com/",
    "Steel Dynamics, Inc.":             "https://www.steeldynamics.com/",
    "Commercial Metals Company":        "https://www.cmc.com/",
    "Novelis Inc.":                     "https://novelis.com/",
    "JW Aluminum":                      "https://www.jwaluminum.com/",
    "Arconic Corporation":              "https://www.arconic.com/",
    "Constellium SE":                   "https://www.constellium.com/",
    "Kaiser Aluminum":                  "https://www.kaiseraluminum.com/",
    "California Steel Industries":      "https://www.californiasteel.com/",
    "SA Recycling":                     "https://www.sarecycling.com/",
    "Radius Recycling (Schnitzer Steel)": "https://www.radiusrecycling.com/",
    "OmniSource, LLC":                  "https://www.omnisource.com/",
    "Alter Trading Corporation":        "https://www.altertrading.com/",
    "River Metals Recycling (RMR)":     "https://www.rmrecycling.com/",
    "Metalico, Inc.":                   "https://www.metalico.com/",
    "Sims Limited":                     "https://www.simsltd.com/",
    "EMR (European Metal Recycling)":   "https://us.emrgroup.com/",
    "PADNOS":                           "https://www.padnos.com/",
    "GLR Advanced Recycling":           "https://www.glradvanced.com/",
    "Huron Valley Steel":               "https://www.hvss.net/",
    "LKQ Corporation":                  "https://www.lkqcorp.com/",
    "LKQ Pick Your Part":               "https://www.lkqpickyourpart.com/",
    "Pick-n-Pull (Radius / Schnitzer)": "https://www.picknpull.com/",
    "Pull-A-Part, LLC":                 "https://www.pullapart.com/",
    "U-Pull-&-Pay (Radius / Schnitzer)":"https://upullandpay.com/",
    "StoneX Group Inc.":                "https://www.stonex.com/",
    "Marex Group":                      "https://www.marex.com/",
    "Glencore":                         "https://www.glencore.com/",
    "Trafigura":                        "https://www.trafigura.com/",
    "Cargill, Inc.":                    "https://www.cargill.com/",
    "Umicore":                          "https://www.umicore.com/",
    "Heraeus":                          "https://www.heraeus.com/",
    "Asahi Refining":                   "https://www.asahirefining.com/",
}

# =========================
# 2. Matching + parsing
# =========================

def match_canonical(raw_name: str):
    """Return (canonical_org, org_type) or (raw_name, 'Unknown')."""
    name_upper = raw_name.upper()
    for pattern, canon, org_type in CANONICAL_PATTERNS:
        if pattern.upper() in name_upper:
            return canon, org_type
        
    # Heuristic: if it "smells" like a yard, call it a Scrap Yard instead of Unknown
    yard_tokens = ["SCRAP", "RECYCLING", "METAL", "U-PULL", "U PULL", "PULL-A-PART",
                   "PICK-N-PULL", "AUTO SALVAGE", "WRECKING"]
    org_type = "Unknown"
    if any(tok in name_upper for tok in yard_tokens):
        org_type = "Scrap Yard"
    return raw_name.strip(), org_type

def parse_facility(raw_name: str, canonical_org: str):
    """
    Try to strip the canonical org or leading dash to get a facility name.
    e.g. 'Freeport – Morenci Mine (AZ)' → 'Morenci Mine (AZ)'
    """
    txt = raw_name
    # If there's a dash/en dash, take the right-hand side
    parts = re.split(r"–|-", txt, maxsplit=1)
    if len(parts) == 2:
        candidate = parts[1].strip()
    else:
        candidate = txt

    # If candidate still contains the canonical org, strip it
    cu = canonical_org.upper()
    if cu in candidate.upper():
        # remove canonical substring
        idx = candidate.upper().find(cu)
        candidate = (candidate[:idx] + candidate[idx+len(cu):]).strip(" -–")

    # If what's left is basically the same as raw_name, call it blank
    if candidate.upper() == raw_name.upper():
        return ""
    return candidate
       
# =========================
# 3. Main pipeline
# =========================

def main():
    input_file = "targets_raw.txt"
    output_file = "targets_master.csv"

    # First pass: canonicalize each raw row
    rows = []
    canonical_set = set()

    with open(input_file, encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            canonical_org, org_type = match_canonical(raw)
            facility_name = parse_facility(raw, canonical_org)
            rows.append({
                "raw_name": raw,
                "canonical_org": canonical_org,
                "org_type": org_type,
                "facility_name": facility_name,
            })
            canonical_set.add(canonical_org)

    print(f"Found {len(rows)} raw rows.")
    print(f"Unique canonical orgs: {len(canonical_set)}")

    # Second pass: build homepage map
    homepage_map = dict(CANONICAL_HOMEPAGES)  

    # Only auto-lookup "bigger" orgs:
    # anything that is NOT a simple Scrap Yard/Auto U-Pull with no canonical homepage.
    lookup_candidates = set()
    for r in rows:
        org = r["canonical_org"]
        if org in homepage_map:
            continue
        # Skip small yards / self-service lots – leave their homepage blank
        if r["org_type"] in ("Scrap Yard", "Auto U-Pull"):
            continue
        lookup_candidates.add(org)

    for org in sorted(lookup_candidates):        
        homepage_map= dict (CANONICAL_HOMEPAGES)

    # Final write
    fieldnames = [
        "raw_name",
        "canonical_org",
        "org_type",
        "canonical_homepage_url",
        "facility_name",
        "facility_city",
        "facility_state",
        "facility_country",
        "facility_url",
        "notes",
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            canon = r["canonical_org"]
            w.writerow({
                "raw_name": r["raw_name"],
                "canonical_org": canon,
                "org_type": r["org_type"],
                "canonical_homepage_url": homepage_map.get(canon, ""),
                "facility_name": r["facility_name"],
                "facility_city": "",
                "facility_state": "",
                "facility_country": "US",
                "facility_url": "",
                "notes": "",
            })

    print(f"Wrote {output_file}")

if __name__ == "__main__":
    main()
