import re, csv, sys
from urllib.parse import urlparse

LINE_RE = re.compile(r"^\s*(.*?)\s*[—-]\s*(https?://\S+)\s*$")  # supports em-dash or hyphen

def canon_host(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""

def clean_url(u: str) -> str:
    u = u.strip().rstrip(").,;")
    # If somebody pasted "https://x.com/foo)" etc
    while u.endswith(")") and u.count("(") < u.count(")"):
        u = u[:-1]
    return u

def main():
    if len(sys.argv) < 3:
        print("Usage: python make_yard_csv.py input.txt output.csv [--no-dedupe]")
        sys.exit(1)

    inp = sys.argv[1]
    out = sys.argv[2]
    dedupe = ("--no-dedupe" not in sys.argv)

    seen_hosts = set()
    rows = []

    with open(inp, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            m = LINE_RE.match(raw)
            if not m:
                continue

            name = m.group(1).strip()
            url = clean_url(m.group(2).strip())

            # Your crawler adds https:// if missing, but we keep it explicit.
            if not url.startswith("http"):
                url = "https://" + url

            host = canon_host(url)
            if not host:
                continue

            if dedupe:
                if host in seen_hosts:
                    continue
                seen_hosts.add(host)

            rows.append((name, url))

    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow(["Name", "Website"])
        for name, url in rows:
            w.writerow([name, url])

    print(f"Wrote {len(rows)} rows to {out} (dedupe={'ON' if dedupe else 'OFF'})")

if __name__ == "__main__":
    main()
