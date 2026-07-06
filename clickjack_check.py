import sys
import socket
import argparse
import datetime
from urllib.parse import urlparse

try:
    import requests
    import urllib3
except ImportError:
    print("This script needs the 'requests' package. Install it with:\n    pip install requests")
    sys.exit(1)


def parse_frame_ancestors(csp):
    if not csp:
        return None
    parts = [p.strip() for p in csp.split(";") if p.strip()]
    for p in parts:
        if p.lower().startswith("frame-ancestors"):
            tokens = p.split()[1:]
            return tokens
    return []


def analyze(headers, url):
    lower = {k.lower(): v for k, v in headers.items()}
    xfo = lower.get("x-frame-options")
    csp = lower.get("content-security-policy")
    csp_ro = lower.get("content-security-policy-report-only")

    findings = []
    severity_rank = {"pass": 0, "info": 0, "warn": 1, "fail": 2}
    worst = "pass"

    def note(level, title, detail=""):
        nonlocal worst
        findings.append((level, title, detail))
        if severity_rank[level] > severity_rank[worst]:
            worst = level

    fa = parse_frame_ancestors(csp)
    fa_ro = parse_frame_ancestors(csp_ro)

    if not xfo and csp is None and csp_ro is None:
        note("fail", "No framing protection found",
             "Neither X-Frame-Options nor Content-Security-Policy is set. The page can be framed by any site.")

    if csp is not None and fa == []:
        note("warn", "CSP present but missing frame-ancestors",
             "Add a frame-ancestors directive explicitly; other CSP directives do not restrict framing.")

    if fa:
        if "*" in fa:
            note("fail", "frame-ancestors allows '*'", "Any origin can embed this page.")
        elif fa == ["'none'"]:
            note("pass", "frame-ancestors 'none'", "Blocks all framing in modern browsers.")
        elif fa == ["'self'"]:
            note("pass", "frame-ancestors 'self'", "Restricts framing to same origin.")
        else:
            note("pass", "frame-ancestors allow-list", "Framing permitted only for: " + " ".join(fa))
            insecure = [s for s in fa if s.startswith("http:")]
            if insecure:
                note("warn", "Insecure http: origin in frame-ancestors", ", ".join(insecure))

    if csp is None and csp_ro is not None:
        note("fail", "CSP is report-only, not enforced",
             "Content-Security-Policy-Report-Only does not block framing, only logs violations.")
        if fa_ro:
            note("info", "Report-only frame-ancestors: " + " ".join(fa_ro), "Not enforced today.")

    if xfo:
        val = xfo.strip().upper()
        if val == "DENY":
            note("info" if fa else "pass", "X-Frame-Options: DENY",
                 "Superseded by CSP frame-ancestors in modern browsers." if fa else "Blocks all framing.")
        elif val == "SAMEORIGIN":
            note("info" if fa else "pass", "X-Frame-Options: SAMEORIGIN",
                 "Superseded by CSP frame-ancestors in modern browsers." if fa else "Allows same-origin framing only.")
        elif val.startswith("ALLOW-FROM"):
            note("warn", "X-Frame-Options: ALLOW-FROM is deprecated",
                 "Ignored by Chrome, Firefox, and Safari. Provides no protection in those browsers unless CSP frame-ancestors is also set.")
        else:
            note("warn", "Unrecognized X-Frame-Options value: " + xfo,
                 "Browsers may ignore invalid values.")

    return worst, findings, xfo, csp, csp_ro


def check_url(url, make_poc=False):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    host = parsed.hostname

    print("=" * 70)
    print(f"Site:      {url}")

    try:
        ip = socket.gethostbyname(host)
        print(f"IP:        {ip}")
    except socket.gaierror:
        print(f"IP:        could not resolve {host}")

    print(f"Time:      {datetime.datetime.now().isoformat(timespec='seconds')}")

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
    except requests.RequestException as e:
        print(f"ERROR:     could not fetch URL ({e})")
        print("=" * 70)
        return

    print(f"Status:    {resp.status_code} (final URL: {resp.url})")
    print("-" * 70)

    worst, findings, xfo, csp, csp_ro = analyze(resp.headers, resp.url)

    print(f"X-Frame-Options:              {xfo or '(not set)'}")
    print(f"Content-Security-Policy:      {csp or '(not set)'}")
    print(f"CSP-Report-Only:              {csp_ro or '(not set)'}")
    print("-" * 70)

    label = {"pass": "PROTECTED", "warn": "PARTIALLY PROTECTED", "fail": "VULNERABLE"}[worst]
    print(f"VERDICT: {label}")
    print()
    for level, title, detail in findings:
        tag = {"pass": "[PASS]", "warn": "[WARN]", "fail": "[FAIL]", "info": "[INFO]"}[level]
        print(f"  {tag} {title}")
        if detail:
            print(f"         {detail}")
    print("=" * 70)

    if make_poc:
        poc_path = f"poc_{host}.html".replace(":", "_")
        with open(poc_path, "w") as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC - {host}</title></head>
<body style="margin:0;font-family:sans-serif;">
  <div style="background:#222;color:#fff;padding:12px;">
    Clickjacking proof-of-concept for {url}. If the frame below shows the real site, it is embeddable.
  </div>
  <iframe src="{resp.url}" style="width:100%;height:90vh;border:0;"></iframe>
</body>
</html>
""")
        print(f"PoC file written: {poc_path}")
        print()


def main():
    ap = argparse.ArgumentParser(description="Check URLs for clickjacking protection.")
    ap.add_argument("urls", nargs="*", help="URLs to check")
    ap.add_argument("-f", "--file", help="File with one URL per line")
    ap.add_argument("--poc", action="store_true", help="Also generate a PoC HTML file per URL")
    args = ap.parse_args()

    urls = list(args.urls)
    if args.file:
        with open(args.file) as fh:
            urls += [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    if not urls:
        ap.print_help()
        sys.exit(1)

    for u in urls:
        check_url(u, make_poc=args.poc)


if __name__ == "__main__":
    main()