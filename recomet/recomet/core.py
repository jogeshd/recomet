"""
RecoMet - Core OSINT & Recon Engine
Cross-platform, open source OSINT toolkit
"""

import socket
import ssl
import json
import urllib.request
import urllib.error
import subprocess
import platform
import re
import datetime
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─── Helpers ────────────────────────────────────────────────────────────────

def _get(url, timeout=8):
    """Simple HTTP GET, returns text or None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "RecoMet-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def _get_json(url, timeout=8):
    """GET and parse JSON, returns dict/list or None."""
    raw = _get(url, timeout)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            return None
    return None


# ─── DNS & IP ────────────────────────────────────────────────────────────────

def dns_lookup(target):
    """Resolve hostname → IPs and reverse DNS."""
    results = {"target": target, "module": "DNS Lookup", "records": {}}
    try:
        ip_list = socket.getaddrinfo(target, None)
        ips = list({r[4][0] for r in ip_list})
        results["records"]["A/AAAA"] = ips
        for ip in ips[:2]:
            try:
                host = socket.gethostbyaddr(ip)[0]
                results["records"].setdefault("PTR", []).append(f"{ip} -> {host}")
            except Exception:
                pass
    except socket.gaierror as e:
        results["error"] = str(e)
    return results


def whois_lookup(target):
    """WHOIS via public API (no external binary needed)."""
    results = {"target": target, "module": "WHOIS"}
    # Try rdap first (structured JSON)
    data = _get_json(f"https://rdap.org/domain/{target}")
    if data:
        results["status"] = data.get("status", [])
        results["events"] = [
            {"action": e.get("eventAction"), "date": e.get("eventDate", "")[:10]}
            for e in data.get("events", [])
        ]
        entities = data.get("entities", [])
        vcards = []
        for ent in entities:
            for vc in ent.get("vcardArray", [[]])[1:]:
                for item in vc:
                    if item[0] == "fn":
                        vcards.append(item[3])
        results["registrant"] = vcards or ["N/A"]
        results["name"] = data.get("ldhName", target)
        results["nameservers"] = [
            ns.get("ldhName") for ns in data.get("nameservers", [])
        ]
    else:
        results["error"] = "RDAP lookup failed or domain not found"
    return results


def ip_info(target):
    """Geo/ASN info for an IP."""
    # Resolve to IP if hostname
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target
    results = {"target": ip, "module": "IP Info"}
    data = _get_json(f"https://ipapi.co/{ip}/json/")
    if data and "error" not in data:
        results.update({
            "ip": data.get("ip"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country_name"),
            "org": data.get("org"),
            "asn": data.get("asn"),
            "timezone": data.get("timezone"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
        })
    else:
        results["error"] = "IP info lookup failed"
    return results


# ─── Port Scanning ──────────────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch",
}


def _check_port(ip, port, timeout=1.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port, True
    except Exception:
        return port, False


def port_scan(target, ports=None, timeout=1.5):
    """Fast threaded port scanner."""
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        return {"target": target, "module": "Port Scan", "error": "Cannot resolve host"}

    scan_ports = ports or list(COMMON_PORTS.keys())
    results = {"target": target, "ip": ip, "module": "Port Scan", "open": [], "closed_count": 0}

    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(_check_port, ip, p, timeout): p for p in scan_ports}
        for fut in as_completed(futures):
            port, open_ = fut.result()
            if open_:
                service = COMMON_PORTS.get(port, "Unknown")
                results["open"].append({"port": port, "service": service})
            else:
                results["closed_count"] += 1

    results["open"].sort(key=lambda x: x["port"])
    return results


# ─── SSL / TLS ───────────────────────────────────────────────────────────────

def ssl_check(target, port=443):
    """Fetch SSL certificate details."""
    results = {"target": target, "port": port, "module": "SSL/TLS Check"}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((target, port), timeout=8), server_hostname=target) as s:
            cert = s.getpeercert()
            results["subject"] = dict(x[0] for x in cert.get("subject", []))
            results["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            results["version"] = cert.get("version")
            results["serial"] = cert.get("serialNumber")
            results["not_before"] = cert.get("notBefore")
            results["not_after"] = cert.get("notAfter")
            sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
            results["SANs"] = sans
            # Check expiry
            expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
            results["days_until_expiry"] = days_left
            results["expired"] = days_left < 0
    except Exception as e:
        results["error"] = str(e)
    return results


# ─── HTTP Headers ────────────────────────────────────────────────────────────

def http_headers(target):
    """Fetch HTTP response headers and flag security misconfigs."""
    if not target.startswith("http"):
        target = "https://" + target
    results = {"target": target, "module": "HTTP Headers", "headers": {}, "warnings": []}
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "RecoMet-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            for k, v in r.headers.items():
                results["headers"][k] = v
            results["status_code"] = r.status
            for sh in security_headers:
                if sh.lower() not in {k.lower() for k in r.headers}:
                    results["warnings"].append(f"Missing: {sh}")
            results["server"] = r.headers.get("Server", "N/A")
            results["x_powered_by"] = r.headers.get("X-Powered-By", "N/A")
    except Exception as e:
        results["error"] = str(e)
    return results


# ─── Subdomain Finder ────────────────────────────────────────────────────────

COMMON_SUBS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "vpn", "admin", "api", "dev", "staging", "test", "blog", "shop",
    "cdn", "static", "assets", "media", "portal", "auth", "login",
    "dashboard", "app", "mobile", "remote", "secure", "support",
    "docs", "wiki", "forum", "git", "gitlab", "jenkins", "ci",
    "mx", "email", "news", "store", "old", "new", "beta", "m",
]


def _check_sub(sub, domain):
    host = f"{sub}.{domain}"
    try:
        ips = socket.getaddrinfo(host, None)
        ip = ips[0][4][0]
        return {"subdomain": host, "ip": ip}
    except Exception:
        return None


def subdomain_enum(domain, wordlist=None):
    """Enumerate subdomains via DNS brute-force + crt.sh."""
    results = {"target": domain, "module": "Subdomain Enum", "found": []}
    subs = wordlist or COMMON_SUBS

    # crt.sh certificate transparency
    ct_data = _get_json(f"https://crt.sh/?q=%.{domain}&output=json")
    ct_subs = set()
    if ct_data:
        for entry in ct_data:
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = n.strip().lstrip("*.")
                if n.endswith(domain) and n != domain:
                    ct_subs.add(n)
        for sub in ct_subs:
            try:
                ip = socket.gethostbyname(sub)
                results["found"].append({"subdomain": sub, "ip": ip, "source": "crt.sh"})
            except Exception:
                pass

    # DNS brute-force
    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = [ex.submit(_check_sub, s, domain) for s in subs]
        for fut in as_completed(futures):
            r = fut.result()
            if r and not any(f["subdomain"] == r["subdomain"] for f in results["found"]):
                r["source"] = "brute-force"
                results["found"].append(r)

    results["found"].sort(key=lambda x: x["subdomain"])
    results["count"] = len(results["found"])
    return results


# ─── Email OSINT ─────────────────────────────────────────────────────────────

def email_osint(email):
    """Basic email OSINT: validate, extract domain, check breach status hint."""
    results = {"target": email, "module": "Email OSINT"}
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        results["valid"] = False
        results["error"] = "Invalid email format"
        return results
    results["valid"] = True
    user, domain = email.split("@", 1)
    results["username"] = user
    results["domain"] = domain
    # MX records via DNS
    mx_results = []
    try:
        # Use socket to try MX (basic approach without dnspython)
        import subprocess
        if platform.system() == "Windows":
            cmd = ["nslookup", "-type=MX", domain]
        else:
            cmd = ["host", "-t", "MX", domain]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        mx_results = [l.strip() for l in proc.stdout.splitlines() if "mail" in l.lower() or "MX" in l]
    except Exception:
        mx_results = ["MX lookup not available"]
    results["mx_records"] = mx_results
    # Domain info
    results["domain_info"] = ip_info(domain)
    return results


# ─── Tech Stack Detect ────────────────────────────────────────────────────────

def tech_detect(target):
    """Detect technologies from HTTP headers and page content."""
    if not target.startswith("http"):
        url = "https://" + target
    else:
        url = target
    results = {"target": url, "module": "Tech Detection", "detected": []}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 RecoMet"})
        with urllib.request.urlopen(req, timeout=10) as r:
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = r.read(50000).decode("utf-8", errors="replace")

        sigs = {
            "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
            "Drupal": [r"Drupal", r"/sites/default/"],
            "Joomla": [r"Joomla!", r"/components/com_"],
            "React": [r"react\.development", r"react\.production", r"__reactFiber"],
            "Vue.js": [r"Vue\.js", r"vue\.min\.js", r"__vue__"],
            "Angular": [r"ng-version", r"angular\.min\.js"],
            "jQuery": [r"jquery[\.\-][\d]"],
            "Bootstrap": [r"bootstrap\.min\.css", r"bootstrap\.bundle"],
            "Nginx": [r"nginx"],
            "Apache": [r"Apache"],
            "Cloudflare": [r"cloudflare", r"cf-ray"],
            "AWS": [r"amazonaws\.com", r"AmazonS3"],
            "Google Analytics": [r"google-analytics\.com", r"gtag\("],
            "PHP": [r"\.php", r"X-Powered-By.*PHP"],
            "ASP.NET": [r"ASP\.NET", r"__VIEWSTATE"],
            "Next.js": [r"__NEXT_DATA__", r"_next/"],
            "Shopify": [r"shopify", r"myshopify\.com"],
        }

        for tech, patterns in sigs.items():
            for p in patterns:
                search_in = body + " ".join(headers.values())
                if re.search(p, search_in, re.IGNORECASE):
                    if tech not in results["detected"]:
                        results["detected"].append(tech)
                    break

        results["server"] = headers.get("server", "N/A")
        results["x_powered_by"] = headers.get("x-powered-by", "N/A")
    except Exception as e:
        results["error"] = str(e)
    return results


# ─── Full Recon ───────────────────────────────────────────────────────────────

def full_recon(target):
    """Run all modules against a target."""
    results = {"target": target, "timestamp": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z", "modules": {}}

    def run(name, fn, *args):
        try:
            return name, fn(*args)
        except Exception as e:
            return name, {"error": str(e)}

    tasks = [
        ("dns", dns_lookup, target),
        ("whois", whois_lookup, target),
        ("ip_info", ip_info, target),
        ("port_scan", port_scan, target),
        ("ssl", ssl_check, target),
        ("http_headers", http_headers, target),
        ("subdomains", subdomain_enum, target),
        ("tech_detect", tech_detect, target),
    ]

    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(run, n, fn, *args): n for n, fn, *args in tasks}
        for fut in as_completed(futures):
            name, result = fut.result()
            results["modules"][name] = result

    return results
