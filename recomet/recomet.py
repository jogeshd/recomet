#!/usr/bin/env python3
"""
RecoMet CLI - OSINT & Recon Toolkit
Usage: python recomet.py [options]
"""

import argparse
import json
import sys
import os
import datetime

# Allow running from repo root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from recomet import core

# ─── Colors ─────────────────────────────────────────────────────────────────

class C:
    """ANSI colors — auto-disabled on Windows unless ANSI is supported."""
    _enabled = sys.stdout.isatty() and (os.name != "nt" or os.environ.get("TERM"))

    @staticmethod
    def _c(code, text):
        return f"\033[{code}m{text}\033[0m" if C._enabled else text

    RED    = staticmethod(lambda t: C._c("31", t))
    GREEN  = staticmethod(lambda t: C._c("32", t))
    YELLOW = staticmethod(lambda t: C._c("33", t))
    CYAN   = staticmethod(lambda t: C._c("36", t))
    BOLD   = staticmethod(lambda t: C._c("1",  t))
    DIM    = staticmethod(lambda t: C._c("2",  t))
    BLUE   = staticmethod(lambda t: C._c("34", t))
    MAGENTA= staticmethod(lambda t: C._c("35", t))


BANNER = r"""
  ____  _____ ____ ___  __  __ _____ _____ 
 |  _ \| ____/ ___/ _ \|  \/  | ____|_   _|
 | |_) |  _|| |  | | | | |\/| |  _|   | |  
 |  _ <| |__| |__| |_| | |  | | |___  | |  
 |_| \_\_____\____\___/|_|  |_|_____| |_|  

  Free OSINT & Recon Toolkit  |  github.com/jogeshd/recomet
  Cross-platform | Open Source | CLI + GUI
"""


def print_banner():
    print(C.CYAN(BANNER))


def print_section(title):
    print()
    print(C.BOLD(C.BLUE(f"┌─── {title} " + "─" * max(0, 50 - len(title)) + "┐")))


def print_kv(key, value, indent=2):
    pad = " " * indent
    if isinstance(value, list):
        if not value:
            print(f"{pad}{C.DIM(key)}: {C.DIM('(none)')}")
        else:
            print(f"{pad}{C.DIM(key)}:")
            for v in value:
                print(f"{pad}  {C.GREEN('•')} {v}")
    elif isinstance(value, dict):
        print(f"{pad}{C.DIM(key)}:")
        for k, v in value.items():
            print(f"{pad}  {k}: {C.GREEN(str(v))}")
    else:
        print(f"{pad}{C.DIM(key)}: {C.GREEN(str(value))}")


# ─── Pretty Printers ─────────────────────────────────────────────────────────

def show_dns(r):
    print_section("DNS Lookup")
    if "error" in r:
        print(f"  {C.RED('Error')}: {r['error']}")
        return
    for rtype, vals in r.get("records", {}).items():
        print_kv(rtype, vals)


def show_whois(r):
    print_section("WHOIS")
    if "error" in r:
        print(f"  {C.RED('Error')}: {r['error']}")
        return
    for key in ["name", "registrant", "nameservers", "status", "events"]:
        if key in r:
            print_kv(key, r[key])


def show_ip(r):
    print_section("IP Info")
    if "error" in r:
        print(f"  {C.RED('Error')}: {r['error']}")
        return
    for key in ["ip", "city", "region", "country", "org", "asn", "timezone", "latitude", "longitude"]:
        if key in r:
            print_kv(key, r[key])


def show_ports(r):
    print_section("Port Scan")
    if "error" in r:
        print(f"  {C.RED('Error')}: {r['error']}")
        return
    open_ports = r.get("open", [])
    if open_ports:
        print(f"  {C.GREEN('Open ports')} ({len(open_ports)}):")
        for p in open_ports:
            print(f"    {C.GREEN('●')} {C.BOLD(str(p['port']))} / {p['service']}")
    else:
        print(f"  {C.YELLOW('No common ports open')}")
    print(f"  Scanned: {len(open_ports) + r.get('closed_count', 0)} ports")


def show_ssl(r):
    print_section("SSL/TLS Certificate")
    if "error" in r:
        print(f"  {C.RED('Error')}: {r['error']}")
        return
    subj = r.get("subject", {})
    issuer = r.get("issuer", {})
    print_kv("Common Name", subj.get("commonName", "N/A"))
    print_kv("Issuer", issuer.get("organizationName", "N/A"))
    print_kv("Valid Until", r.get("not_after", "N/A"))
    days = r.get("days_until_expiry")
    if days is not None:
        color = C.RED if days < 30 else C.GREEN
        print_kv("Days Until Expiry", color(str(days)))
    print_kv("SANs", r.get("SANs", []))


def show_headers(r):
    print_section("HTTP Headers & Security")
    if "error" in r:
        print(f"  {C.RED('Error')}: {r['error']}")
        return
    print_kv("Status Code", r.get("status_code", "N/A"))
    print_kv("Server", r.get("server", "N/A"))
    print_kv("X-Powered-By", r.get("x_powered_by", "N/A"))
    warnings = r.get("warnings", [])
    if warnings:
        print(f"  {C.YELLOW('⚠ Security Issues')}:")
        for w in warnings:
            print(f"    {C.YELLOW('!')} {w}")
    else:
        print(f"  {C.GREEN('✓ All key security headers present')}")


def show_subdomains(r):
    print_section("Subdomain Enumeration")
    if "error" in r:
        print(f"  {C.RED('Error')}: {r['error']}")
        return
    found = r.get("found", [])
    print(f"  Found: {C.GREEN(str(len(found)))} subdomains")
    for s in found[:50]:  # cap display
        src = C.DIM(f"[{s.get('source','?')}]")
        print(f"    {C.GREEN('◆')} {s['subdomain']:<40} {s.get('ip',''):<18} {src}")
    if len(found) > 50:
        print(f"    {C.DIM(f'... and {len(found)-50} more (use --output to see all)')}")


def show_tech(r):
    print_section("Tech Stack Detection")
    if "error" in r:
        print(f"  {C.RED('Error')}: {r['error']}")
        return
    detected = r.get("detected", [])
    if detected:
        print(f"  {C.GREEN('Detected')}:")
        for t in detected:
            print(f"    {C.GREEN('▸')} {t}")
    else:
        print(f"  {C.DIM('Nothing detected')}")


def show_email(r):
    print_section("Email OSINT")
    if "error" in r:
        print(f"  {C.RED('Error')}: {r['error']}")
        return
    print_kv("Valid Format", str(r.get("valid", False)))
    print_kv("Username", r.get("username", "N/A"))
    print_kv("Domain", r.get("domain", "N/A"))
    print_kv("MX Records", r.get("mx_records", []))


MODULE_MAP = {
    "dns": (core.dns_lookup, show_dns),
    "whois": (core.whois_lookup, show_whois),
    "ip": (core.ip_info, show_ip),
    "ports": (core.port_scan, show_ports),
    "ssl": (core.ssl_check, show_ssl),
    "headers": (core.http_headers, show_headers),
    "subdomains": (core.subdomain_enum, show_subdomains),
    "tech": (core.tech_detect, show_tech),
    "email": (core.email_osint, show_email),
}


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="recomet",
        description="RecoMet - Free OSINT & Recon Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recomet.py -t example.com --all
  python recomet.py -t example.com -m dns whois ports ssl
  python recomet.py -t 8.8.8.8 -m ip
  python recomet.py -t user@example.com -m email
  python recomet.py -t example.com --all -o results.json
  python recomet.py --gui
        """
    )
    parser.add_argument("-t", "--target", help="Target domain, IP, or email")
    parser.add_argument(
        "-m", "--modules", nargs="+",
        choices=list(MODULE_MAP.keys()),
        help="Modules to run (default: all)"
    )
    parser.add_argument("-a", "--all", action="store_true", help="Run all modules (full recon)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("--gui", action="store_true", help="Launch GUI")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")
    parser.add_argument("--json", action="store_true", help="Raw JSON output")
    args = parser.parse_args()

    if args.gui:
        from recomet.gui_app import launch_gui
        launch_gui()
        return

    if not args.target:
        parser.print_help()
        sys.exit(0)

    if not args.no_banner:
        print_banner()

    target = args.target.strip()
    print(f"  {C.BOLD('Target')}: {C.CYAN(target)}")
    print(f"  {C.BOLD('Time')}  : {datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    all_results = {}

    if args.all:
        print(f"\n  {C.YELLOW('⚡ Running full recon...')}\n")
        result = core.full_recon(target)
        all_results = result["modules"]
        if args.json:
            print(json.dumps(result, indent=2))
            return
        for mod_name, show_fn in [
            ("dns", show_dns), ("whois", show_whois), ("ip_info", show_ip),
            ("port_scan", show_ports), ("ssl", show_ssl), ("http_headers", show_headers),
            ("subdomains", show_subdomains), ("tech_detect", show_tech),
        ]:
            if mod_name in result["modules"]:
                show_fn(result["modules"][mod_name])
    else:
        modules = args.modules or list(MODULE_MAP.keys())
        for mod in modules:
            fn, show_fn = MODULE_MAP[mod]
            print(f"\n  {C.YELLOW('►')} Running {mod}...")
            result = fn(target)
            all_results[mod] = result
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                show_fn(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\n  {C.GREEN('✓')} Results saved to {C.BOLD(args.output)}")

    print(f"\n  {C.DIM('─' * 55)}")
    print(f"  {C.GREEN('Done!')} | RecoMet  github.com/jogeshd/recomet\n")


if __name__ == "__main__":
    main()
