<div align="center">

```
  ____  _____ ____ ___  __  __ _____ _____ 
 |  _ \| ____/ ___/ _ \|  \/  | ____|_   _|
 | |_) |  _|| |  | | | | |\/| |  _|   | |  
 |  _ <| |__| |__| |_| | |  | | |___  | |  
 |_| \_\_____\____\___/|_|  |_|_____| |_|  
```

# RecoMet — Free OSINT & Recon Toolkit

**The all-in-one reconnaissance toolkit that needs zero setup.**  
CLI + GUI · Cross-platform · 100% Python stdlib · No API keys

[![Python](https://img.shields.io/badge/Python-3.7%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)]()
[![Stars](https://img.shields.io/github/stars/jogeshd/recomet?style=flat-square&color=yellow)](https://github.com/jogeshd/recomet/stargazers)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/jogeshd/recomet/pulls)

</div>

---

## ⚡ What is RecoMet?

RecoMet is a **free, open-source OSINT and recon toolkit** for security researchers, CTF players, bug bounty hunters, and ethical hackers.

It combines **9 recon modules** into a single tool with a clean CLI and a full GUI — all using **Python's standard library only**. No pip installs needed. No API keys. Just clone and run.

> ⚠️ **For educational purposes and authorized testing only.** Always get permission before scanning systems you don't own.

---

## 🔍 Modules

| Module | What it does |
|---|---|
| `dns` | A/AAAA records, PTR (reverse DNS) |
| `whois` | RDAP-based registrant, nameservers, expiry |
| `ip` | Geo-location, ASN, org, timezone via ipapi.co |
| `ports` | Fast threaded scan of 20 common ports |
| `ssl` | TLS cert details, SANs, expiry countdown |
| `headers` | HTTP response headers + security misconfig warnings |
| `subdomains` | crt.sh cert transparency + DNS brute-force |
| `tech` | Fingerprint CMS, frameworks, CDN, analytics |
| `email` | Email validation, domain info, MX records |

---

## 🚀 Quick Start

**No installation required. Just Python 3.7+**

```bash
git clone https://github.com/jogeshd/recomet.git
cd recomet

# Full recon on a domain
python recomet.py -t example.com --all

# Run specific modules
python recomet.py -t example.com -m dns whois ports ssl

# IP address info
python recomet.py -t 8.8.8.8 -m ip

# Email OSINT
python recomet.py -t user@example.com -m email

# Launch GUI
python recomet.py --gui

# Save results to file
python recomet.py -t example.com --all -o results.json

# Raw JSON output (great for piping)
python recomet.py -t example.com -m dns --json
```

---

## 🖥️ CLI Demo

```
  ____  _____ ____ ___  __  __ _____ _____
 |  _ \| ____/ ___/ _ \|  \/  | ____|_   _|
 | |_) |  _|| |  | | | | |\/| |  _|   | |
 |  _ <| |__| |__| |_| | |  | | |___  | |
 |_| \_\_____\____\___/|_|  |_|_____| |_|

  Target: example.com
  Time  : 2025-01-15 12:00:00 UTC

┌─── DNS Lookup ──────────────────────────────────┐
  A/AAAA: ['93.184.216.34']
  PTR: ['93.184.216.34 -> 93.184.216.34']

┌─── Port Scan ───────────────────────────────────┐
  Open ports (2):
    ● 80   / HTTP
    ● 443  / HTTPS

┌─── SSL/TLS Certificate ─────────────────────────┐
  CN:      example.com
  Issuer:  DigiCert
  Expires: Nov 28 23:59:59 2025 GMT
  Days:    317

┌─── Subdomain Enumeration ───────────────────────┐
  Found: 4 subdomains
    ◆ api.example.com       93.184.216.34   [crt.sh]
    ◆ dev.example.com       93.184.216.34   [crt.sh]
    ◆ mail.example.com      93.184.216.34   [brute-force]
    ◆ www.example.com       93.184.216.34   [brute-force]
```

---

## 🖱️ GUI

Launch the GUI with one command:

```bash
python recomet.py --gui
```

- Dark theme, clean layout
- Check/uncheck individual modules
- Live output as each module completes
- Save results as JSON
- Works on Windows, Linux, macOS (uses built-in Tkinter)

---

## 📁 Project Structure

```
recomet/
├── recomet.py           # CLI entry point
├── recomet/
│   ├── __init__.py
│   ├── core.py          # All recon engines
│   ├── gui_app.py       # Tkinter GUI
│   └── cli.py           # pip entry point shim
├── setup.py
├── LICENSE
└── README.md
```

---

## 🔧 Optional: Install as a command

```bash
pip install -e .
recomet -t example.com --all
```

---

## 📊 Module Details

### DNS Lookup
Resolves a hostname to IPv4/IPv6 addresses and performs reverse DNS lookups.

### WHOIS
Uses the RDAP protocol (structured JSON) — more reliable than raw WHOIS text. Returns registrant info, nameservers, registration/expiry dates.

### IP Info
Queries `ipapi.co` for geolocation, ASN, organization, timezone, lat/long.

### Port Scan
Threaded scanner (50 workers) checks 20 most critical ports in seconds. Includes service name mapping.

### SSL/TLS Check
Fetches the full TLS certificate, extracts Subject Alternative Names, warns on certs expiring within 30 days.

### HTTP Headers
Fetches response headers and flags missing security headers:
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

### Subdomain Enumeration
Two-phase approach:
1. **Certificate Transparency** via crt.sh (finds subdomains from SSL certs — often finds dev/staging)
2. **DNS brute-force** with 50 common subdomain names

### Tech Detection
Fingerprints CMS, JS frameworks, CDN, analytics from HTTP headers and page source. Detects: WordPress, Drupal, Joomla, React, Vue, Angular, jQuery, Bootstrap, Nginx, Apache, Cloudflare, AWS, Google Analytics, PHP, ASP.NET, Next.js, Shopify, and more.

### Email OSINT
Validates email format, extracts username and domain, looks up MX records and domain IP info.

---

## 🤝 Contributing

Pull requests are welcome! Areas to contribute:
- More subdomain wordlists
- Additional tech fingerprints
- More port → service mappings
- New OSINT modules (Shodan, FOFA integration, etc.)
- Better error handling

```bash
git fork https://github.com/jogeshd/recomet
git checkout -b feature/my-module
# ... make changes ...
git commit -m "Add my-module"
git push origin feature/my-module
# Open a PR!
```

---

## ⭐ Support

If RecoMet helped you, give it a **star** — it helps others find the tool and keeps the project going!

---

## 📜 License

MIT — free for personal and commercial use. See [LICENSE](LICENSE).

---

## ⚠️ Disclaimer

RecoMet is intended for **authorized security testing, education, and research only**. Unauthorized scanning of systems you do not own is illegal. The authors take no responsibility for misuse.

---

<div align="center">

Made with 💙 by [jogeshd](https://github.com/jogeshd)

</div>
