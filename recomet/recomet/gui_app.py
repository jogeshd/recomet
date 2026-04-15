"""
RecoMet GUI - Tkinter-based GUI for the OSINT toolkit.
Zero external dependencies — uses only Python stdlib.
"""

import sys
import os
import json
import threading
import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recomet import core


# ─── Theme ───────────────────────────────────────────────────────────────────

DARK_BG    = "#0d1117"
PANEL_BG   = "#161b22"
BORDER     = "#30363d"
ACCENT     = "#00d4ff"
ACCENT2    = "#7ee787"
WARNING    = "#f78166"
TEXT       = "#c9d1d9"
TEXT_DIM   = "#6e7681"
FONT_MONO  = ("Consolas", 10) if sys.platform == "win32" else ("Courier New", 10)
FONT_UI    = ("Segoe UI", 10) if sys.platform == "win32" else ("Helvetica", 10)
FONT_TITLE = ("Segoe UI Semibold", 12) if sys.platform == "win32" else ("Helvetica", 12)


class RecoMetGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RecoMet — OSINT & Recon Toolkit")
        self.root.configure(bg=DARK_BG)
        self.root.minsize(1000, 700)

        self._current_results = {}
        self._running = False

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=DARK_BG)
        style.configure("Panel.TFrame", background=PANEL_BG)
        style.configure(
            "TButton",
            background=ACCENT, foreground=DARK_BG,
            font=FONT_UI, padding=(12, 6), relief="flat", borderwidth=0
        )
        style.map("TButton", background=[("active", "#00b8d9"), ("disabled", BORDER)])
        style.configure(
            "Danger.TButton",
            background=WARNING, foreground=DARK_BG, font=FONT_UI, padding=(10, 5)
        )
        style.configure(
            "TCheckbutton",
            background=PANEL_BG, foreground=TEXT, font=FONT_UI
        )
        style.map("TCheckbutton", background=[("active", PANEL_BG)])
        style.configure(
            "TLabel",
            background=DARK_BG, foreground=TEXT, font=FONT_UI
        )
        style.configure("Dim.TLabel", background=DARK_BG, foreground=TEXT_DIM, font=FONT_UI)
        style.configure(
            "TEntry",
            fieldbackground=PANEL_BG, foreground=TEXT,
            insertcolor=ACCENT, relief="flat", borderwidth=1
        )
        style.configure(
            "TNotebook", background=DARK_BG, tabmargins=[0, 0, 0, 0]
        )
        style.configure(
            "TNotebook.Tab",
            background=PANEL_BG, foreground=TEXT_DIM, padding=[12, 6],
            font=FONT_UI
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", DARK_BG)],
            foreground=[("selected", ACCENT)]
        )
        style.configure("TProgressbar", troughcolor=PANEL_BG, background=ACCENT, thickness=3)
        style.configure(
            "TLabelframe", background=PANEL_BG, foreground=TEXT_DIM,
            relief="flat", borderwidth=1
        )
        style.configure("TLabelframe.Label", background=PANEL_BG, foreground=ACCENT, font=FONT_UI)

    def _build_ui(self):
        # ── Top bar ──────────────────────────────────────────────────────────
        top = tk.Frame(self.root, bg=PANEL_BG, pady=12, padx=20)
        top.pack(fill="x")

        tk.Label(top, text="◈ RecoMet", bg=PANEL_BG, fg=ACCENT,
                 font=("Consolas", 18, "bold")).pack(side="left")
        tk.Label(top, text="  OSINT & Recon Toolkit  |  github.com/jogeshd/recomet",
                 bg=PANEL_BG, fg=TEXT_DIM, font=FONT_UI).pack(side="left")

        # ── Main layout ───────────────────────────────────────────────────────
        main = tk.Frame(self.root, bg=DARK_BG)
        main.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        left = tk.Frame(main, bg=PANEL_BG, width=240)
        left.pack(side="left", fill="y", padx=(0, 10), pady=4)
        left.pack_propagate(False)

        right = tk.Frame(main, bg=DARK_BG)
        right.pack(side="left", fill="both", expand=True, pady=4)

        self._build_sidebar(left)
        self._build_right_panel(right)

    def _build_sidebar(self, parent):
        # Target
        tk.Label(parent, text="TARGET", bg=PANEL_BG, fg=ACCENT,
                 font=("Consolas", 9, "bold")).pack(anchor="w", padx=16, pady=(16, 4))

        self.target_var = tk.StringVar()
        entry = tk.Entry(
            parent, textvariable=self.target_var,
            bg="#0d1117", fg=TEXT, insertbackground=ACCENT,
            relief="flat", font=FONT_MONO, bd=0,
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT
        )
        entry.pack(fill="x", padx=16, ipady=6)
        entry.bind("<Return>", lambda _: self._run())

        tk.Label(parent, text="e.g. example.com, 1.2.3.4, user@mail.com",
                 bg=PANEL_BG, fg=TEXT_DIM, font=("Consolas", 8)).pack(anchor="w", padx=16, pady=(2, 12))

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=8)

        # Modules
        tk.Label(parent, text="MODULES", bg=PANEL_BG, fg=ACCENT,
                 font=("Consolas", 9, "bold")).pack(anchor="w", padx=16, pady=(12, 6))

        self.module_vars = {}
        modules = [
            ("dns",        "◈  DNS Lookup"),
            ("whois",      "◈  WHOIS"),
            ("ip",         "◈  IP Info"),
            ("ports",      "◈  Port Scan"),
            ("ssl",        "◈  SSL/TLS Check"),
            ("headers",    "◈  HTTP Headers"),
            ("subdomains", "◈  Subdomains"),
            ("tech",       "◈  Tech Detection"),
            ("email",      "◈  Email OSINT"),
        ]
        for key, label in modules:
            var = tk.BooleanVar(value=True)
            self.module_vars[key] = var
            cb = tk.Checkbutton(
                parent, text=label, variable=var,
                bg=PANEL_BG, fg=TEXT, activebackground=PANEL_BG,
                activeforeground=ACCENT, selectcolor=DARK_BG,
                font=("Consolas", 9), cursor="hand2",
                highlightthickness=0, bd=0
            )
            cb.pack(anchor="w", padx=12, pady=1)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=8, pady=10)

        # All / None quick toggles
        row = tk.Frame(parent, bg=PANEL_BG)
        row.pack(fill="x", padx=12)

        def _all():
            for v in self.module_vars.values(): v.set(True)
        def _none():
            for v in self.module_vars.values(): v.set(False)

        tk.Button(row, text="All", bg=BORDER, fg=TEXT, font=FONT_UI,
                  relief="flat", cursor="hand2", command=_all).pack(side="left", padx=(0, 4))
        tk.Button(row, text="None", bg=BORDER, fg=TEXT, font=FONT_UI,
                  relief="flat", cursor="hand2", command=_none).pack(side="left")

        # Run / Stop buttons
        self.run_btn = tk.Button(
            parent, text="▶  RUN RECON", bg=ACCENT, fg=DARK_BG,
            font=("Consolas", 10, "bold"), relief="flat", cursor="hand2",
            command=self._run
        )
        self.run_btn.pack(fill="x", padx=16, pady=(14, 6), ipady=8)

        self.stop_btn = tk.Button(
            parent, text="■  STOP", bg=WARNING, fg=DARK_BG,
            font=("Consolas", 10, "bold"), relief="flat", cursor="hand2",
            state="disabled", command=self._stop
        )
        self.stop_btn.pack(fill="x", padx=16, pady=(0, 8), ipady=6)

        # Save
        tk.Button(
            parent, text="⬇  Save JSON", bg=PANEL_BG, fg=TEXT,
            font=FONT_UI, relief="flat", cursor="hand2",
            command=self._save_json
        ).pack(fill="x", padx=16, pady=(0, 4), ipady=5)

        # Progress bar
        self.progress = ttk.Progressbar(parent, mode="indeterminate")
        self.progress.pack(fill="x", padx=16, pady=(8, 0))

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(parent, textvariable=self.status_var, bg=PANEL_BG, fg=TEXT_DIM,
                 font=("Consolas", 8)).pack(anchor="w", padx=16, pady=(4, 0))

    def _build_right_panel(self, parent):
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill="both", expand=True)

        # Output tab
        out_frame = tk.Frame(self.notebook, bg=DARK_BG)
        self.notebook.add(out_frame, text="  Output  ")
        self.output_text = scrolledtext.ScrolledText(
            out_frame, bg=DARK_BG, fg=TEXT, font=FONT_MONO,
            insertbackground=ACCENT, relief="flat",
            wrap="word", bd=0,
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT, state="disabled"
        )
        self.output_text.pack(fill="both", expand=True)

        # Tag colours
        self.output_text.tag_config("header",  foreground=ACCENT,  font=("Consolas", 10, "bold"))
        self.output_text.tag_config("key",     foreground=TEXT_DIM)
        self.output_text.tag_config("value",   foreground=ACCENT2)
        self.output_text.tag_config("warn",    foreground=WARNING)
        self.output_text.tag_config("info",    foreground=ACCENT)
        self.output_text.tag_config("dim",     foreground=TEXT_DIM)
        self.output_text.tag_config("error",   foreground=WARNING, font=("Consolas", 10, "bold"))

        # JSON tab
        json_frame = tk.Frame(self.notebook, bg=DARK_BG)
        self.notebook.add(json_frame, text="  JSON  ")
        self.json_text = scrolledtext.ScrolledText(
            json_frame, bg=DARK_BG, fg=TEXT, font=FONT_MONO,
            insertbackground=ACCENT, relief="flat", wrap="none", bd=0,
            highlightthickness=1, highlightbackground=BORDER,
            state="disabled"
        )
        self.json_text.pack(fill="both", expand=True)

    # ─── Output helpers ───────────────────────────────────────────────────────

    def _write(self, text, tag=None):
        self.output_text.config(state="normal")
        if tag:
            self.output_text.insert("end", text, tag)
        else:
            self.output_text.insert("end", text)
        self.output_text.see("end")
        self.output_text.config(state="disabled")

    def _clear(self):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.config(state="disabled")
        self.json_text.config(state="normal")
        self.json_text.delete("1.0", "end")
        self.json_text.config(state="disabled")

    def _section(self, title):
        self._write(f"\n┌─── {title} {'─'*max(0,50-len(title))}┐\n", "header")

    def _kv(self, key, value):
        self._write(f"  {key}: ", "key")
        if isinstance(value, list):
            if value:
                self._write("\n")
                for v in value:
                    self._write(f"    • {v}\n", "value")
            else:
                self._write("(none)\n", "dim")
        else:
            self._write(f"{value}\n", "value")

    # ─── Module display ───────────────────────────────────────────────────────

    def _display_dns(self, r):
        self._section("DNS Lookup")
        if "error" in r:
            self._write(f"  Error: {r['error']}\n", "error"); return
        for rtype, vals in r.get("records", {}).items():
            self._kv(rtype, vals)

    def _display_whois(self, r):
        self._section("WHOIS")
        if "error" in r:
            self._write(f"  Error: {r['error']}\n", "error"); return
        for k in ["name", "registrant", "nameservers", "status"]:
            if k in r: self._kv(k, r[k])
        for ev in r.get("events", []):
            self._write(f"  {ev.get('action')}: ", "key")
            self._write(f"{ev.get('date', '')}\n", "value")

    def _display_ip(self, r):
        self._section("IP Info")
        if "error" in r:
            self._write(f"  Error: {r['error']}\n", "error"); return
        for k in ["ip", "city", "region", "country", "org", "asn", "timezone"]:
            if k in r: self._kv(k, r[k])

    def _display_ports(self, r):
        self._section("Port Scan")
        if "error" in r:
            self._write(f"  Error: {r['error']}\n", "error"); return
        open_ports = r.get("open", [])
        self._write(f"  Open ports: ", "key")
        self._write(f"{len(open_ports)}\n", "value")
        for p in open_ports:
            self._write(f"    ● {p['port']:<8} {p['service']}\n", "value")

    def _display_ssl(self, r):
        self._section("SSL/TLS Certificate")
        if "error" in r:
            self._write(f"  Error: {r['error']}\n", "error"); return
        self._kv("CN", r.get("subject", {}).get("commonName", "N/A"))
        self._kv("Issuer", r.get("issuer", {}).get("organizationName", "N/A"))
        self._kv("Expires", r.get("not_after", "N/A"))
        days = r.get("days_until_expiry")
        if days is not None:
            tag = "warn" if days < 30 else "value"
            self._write("  Days until expiry: ", "key")
            self._write(f"{days}\n", tag)
        self._kv("SANs", r.get("SANs", []))

    def _display_headers(self, r):
        self._section("HTTP Headers & Security")
        if "error" in r:
            self._write(f"  Error: {r['error']}\n", "error"); return
        self._kv("Status", r.get("status_code"))
        self._kv("Server", r.get("server"))
        warnings = r.get("warnings", [])
        if warnings:
            self._write("  ⚠ Missing headers:\n", "warn")
            for w in warnings:
                self._write(f"    ! {w}\n", "warn")
        else:
            self._write("  ✓ All key security headers present\n", "value")

    def _display_subdomains(self, r):
        self._section("Subdomain Enumeration")
        if "error" in r:
            self._write(f"  Error: {r['error']}\n", "error"); return
        found = r.get("found", [])
        self._write(f"  Found: ", "key")
        self._write(f"{len(found)} subdomains\n", "value")
        for s in found[:60]:
            self._write(f"    ◆ {s['subdomain']:<40} {s.get('ip',''):<18} ", "value")
            self._write(f"[{s.get('source','?')}]\n", "dim")

    def _display_tech(self, r):
        self._section("Tech Detection")
        if "error" in r:
            self._write(f"  Error: {r['error']}\n", "error"); return
        detected = r.get("detected", [])
        if detected:
            for t in detected:
                self._write(f"    ▸ {t}\n", "value")
        else:
            self._write("  Nothing detected\n", "dim")

    def _display_email(self, r):
        self._section("Email OSINT")
        if "error" in r:
            self._write(f"  Error: {r['error']}\n", "error"); return
        self._kv("Valid Format", str(r.get("valid", False)))
        self._kv("Username", r.get("username", "N/A"))
        self._kv("Domain", r.get("domain", "N/A"))
        self._kv("MX Records", r.get("mx_records", []))

    DISPLAY_MAP = {
        "dns": _display_dns,
        "whois": _display_whois,
        "ip": _display_ip,
        "ports": _display_ports,
        "ssl": _display_ssl,
        "headers": _display_headers,
        "subdomains": _display_subdomains,
        "tech": _display_tech,
        "email": _display_email,
    }
    CORE_MAP = {
        "dns": core.dns_lookup,
        "whois": core.whois_lookup,
        "ip": core.ip_info,
        "ports": core.port_scan,
        "ssl": core.ssl_check,
        "headers": core.http_headers,
        "subdomains": core.subdomain_enum,
        "tech": core.tech_detect,
        "email": core.email_osint,
    }

    # ─── Run logic ────────────────────────────────────────────────────────────

    def _run(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("No target", "Please enter a target first.")
            return
        if self._running:
            return
        selected = [k for k, v in self.module_vars.items() if v.get()]
        if not selected:
            messagebox.showwarning("No modules", "Select at least one module.")
            return

        self._running = True
        self._current_results = {}
        self._clear()

        self._write("◈ RecoMet — OSINT & Recon Toolkit\n", "header")
        self._write(f"  Target : {target}\n", "info")
        self._write(f"  Time   : {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n", "dim")
        self._write(f"  Modules: {', '.join(selected)}\n\n", "dim")

        self.run_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress.start(12)

        def worker():
            for mod in selected:
                if not self._running:
                    break
                self._set_status(f"Running {mod}...")
                fn = self.CORE_MAP[mod]
                try:
                    result = fn(target)
                except Exception as e:
                    result = {"error": str(e)}
                self._current_results[mod] = result
                disp = self.DISPLAY_MAP[mod]
                self.root.after(0, lambda r=result, d=disp: d(self, r))

            self.root.after(0, self._done)

        threading.Thread(target=worker, daemon=True).start()

    def _stop(self):
        self._running = False
        self._write("\n  ■ Stopped by user.\n", "warn")
        self._done()

    def _done(self):
        self._running = False
        self.run_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.progress.stop()
        self._set_status("Done")

        # Update JSON tab
        self.json_text.config(state="normal")
        self.json_text.delete("1.0", "end")
        self.json_text.insert("end", json.dumps(self._current_results, indent=2))
        self.json_text.config(state="disabled")

        self._write("\n\n  ✓ Recon complete.  |  github.com/jogeshd/recomet\n", "info")

    def _set_status(self, msg):
        self.status_var.set(msg)

    def _save_json(self):
        if not self._current_results:
            messagebox.showinfo("Nothing to save", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
            initialfile="recomet_results.json"
        )
        if path:
            with open(path, "w") as f:
                json.dump(self._current_results, f, indent=2)
            messagebox.showinfo("Saved", f"Results saved to:\n{path}")


def launch_gui():
    root = tk.Tk()
    app = RecoMetGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
