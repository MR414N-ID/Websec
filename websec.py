#!/usr/bin/env python3
"""
MR.414N - Safe Website Security Audit
A non-destructive, low-impact website checker for systems you own or are
explicitly authorized to assess.

Uses only DNS lookups, TLS certificate inspection, and a small number of
ordinary HTTP GET/HEAD requests. It does NOT exploit vulnerabilities,
brute-force credentials, bypass authentication, crawl the site, or scan ports.
Python 3.9+; standard library only.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple


APP = "MR.414N"
VERSION = "1.0"
USER_AGENT = "MR-414N-SafeAudit/1.0 (+authorized security testing)"
TIMEOUT = 8
DELAY = 0.35

# A deliberately short list of public, non-invasive checks. No payloads.
PUBLIC_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
]


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    detail: str
    recommendation: str


class SafeAudit:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        parsed = urllib.parse.urlsplit(self.base_url)
        self.scheme = parsed.scheme.lower()
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.origin = f"{self.scheme}://{self.host}"
        if parsed.port:
            default = 443 if self.scheme == "https" else 80
            if parsed.port != default:
                self.origin += f":{parsed.port}"
        self.findings: List[Finding] = []
        self.evidence: Dict[str, Any] = {}
        self.checked_at = dt.datetime.now(dt.timezone.utc).isoformat()

    def add(self, category: str, severity: str, title: str,
            detail: str, recommendation: str) -> None:
        self.findings.append(Finding(category, severity, title, detail, recommendation))

    def request(self, path: str = "/", method: str = "GET") -> Tuple[Optional[int], Dict[str, str], bytes, str]:
        url = self.origin + path
        req = urllib.request.Request(
            url,
            method=method,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"},
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                body = response.read(256 * 1024) if method == "GET" else b""
                headers = {k.lower(): v for k, v in response.headers.items()}
                return response.status, headers, body, response.geturl()
        except urllib.error.HTTPError as e:
            try:
                body = e.read(64 * 1024) if method == "GET" else b""
            except Exception:
                body = b""
            headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            return e.code, headers, body, url
        except Exception as e:
            return None, {}, b"", f"{type(e).__name__}: {e}"
        finally:
            time.sleep(DELAY)

    def check_dns(self) -> None:
        try:
            records = sorted({item[4][0] for item in socket.getaddrinfo(
                self.host, self.port, type=socket.SOCK_STREAM
            )})
            self.evidence["dns_addresses"] = records
            self.add("DNS", "INFO", "DNS resolution successful",
                     "Host resolved to: " + ", ".join(records),
                     "No action required. Confirm these addresses belong to your hosting provider.")
        except Exception as e:
            self.evidence["dns_error"] = str(e)
            self.add("DNS", "HIGH", "DNS resolution failed", str(e),
                     "Check the domain's DNS records and authoritative nameservers.")

    def check_tls(self) -> None:
        if self.scheme != "https":
            self.add("TLS", "HIGH", "Website uses HTTP instead of HTTPS",
                     "The supplied URL uses unencrypted HTTP.",
                     "Enable HTTPS with a valid certificate and redirect HTTP to HTTPS.")
            return
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, self.port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as tls:
                    cert = tls.getpeercert()
                    cipher = tls.cipher()
                    version = tls.version()
                    self.evidence["tls"] = {
                        "version": version,
                        "cipher": cipher[0] if cipher else None,
                        "not_after": cert.get("notAfter"),
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                    }
                    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self.add("TLS", "HIGH", "Outdated TLS protocol",
                                 f"Negotiated protocol: {version}",
                                 "Configure the server to support TLS 1.2 and TLS 1.3; disable obsolete protocols.")
                    else:
                        self.add("TLS", "INFO", "TLS connection verified",
                                 f"Protocol: {version}; cipher: {cipher[0] if cipher else 'unknown'}",
                                 "Keep TLS configuration and certificates up to date.")
        except Exception as e:
            self.evidence["tls_error"] = str(e)
            self.add("TLS", "HIGH", "TLS validation failed", str(e),
                     "Check certificate validity, hostname coverage, certificate chain, and server TLS configuration.")

    def check_http(self) -> None:
        status, headers, body, final_url = self.request("/")
        self.evidence["http"] = {
            "status": status,
            "final_url": final_url,
            "headers": headers,
            "body_bytes_read": len(body),
        }
        if status is None:
            self.add("HTTP", "HIGH", "Website could not be reached", final_url,
                     "Verify the URL, DNS, hosting availability, and firewall rules.")
            return

        if self.scheme == "https" and final_url.startswith("http://"):
            self.add("HTTP", "HIGH", "HTTPS request redirected to HTTP",
                     f"Final URL: {final_url}",
                     "Keep the entire session on HTTPS and remove redirects to HTTP.")

        checks = [
            ("strict-transport-security", "HSTS header missing", "MEDIUM",
             "Add Strict-Transport-Security after confirming HTTPS works across the site."),
            ("content-security-policy", "Content-Security-Policy header missing", "MEDIUM",
             "Define a Content-Security-Policy suited to the site's scripts, styles, images, and connections."),
            ("x-content-type-options", "X-Content-Type-Options header missing", "LOW",
             "Set X-Content-Type-Options: nosniff."),
            ("referrer-policy", "Referrer-Policy header missing", "LOW",
             "Set a restrictive Referrer-Policy, such as strict-origin-when-cross-origin."),
            ("permissions-policy", "Permissions-Policy header missing", "LOW",
             "Explicitly disable browser features the site does not need."),
        ]
        for header, title, severity, recommendation in checks:
            if header not in headers:
                self.add("HTTP headers", severity, title,
                         f"The response did not include {header}.",
                         recommendation)

        if "server" in headers:
            self.add("Information disclosure", "LOW", "Server banner is exposed",
                     f"Server header: {headers['server']}",
                     "Consider minimizing version details in server response headers.")
        if "x-powered-by" in headers:
            self.add("Information disclosure", "LOW", "Technology banner is exposed",
                     f"X-Powered-By: {headers['x-powered-by']}",
                     "Remove unnecessary X-Powered-By headers.")

        if "set-cookie" in headers:
            cookie_lines = headers["set-cookie"].split("\n")
            for line in cookie_lines:
                lower = line.lower()
                cookie_name = line.split("=", 1)[0].strip() or "(unnamed cookie)"
                if self.scheme == "https" and "secure" not in lower:
                    self.add("Cookies", "MEDIUM", f"Cookie lacks Secure flag: {cookie_name}",
                             "A Set-Cookie response appears not to include the Secure attribute.",
                             "Set the Secure attribute on cookies sent over HTTPS.")
                if "httponly" not in lower:
                    self.add("Cookies", "LOW", f"Cookie lacks HttpOnly flag: {cookie_name}",
                             "A Set-Cookie response appears not to include HttpOnly.",
                             "Set HttpOnly on session cookies that do not need JavaScript access.")
                if "samesite" not in lower:
                    self.add("Cookies", "LOW", f"Cookie lacks SameSite attribute: {cookie_name}",
                             "A Set-Cookie response appears not to include SameSite.",
                             "Set an appropriate SameSite policy, commonly Lax, for session cookies.")

    def check_public_files(self) -> None:
        for path in PUBLIC_PATHS:
            status, headers, body, final_url = self.request(path, "GET")
            self.evidence.setdefault("public_paths", {})[path] = {
                "status": status,
                "final_url": final_url,
                "bytes_read": len(body),
                "content_type": headers.get("content-type"),
            }
            if status == 200:
                self.add("Public resources", "INFO", f"Public resource found: {path}",
                         f"HTTP 200; read at most {len(body)} bytes. This may be expected.",
                         "Review the content and ensure it contains no secrets, credentials, private paths, or internal data.")
            elif status is not None and status not in (403, 404, 410):
                self.add("Public resources", "INFO", f"{path} returned HTTP {status}",
                         "The endpoint responded; this status alone does not prove a vulnerability.",
                         "Confirm the response is intentional and does not expose sensitive information.")

    def run(self, selected: List[str]) -> Dict[str, Any]:
        actions = {
            "1": ("DNS", self.check_dns),
            "2": ("TLS", self.check_tls),
            "3": ("HTTP", self.check_http),
            "4": ("PUBLIC", self.check_public_files),
        }
        for choice in selected:
            name, fn = actions[choice]
            print(f"\n[+] Running {name} checks...")
            fn()
        return {
            "tool": APP,
            "version": VERSION,
            "target": self.origin,
            "checked_at_utc": self.checked_at,
            "scope": "Safe, non-destructive checks only",
            "findings": [asdict(f) for f in self.findings],
            "evidence": self.evidence,
        }


def banner() -> None:
    print(r"""
  __  __ ____      _  _  _  _  _
 |  \/  |  _ \    / \| || || \| |
 | |\/| | |_) |  / _ \ || || .` |
 | |  | |  _ <  / ___ \__   _| |\ |
 |_|  |_|_| \_\/_/   \_\ |_| |_| \_|

        MR.414N  ::  SAFE WEBSITE AUDIT
        Kali-style terminal interface
    """)
    print(f"  Version {VERSION} | Authorized testing only")
    print("  No exploits • No brute force • No port scanning • Low request rate\n")


def validate_url(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL tidak valid. Gunakan contoh: https://domain-anda.com")
    if parsed.username or parsed.password:
        raise ValueError("URL dengan username/password tidak didukung.")
    # Normalize to origin to keep checks scoped to the entered hostname.
    return f"{parsed.scheme}://{parsed.netloc}"


def print_findings(report: Dict[str, Any]) -> None:
    print("\n" + "=" * 68)
    print("  HASIL AUDIT MR.414N")
    print("=" * 68)
    print(f"  Target : {report['target']}")
    print(f"  Waktu  : {report['checked_at_utc']}")
    findings = report["findings"]
    if not findings:
        print("\n  Belum ada temuan. Periksa kembali apakah metode yang dipilih berjalan.")
        return
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings = sorted(findings, key=lambda x: order.get(x["severity"], 5))
    counts = {level: sum(1 for f in findings if f["severity"] == level)
              for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    print("  Ringkasan: " + " | ".join(f"{k}: {v}" for k, v in counts.items()))
    for i, item in enumerate(findings, 1):
        print(f"\n  [{i:02}] [{item['severity']}] {item['title']}")
        print(f"       Kategori : {item['category']}")
        print(f"       Detail   : {item['detail']}")
        print(f"       Saran    : {item['recommendation']}")


def save_report(report: Dict[str, Any]) -> None:
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_name = f"mr414n_report_{stamp}.json"
    html_name = f"mr414n_report_{stamp}.html"
    with open(json_name, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    rows = []
    for item in report["findings"]:
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                *(html.escape(str(item[k])) for k in
                  ("severity", "category", "title", "detail", "recommendation"))
            )
        )
    page = """<!doctype html><html lang="id"><meta charset="utf-8">
<title>MR.414N Security Report</title>
<style>
body{background:#0b1119;color:#dce8f2;font:15px Arial,sans-serif;margin:30px}
h1{color:#49baff} .muted{color:#91a6b8} table{border-collapse:collapse;width:100%}
td,th{border:1px solid #334454;padding:10px;text-align:left;vertical-align:top}
th{background:#172637;color:#67c5ff} tr:nth-child(even){background:#111d29}
</style><h1>MR.414N — Security Audit</h1>
<p class="muted">Target: {target}<br>Checked: {time}<br>Scope: Safe, non-destructive checks only</p>
<table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th><th>Recommendation</th></tr></thead>
<tbody>{rows}</tbody></table></html>""".format(
        target=html.escape(report["target"]),
        time=html.escape(report["checked_at_utc"]),
        rows="".join(rows),
    )
    with open(html_name, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"\n[+] Laporan tersimpan: {json_name}")
    print(f"[+] Laporan HTML tersimpan: {html_name}")


def main() -> None:
    banner()
    print("PERINGATAN: Gunakan hanya pada situs milik Anda atau yang Anda")
    print("miliki izin tertulis untuk mengujinya. Jalankan dengan persetujuan.\n")
    raw = input("[MR.414N] Masukkan URL target: ").strip()
    try:
        target = validate_url(raw)
    except ValueError as e:
        print(f"[!] {e}")
        return

    print(f"\n[+] Target dikunci ke host: {target}")
    print("\nPILIH METODE PENGUJIAN")
    print("  1. DNS lookup")
    print("  2. TLS / sertifikat HTTPS")
    print("  3. HTTP security headers & cookie flags")
    print("  4. Pemeriksaan resource publik (robots.txt, sitemap.xml, security.txt)")
    print("  A. ALL METHODS — jalankan semua pemeriksaan aman")
    print("  Q. Keluar")
    choice = input("\nMR.414N > Pilihan: ").strip().lower()

    mapping = {"1": ["1"], "2": ["2"], "3": ["3"], "4": ["4"],
               "a": ["1", "2", "3", "4"], "all": ["1", "2", "3", "4"]}
    if choice in ("q", "quit", "exit"):
        print("Keluar.")
        return
    if choice not in mapping:
        print("[!] Pilihan tidak dikenal.")
        return

    print("\n[!] Memulai pemeriksaan ringan. Jangan tutup terminal...")
    audit = SafeAudit(target)
    report = audit.run(mapping[choice])
    print_findings(report)
    save = input("\nSimpan laporan JSON dan HTML? [Y/n]: ").strip().lower()
    if save in ("", "y", "yes"):
        save_report(report)
    print("\n[MR.414N] Audit selesai. Perbaiki temuan lalu lakukan verifikasi ulang.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Dihentikan oleh pengguna.")
        sys.exit(130)
