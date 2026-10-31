"""make_samples.py - creates fake logs with planted attacks (RFC 5737 test IPs only)."""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
OUT = Path(__file__).parent / "sample_logs"
OUT.mkdir(exist_ok=True)
T0 = datetime(2026, 10, 1, 9, 0, 0)

def t(minutes=0, seconds=0):
    return T0 + timedelta(minutes=minutes, seconds=seconds)

def write(name, header, rows):
    rows.sort(key=lambda r: r[0])
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow([x.strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(x, datetime) else x for x in r])

# 1. Windows Security (Splunk-style column names) ------------------------
rows = []
for i in range(12):                                   # normal logons
    rows.append([t(i * 5), 4624, f"user{i % 4}", f"10.0.0.{10 + i}", 2, "Audit Success", "WS01"])
for i in range(7):                                    # brute force on administrator
    rows.append([t(20, i * 4), 4625, "administrator", "203.0.113.50", 3, "Audit Failure", "DC01"])
for i, u in enumerate(["alice", "bob", "carol", "dave", "erin", "frank"]):   # spraying
    rows.append([t(30, i * 10), 4625, u, "203.0.113.60", 3, "Audit Failure", "DC01"])
for i in range(5):                                    # failures then success
    rows.append([t(40, i * 6), 4625, "svc_backup", "198.51.100.77", 3, "Audit Failure", "DC01"])
rows.append([t(41), 4624, "svc_backup", "198.51.100.77", 3, "Audit Success", "DC01"])
rows.append([t(45), 4720, "helpdesk1", "-", "", "Audit Success", "DC01"])      # account created
rows.append([t(46), 4732, "helpdesk1", "-", "", "Audit Success", "DC01"])      # added to Administrators
rows.append([t(50), 1102, "svc_backup", "-", "", "Audit Success", "DC01"])     # log cleared
for i in range(2):                                    # harmless failures -> INFO
    rows.append([t(55, i * 30), 4625, "user1", "10.0.0.99", 2, "Audit Failure", "WS02"])
write("sample_windows_security.csv",
      ["_time", "EventCode", "Account_Name", "Source_Network_Address", "Logon_Type", "Keywords", "ComputerName"],
      rows)

# 2. Linux SSH, Splunk export with only a _raw column ---------------------
rows = []
def ssh(ts, line):
    host = "linux-web01"
    stamp = ts.strftime("%b %d %H:%M:%S")
    rows.append([ts, host, f"{stamp} {host} sshd[{random.randint(1000, 9999)}]: {line}"])
for i in range(3):
    ssh(t(i * 7), f"Accepted publickey for devops from 10.0.0.{20 + i} port {40000 + i} ssh2")
for i in range(9):
    ssh(t(10, i * 3), f"Failed password for invalid user admin from 203.0.113.50 port {50000 + i} ssh2")
for i, u in enumerate(["root", "oracle", "postgres", "ubuntu", "test"]):
    ssh(t(15, i * 5), f"Failed password for {u} from 203.0.113.60 port {51000 + i} ssh2")
for i in range(4):
    ssh(t(20, i * 5), f"Failed password for deploy from 198.51.100.77 port {52000 + i} ssh2")
ssh(t(21), "Accepted password for deploy from 198.51.100.77 port 52010 ssh2")
write("sample_linux_ssh.csv", ["_time", "host", "_raw"], rows)

# 3. Web access log ---------------------------------------------------------
rows = []
good = ["/", "/index.html", "/products", "/about", "/contact"]
for i in range(15):
    rows.append([t(i * 2), "10.0.0.5", "GET", random.choice(good), 200, "Mozilla/5.0", 5120])
for i, p in enumerate(["/products?id=1' OR '1'='1", "/products?id=1 UNION SELECT user,pass FROM users",
                       "/search?q=<script>alert(1)</script>", "/download?file=../../etc/passwd"]):
    rows.append([t(20, i * 3), "203.0.113.99", "GET", p, 200 if i in (1, 3) else 403, "sqlmap/1.7", 900])
for i, p in enumerate(["/.env", "/wp-login.php", "/phpmyadmin/", "/admin", "/xmlrpc.php"]):
    rows.append([t(25, i * 2), "203.0.113.101", "GET", p, 404, "curl/8.0", 300])
for i in range(20):
    rows.append([t(30, i), "203.0.113.100", "GET", f"/hidden{i}", 404, "Mozilla/5.0", 200])
for i in range(6):
    rows.append([t(35, i * 5), "203.0.113.102", "POST", "/login", 401, "python-requests/2.31", 150])
write("sample_web_access.csv",
      ["_time", "clientip", "method", "uri_path", "status", "useragent", "bytes"], rows)

# 4. Firewall -------------------------------------------------------------
rows = []
for i in range(10):
    rows.append([t(i * 3), "10.0.0.7", "10.0.1.5", 443, "allow", "tcp"])
for i, p in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]):
    rows.append([t(12, i), "198.51.100.88", "10.0.1.5", p, "deny", "tcp"])
for i in range(14):
    rows.append([t(20, i * 2), "203.0.113.120", "10.0.1.5", 3389, "drop", "tcp"])
for i in range(12):
    rows.append([t(30, i), "198.51.100.90", f"10.0.1.{i + 10}", 445, "deny", "tcp"])
write("sample_firewall.csv",
      ["timestamp", "src_ip", "dest_ip", "dest_port", "action", "protocol"], rows)

# 5. Original 6-column format ----------------------------------------------
rows = []
for i in range(6):
    rows.append([t(i), "203.0.113.50", "login", "admin", "failed", ""])
for i in range(9):
    rows.append([t(10, i), "198.51.100.88", "network", "", "failed", 1000 + i])
rows.append([t(20), "10.0.0.5", "login", "alice", "success", ""])
write("sample_original_format.csv",
      ["timestamp", "source_ip", "event_type", "username", "status", "destination_port"], rows)

# 6. Deliberately broken files for testing error handling -------------------
(OUT / "test_invalid_ip.csv").write_text(
    "timestamp,source_ip,event_type,username,status,destination_port\n"
    "2026-10-01T09:00:01Z,not_an_ip,login,a,failed,\n"
    "2026-10-01T09:00:02Z,999.1.1.1,login,a,failed,\n"
    "2026-10-01T09:00:03Z,10.0.0.5,login,a,success,\n")
(OUT / "test_unknown_columns.csv").write_text(
    "when,attacker,who,result\n"
    "2026-10-01T09:00:01Z,203.0.113.5,root,FAIL\n" * 1 +
    "".join(f"2026-10-01T09:01:0{i}Z,203.0.113.5,root,FAIL\n" for i in range(6)))
print("Created:", ", ".join(sorted(p.name for p in OUT.iterdir())))
