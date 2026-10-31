"""
soc_toolkit.py - multi-source log analysis engine for a small SOC dashboard.

Supports (auto-detected, or mapped by hand):
  * Windows Security events (EventCode 4624/4625/4720/4732/1102 ...)
  * Linux SSH auth logs (also raw sshd lines inside a Splunk `_raw` column)
  * Web server access logs (Apache/Nginx, also raw combined-log lines)
  * Firewall / network logs (allow, deny, drop)
  * The original 6-column format (timestamp, source_ip, event_type, ...)
"""
from __future__ import annotations

import io
import ipaddress
import re
from dataclasses import dataclass, field

import pandas as pd

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

DEFAULT_THRESHOLDS = {
    "failed_logins": 5,      # failed logins from one IP  -> brute force
    "spray_users": 4,        # distinct usernames from one IP -> password spraying
    "compromise_fails": 3,   # failures before a success   -> possible compromise
    "scan_ports": 8,         # distinct destination ports  -> port scan
    "sweep_hosts": 10,       # distinct destination hosts  -> host sweep
    "fw_blocks": 10,         # firewall blocks from one IP -> repeated blocks
    "web_404": 15,           # HTTP 404s from one IP       -> directory enumeration
    "probe_hits": 3,         # sensitive-path probes       -> recon
}

# ---------------------------------------------------------------- columns
# canonical column -> names it is commonly called (matched ignoring case/_/-/space)
ALIASES = {
    "timestamp": ["timestamp", "_time", "time", "datetime", "date", "@timestamp",
                  "eventtime", "timecreated", "systemtime", "logtime"],
    "source_ip": ["source_ip", "src_ip", "src", "sourceip", "clientip", "client_ip",
                  "remote_addr", "remote_ip", "source_network_address",
                  "sourceaddress", "source_address", "ipaddress", "ip_address",
                  "c_ip", "ip"],
    "username": ["username", "user", "user_name", "account_name", "accountname",
                 "targetusername", "target_user_name", "account", "src_user", "userid"],
    "event_id": ["event_id", "eventid", "eventcode", "event_code", "signature_id"],
    "event_type": ["event_type", "eventtype", "log_type", "sourcetype", "category", "type"],
    "status": ["status", "outcome", "result", "action", "eventoutcome", "keywords",
               "disposition"],
    "http_status": ["http_status", "status_code", "sc_status", "response_code", "http_code"],
    "destination_ip": ["destination_ip", "dest_ip", "dest", "dst_ip", "dst",
                       "destinationip", "destination_address", "server_ip"],
    "destination_port": ["destination_port", "dest_port", "dst_port", "dport",
                         "destinationport", "dpt", "port"],
    "url": ["url", "uri", "uri_path", "request_uri", "cs_uri_stem", "request", "path"],
    "user_agent": ["user_agent", "useragent", "http_user_agent", "cs_user_agent", "agent"],
    "message": ["_raw", "raw", "message", "msg", "log", "description"],
}
CANONICAL = list(ALIASES)

# ---------------------------------------------------------------- values
def _norm(text) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text).lower())

FAILED = {"failed", "failure", "fail", "invalid", "unsuccessful", "auditfailure",
          "authfailure", "failedlogin", "4625"}
SUCCESS = {"success", "successful", "succeeded", "accepted", "ok", "logon",
           "auditsuccess", "4624"}
BLOCKED = {"blocked", "block", "deny", "denied", "drop", "dropped", "reject",
           "rejected", "refused", "reset"}
ALLOWED = {"allow", "allowed", "permit", "permitted", "pass", "passed", "accept"}

def normalise_status(value) -> object:
    if pd.isna(value):
        return pd.NA
    v = _norm(value)
    if v in FAILED:
        return "failed"
    if v in SUCCESS:
        return "success"
    if v in BLOCKED:
        return "blocked"
    if v in ALLOWED:
        return "allowed"
    return pd.NA

# Windows events that matter on their own (no source IP needed)
AUDIT_EVENTS = {
    "1102": ("CRITICAL", "Security audit log cleared", "T1070.001",
             "Attackers clear logs to hide activity."),
    "104": ("CRITICAL", "System log cleared", "T1070.001",
            "Attackers clear logs to hide activity."),
    "4719": ("HIGH", "Audit policy changed", "T1562.002",
             "Logging may have been weakened."),
    "4728": ("HIGH", "Member added to privileged global group", "T1098",
             "Check if this was an approved change."),
    "4732": ("HIGH", "Member added to privileged local group", "T1098",
             "Check if this was an approved change."),
    "4756": ("HIGH", "Member added to privileged universal group", "T1098",
             "Check if this was an approved change."),
    "7045": ("HIGH", "New service installed", "T1543.003",
             "Services are a common persistence method."),
    "4697": ("HIGH", "Service installed on system", "T1543.003",
             "Services are a common persistence method."),
    "4720": ("MEDIUM", "User account created", "T1136",
             "New accounts can be used as backdoors."),
    "4724": ("MEDIUM", "Password reset attempted", "T1098",
             "Confirm the reset was requested by the user or helpdesk."),
    "4726": ("MEDIUM", "User account deleted", "T1531",
             "Confirm the deletion was authorised."),
    "4698": ("MEDIUM", "Scheduled task created", "T1053.005",
             "Scheduled tasks are a common persistence method."),
    "4740": ("MEDIUM", "Account locked out", "T1110",
             "Often follows brute force or password spraying."),
}
WIN_LOGON = {"4625": "failed", "4624": "success"}

# ---------------------------------------------------------------- raw text parsing
IP_RE = r"[0-9A-Fa-f:.]+"
SSH_FAIL = re.compile(
    rf"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
    rf"(?P<user>\S+) from (?P<ip>{IP_RE}) port \d+")
SSH_OK = re.compile(
    rf"Accepted (?:password|publickey|keyboard-interactive/pam) for "
    rf"(?P<user>\S+) from (?P<ip>{IP_RE}) port \d+")
SSH_INVALID = re.compile(rf"Invalid user (?P<user>\S*) from (?P<ip>{IP_RE})")
WEB_LOG = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)[^"]*" '
    r'(?P<code>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?')

def parse_raw_line(line: str) -> dict:
    """Pull fields out of one raw log line (sshd or web access log)."""
    if not isinstance(line, str):
        return {}
    m = SSH_FAIL.search(line) or SSH_INVALID.search(line)
    if m:
        return {"source_ip": m["ip"], "username": m["user"] or None, "status": "failed"}
    m = SSH_OK.search(line)
    if m:
        return {"source_ip": m["ip"], "username": m["user"], "status": "success"}
    m = WEB_LOG.search(line)
    if m:
        return {"source_ip": m["ip"], "url": m["url"], "http_status": m["code"],
                "user_agent": m["ua"], "_web_ts": m["ts"]}
    return {}

# ---------------------------------------------------------------- web attack patterns
WEB_ATTACKS = {
    "SQL injection": (re.compile(
        r"(?i)(union(\s|\+|%20)+select|'(\s|\+|%20)*or(\s|\+|%20)|or(\s|\+|%20)+1=1|"
        r"sleep\(|benchmark\(|information_schema|%27|;\s*drop\s)"), "T1190"),
    "Cross-site scripting": (re.compile(
        r"(?i)(<script|%3cscript|javascript:|onerror=|onload=)"), "T1059.007"),
    "Path traversal": (re.compile(
        r"(?i)(\.\./|\.\.%2f|%2e%2e%2f|/etc/passwd|boot\.ini|windows\\system32)"), "T1083"),
    "Command injection": (re.compile(
        r"(?i)((;|\||%3b|%7c)(\s|\+|%20)*(cat|ls|wget|curl|nc|bash|sh|whoami|id)\b|\$\(|`)"),
     "T1059"),
}
PROBE_RE = re.compile(
    r"(?i)(/\.env|/\.git/|wp-login\.php|wp-admin|xmlrpc\.php|phpmyadmin|/\.aws|"
    r"server-status|/admin\b|/config\.php|/backup)")
SCANNER_UA = re.compile(
    r"(?i)(sqlmap|nikto|nmap|masscan|acunetix|dirbuster|gobuster|wfuzz|hydra|zgrab|nessus|nuclei)")

# ---------------------------------------------------------------- data classes
@dataclass
class Finding:
    severity: str
    rule: str
    source: str
    title: str
    evidence: str
    next_steps: str
    count: int = 0
    mitre: str = ""
    first_seen: str = ""
    last_seen: str = ""

@dataclass
class Report:
    findings: list = field(default_factory=list)
    rows: int = 0
    valid: int = 0
    skipped: list = field(default_factory=list)   # (row_number, reason)
    warnings: list = field(default_factory=list)
    kinds: dict = field(default_factory=dict)
    mapping: dict = field(default_factory=dict)
    data: pd.DataFrame | None = None

    def count(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

class LogError(Exception):
    """Raised when a file cannot be analysed at all."""

# ---------------------------------------------------------------- loading + mapping
def load_csv(source) -> pd.DataFrame:
    """Read a CSV (path or uploaded file). Everything is kept as text."""
    if hasattr(source, "read"):
        data = source.read()
    else:
        with open(source, "rb") as fh:
            data = fh.read()
    if isinstance(data, str):
        data = data.encode()
    for enc in ("utf-8-sig", "latin-1"):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    try:
        df = pd.read_csv(io.StringIO(text), dtype=str, sep=None, engine="python")
    except Exception as exc:
        raise LogError(f"Could not read the file as CSV: {exc}") from exc
    if df.empty:
        raise LogError("The file has no data rows.")
    df.columns = [str(c).strip() for c in df.columns]
    return df

def auto_map(columns) -> dict:
    """Guess which of the file's columns is which canonical field."""
    by_norm = {}
    for c in columns:
        by_norm.setdefault(_norm(c), c)
    mapping, used = {}, set()
    for canon, names in ALIASES.items():
        for name in names:
            col = by_norm.get(_norm(name))
            if col is not None and col not in used:
                mapping[canon] = col
                used.add(col)
                break
    return mapping

# ---------------------------------------------------------------- preparation
def _clean_ip(value):
    if pd.isna(value):
        return pd.NA
    v = str(value).strip().strip("[]")
    if v.count(":") == 1:                     # "1.2.3.4:5555"
        v = v.split(":")[0]
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return pd.NA

def _parse_time(series: pd.Series) -> pd.Series:
    nums = pd.to_numeric(series, errors="coerce")
    if nums.notna().mean() > 0.9:             # Splunk epoch seconds
        return pd.to_datetime(nums, unit="s", utc=True, errors="coerce")
    return pd.to_datetime(series, utc=True, errors="coerce", format="mixed")

def prepare(raw: pd.DataFrame, mapping: dict | None = None,
            value_map: dict | None = None) -> Report:
    """Turn any supported CSV into one clean table plus skipped-row reasons."""
    rep = Report(rows=len(raw))
    mapping = dict(auto_map(raw.columns) if mapping is None else mapping)
    mapping = {k: v for k, v in mapping.items() if v in raw.columns}
    rep.mapping = mapping

    if "source_ip" not in mapping and "message" not in mapping:
        raise LogError(
            "Could not find a source IP column (or a raw message column). "
            "Use the column mapping in the sidebar to point to it.")

    n = pd.DataFrame(index=raw.index)
    for canon in CANONICAL:
        if canon in mapping:
            col = raw[mapping[canon]].astype("object")
            col = col.map(lambda v: pd.NA if pd.isna(v) or str(v).strip() in ("", "-", "N/A", "null")
                          else str(v).strip())
            n[canon] = col
        else:
            n[canon] = pd.Series(pd.NA, index=raw.index, dtype="object")

    # raw text (Splunk _raw) -> fill whatever is still missing
    if "message" in mapping:
        parsed = n["message"].map(parse_raw_line)
        for fld in ("source_ip", "username", "status", "url", "http_status", "user_agent"):
            vals = parsed.map(lambda d, f=fld: d.get(f, pd.NA))
            n[fld] = n[fld].where(n[fld].notna(), vals)
        web_ts = parsed.map(lambda d: d.get("_web_ts", pd.NA))
        if n["timestamp"].isna().all() and web_ts.notna().any():
            n["timestamp"] = web_ts.map(
                lambda s: pd.NA if pd.isna(s) else
                pd.to_datetime(s, format="%d/%b/%Y:%H:%M:%S %z", errors="coerce"))

    # a "status" column full of 200/404/500 is really the HTTP status
    num = pd.to_numeric(n["status"], errors="coerce")
    if n["http_status"].isna().all() and num.notna().mean() > 0.8 and num.between(100, 599).mean() > 0.8:
        n["http_status"] = n["status"]
        n["status"] = pd.NA

    # event id + status
    n["event_id"] = n["event_id"].map(
        lambda v: pd.NA if pd.isna(v) else re.sub(r"\.0$", "", str(v)))
    vm = {_norm(k): v for k, v in (value_map or {}).items()}
    n["status"] = n["status"].map(
        lambda v: vm.get(_norm(v), normalise_status(v)) if not pd.isna(v) else pd.NA)
    from_event = n["event_id"].map(lambda v: WIN_LOGON.get(v, pd.NA) if not pd.isna(v) else pd.NA)
    n["status"] = n["status"].where(n["status"].notna(), from_event)

    # timestamp
    if n["timestamp"].notna().any():
        n["timestamp"] = _parse_time(n["timestamp"].astype("object"))
    else:
        n["timestamp"] = pd.NaT
    if "timestamp" in mapping:
        bad_ts = n["timestamp"].isna()
        if bad_ts.mean() > 0.5:
            rep.warnings.append(
                "Most timestamps could not be read, so time information is ignored "
                "(rows are analysed in file order).")
            ts_bad_rows = pd.Series(False, index=n.index)
        else:
            ts_bad_rows = bad_ts
    else:
        rep.warnings.append("No timestamp column found; rows are analysed in file order.")
        ts_bad_rows = pd.Series(False, index=n.index)

    n["source_ip"] = n["source_ip"].map(_clean_ip)

    # what kind of event is each row?
    def kind_of(r):
        et = _norm(r["event_type"]) if not pd.isna(r["event_type"]) else ""
        eid = r["event_id"]
        if not pd.isna(eid) and eid in AUDIT_EVENTS:
            return "audit"
        if not pd.isna(eid) and eid in WIN_LOGON:
            return "auth"
        if any(k in et for k in ("network", "firewall", "traffic", "conn")):
            return "network"
        if any(k in et for k in ("login", "auth", "ssh", "logon")):
            return "auth"
        if any(k in et for k in ("web", "http", "access")):
            return "web"
        if not pd.isna(r["url"]) or not pd.isna(r["http_status"]):
            return "web"
        if r["status"] in ("blocked", "allowed"):
            return "network"
        if r["status"] in ("failed", "success"):
            return "auth"
        if not pd.isna(r["destination_port"]):
            return "network"
        return "other"
    n["kind"] = n.apply(kind_of, axis=1)

    # validity
    is_audit = n["kind"] == "audit"
    no_ip = n["source_ip"].isna()
    n.loc[is_audit & no_ip, "source_ip"] = "n/a"
    reasons = pd.Series(pd.NA, index=n.index, dtype="object")
    reasons[no_ip & ~is_audit] = "WARNING: invalid or missing source IP"
    reasons[ts_bad_rows & reasons.isna()] = "WARNING: invalid timestamp"
    skipped = reasons.notna()
    rep.skipped = [(int(i) + 2, reasons[i]) for i in n.index[skipped]]
    rep.valid = int((~skipped).sum())
    n = n[~skipped].copy()

    n["destination_port"] = pd.to_numeric(n["destination_port"], errors="coerce")
    n.loc[~n["destination_port"].between(0, 65535), "destination_port"] = pd.NA
    n["http_status"] = pd.to_numeric(n["http_status"], errors="coerce")
    n = n.sort_values("timestamp", kind="stable", na_position="last")
    rep.kinds = n["kind"].value_counts().to_dict()
    rep.data = n
    if rep.valid == 0:
        rep.warnings.append(
            "No valid events. Check the column mapping and that IP/timestamp values are real.")
    return rep

# ---------------------------------------------------------------- detection helpers
def _has(series: pd.Series, rx) -> pd.Series:
    """True where the regex matches (plain re, so no pandas capture-group warning)."""
    return series.map(lambda v: bool(rx.search(v)) if isinstance(v, str) else False).astype(bool)

def _span(g: pd.DataFrame):
    ts = g["timestamp"].dropna()
    if ts.empty:
        return "", ""
    return ts.min().strftime("%Y-%m-%d %H:%M:%S"), ts.max().strftime("%Y-%m-%d %H:%M:%S")

def _top(series, k=3):
    s = series.dropna().map(lambda v: str(int(v)) if isinstance(v, float) and v == int(v) else str(v))
    return ", ".join(s.value_counts().head(k).index) if len(s) else "n/a"

def _finding(sev, rule, src, title, evidence, steps, g, mitre="", count=None):
    first, last = _span(g)
    return Finding(sev, rule, src, title, evidence, steps,
                   len(g) if count is None else count, mitre, first, last)

# ---------------------------------------------------------------- detections
def detect(d: pd.DataFrame, T: dict) -> list[Finding]:
    out: list[Finding] = []

    # --- authentication ------------------------------------------------
    auth = d[d["kind"] == "auth"]
    fails = auth[auth["status"] == "failed"]
    flagged_ips = set()
    for ip, g in fails.groupby("source_ip"):
        users = g["username"].dropna().nunique()
        if users >= T["spray_users"]:
            flagged_ips.add(ip)
            out.append(_finding(
                "HIGH", "Password spraying", ip,
                f"Password spraying from {ip}",
                f"{len(g)} failed logins against {users} different accounts "
                f"(e.g. {_top(g['username'])}).",
                "Block or rate-limit the IP, check whether any of the targeted accounts "
                "later logged in successfully, and enforce MFA.", g, "T1110.003"))
        elif len(g) >= T["failed_logins"]:
            flagged_ips.add(ip)
            out.append(_finding(
                "HIGH", "Brute force login", ip,
                f"Brute force login attempts from {ip}",
                f"{len(g)} failed logins; accounts targeted: {_top(g['username'])}.",
                "Block the IP, review the targeted accounts, and check for a later "
                "successful login from the same IP.", g, "T1110.001"))

    # failures followed by a success = possible compromise
    compromised = {}
    for (ip, user), g in auth.groupby(["source_ip", auth["username"].fillna("(unknown)")]):
        run = 0
        for row in g.itertuples():
            if row.status == "failed":
                run += 1
            elif row.status == "success":
                if run >= T["compromise_fails"]:
                    compromised.setdefault(ip, []).append((user, run, row.timestamp))
                run = 0
    for ip, items in compromised.items():
        users = ", ".join(sorted({u for u, _, _ in items}))
        worst = max(r for _, r, _ in items)
        g = auth[auth["source_ip"] == ip]
        out.append(_finding(
            "CRITICAL", "Success after failures", ip,
            f"Possible account compromise from {ip}",
            f"Login succeeded for {users} after up to {worst} failed attempts from the same IP.",
            "Treat the account as compromised: reset the password, kill active sessions, "
            "review what the account did after the login, and block the IP.",
            g, "T1078", count=len(items)))

    # --- network / firewall -------------------------------------------
    net = d[d["kind"] == "network"]
    scanners = set()
    for ip, g in net.groupby("source_ip"):
        ports = g["destination_port"].dropna().nunique()
        hosts = g["destination_ip"].dropna().nunique()
        if ports >= T["scan_ports"]:
            scanners.add(ip)
            out.append(_finding(
                "MEDIUM", "Port scan", ip, f"Port scan from {ip}",
                f"{ports} different destination ports probed"
                f"{f' across {hosts} host(s)' if hosts else ''}.",
                "Check whether the IP is internal or external, block it at the firewall, "
                "and confirm none of the probed ports are unexpectedly open.",
                g, "T1046", count=ports))
        elif hosts >= T["sweep_hosts"]:
            scanners.add(ip)
            out.append(_finding(
                "MEDIUM", "Host sweep", ip, f"Host sweep from {ip}",
                f"{hosts} different destination hosts contacted "
                f"(ports: {_top(g['destination_port'])}).",
                "Identify the source, block it if unauthorised, and check targeted hosts.",
                g, "T1046", count=hosts))
        blocks = g[g["status"] == "blocked"]
        if len(blocks) >= T["fw_blocks"] and ip not in scanners:
            out.append(_finding(
                "MEDIUM", "Repeated firewall blocks", ip, f"Repeated blocked traffic from {ip}",
                f"{len(blocks)} connections blocked; top ports: {_top(blocks['destination_port'])}.",
                "Confirm the traffic is unwanted, add a block rule, and watch for the IP "
                "reaching other services.", blocks, "T1595"))

    # --- web ------------------------------------------------------------
    web = d[d["kind"] == "web"]
    url = web["url"].fillna("")
    for attack, (rx, tech) in WEB_ATTACKS.items():
        hits = web[_has(url, rx)]
        for ip, g in hits.groupby("source_ip"):
            ok = int((g["http_status"] == 200).sum())
            sev = "CRITICAL" if ok and attack in ("SQL injection", "Path traversal",
                                                   "Command injection") else "HIGH"
            note = (f" {ok} request(s) got HTTP 200, so the attack may have worked."
                    if sev == "CRITICAL" else "")
            out.append(_finding(
                sev, attack, ip, f"{attack} attempts from {ip}",
                f"{len(g)} request(s) with attack patterns, e.g. {_top(g['url'], 2)}.{note}",
                "Block the IP/WAF-rule the pattern, review application logs for the same "
                "requests, and verify the endpoint validates input.", g, tech))
    ua = web["user_agent"].fillna("")
    for ip, g in web[_has(ua, SCANNER_UA)].groupby("source_ip"):
        out.append(_finding(
            "HIGH", "Scanner tool detected", ip, f"Attack tool user-agent from {ip}",
            f"{len(g)} request(s) using scanner user-agent: {_top(g['user_agent'], 2)}.",
            "Block the IP and review what the scanner reached.", g, "T1595.002"))
    probes = web[_has(url, PROBE_RE)]
    for ip, g in probes.groupby("source_ip"):
        if len(g) >= T["probe_hits"]:
            out.append(_finding(
                "MEDIUM", "Sensitive path probing", ip, f"Probing of sensitive paths from {ip}",
                f"{len(g)} requests to admin/config paths, e.g. {_top(g['url'])}.",
                "Make sure these paths are not exposed, and block the IP if it keeps probing.",
                g, "T1595.003"))
    for ip, g in web[web["http_status"] == 404].groupby("source_ip"):
        if len(g) >= T["web_404"]:
            out.append(_finding(
                "MEDIUM", "Directory enumeration", ip, f"Directory enumeration from {ip}",
                f"{len(g)} HTTP 404 responses, which looks like content discovery.",
                "Rate-limit or block the IP and check whether any hidden path returned 200.",
                g, "T1595.003"))
    for ip, g in web[web["http_status"] == 401].groupby("source_ip"):
        if len(g) >= T["failed_logins"]:
            out.append(_finding(
                "HIGH", "Web login brute force", ip, f"Web login failures from {ip}",
                f"{len(g)} HTTP 401 responses (e.g. {_top(g['url'], 2)}).",
                "Add rate limiting/lockout on the login endpoint and block the IP.",
                g, "T1110"))

    # --- Windows audit events ------------------------------------------
    aud = d[d["kind"] == "audit"]
    for (eid, user), g in aud.groupby(["event_id", aud["username"].fillna("(not given)")]):
        sev, title, tech, why = AUDIT_EVENTS[eid]
        out.append(_finding(
            sev, f"Event {eid}", g["source_ip"].iloc[0],
            f"{title} (Event {eid})",
            f"{len(g)} event(s); account: {user}. {why}",
            "Confirm this was an approved change; if not, treat it as possible "
            "persistence or defence evasion and investigate the account/host.",
            g, tech))

    # --- INFO: below-threshold activity --------------------------------
    for ip, g in fails.groupby("source_ip"):
        if ip not in flagged_ips and ip not in compromised and len(g) >= 2:
            out.append(_finding(
                "INFO", "Below threshold", ip, f"Some failed logins from {ip}",
                f"{len(g)} failed logins, below the alert threshold of {T['failed_logins']}.",
                "No action needed unless this repeats; INFO is not the same as safe.", g))

    if not out:
        out.append(Finding(
            "INFO", "No match", "-", "No known attack pattern found",
            "None of the built-in rules matched. This does NOT prove the logs are safe.",
            "Review the data manually or load more log sources.", len(d)))

    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    out.sort(key=lambda f: (order[f.severity], -f.count))
    return out

# ---------------------------------------------------------------- public API
def analyze(raw: pd.DataFrame, mapping: dict | None = None,
            thresholds: dict | None = None, value_map: dict | None = None) -> Report:
    T = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    rep = prepare(raw, mapping, value_map)
    if rep.data is not None and len(rep.data):
        rep.findings = detect(rep.data, T)
    return rep

def findings_frame(findings) -> pd.DataFrame:
    cols = ["severity", "rule", "source", "title", "count", "mitre",
            "first_seen", "last_seen", "evidence", "next_steps"]
    return pd.DataFrame([{c: getattr(f, c) for c in cols} for f in findings], columns=cols)
