"""app.py - SOC Log Analyzer dashboard.   Run:  python -m streamlit run app.py"""
from pathlib import Path

import pandas as pd
import streamlit as st

import soc_toolkit as tk

st.set_page_config(page_title="SOC Log Analyzer", page_icon="🛡️", layout="wide")

SAMPLES = Path(__file__).parent / "sample_logs"
COLORS = {"CRITICAL": "#7f1d1d", "HIGH": "#dc2626", "MEDIUM": "#f59e0b",
          "LOW": "#3b82f6", "INFO": "#6b7280"}
FIELD_HELP = {
    "timestamp": "When the event happened", "source_ip": "Who did it (attacker/client IP)",
    "username": "Account involved", "event_id": "Windows EventCode / ID",
    "event_type": "Kind of log (optional)", "status": "success / failed / allow / deny",
    "http_status": "Web response code (200, 404...)", "destination_ip": "Target host",
    "destination_port": "Target port", "url": "Requested URL / path",
    "user_agent": "Browser or tool name", "message": "Raw log line (e.g. Splunk _raw)",
}

st.title("🛡️ SOC Log Analyzer")
st.caption("Upload a CSV export from Splunk, Windows, Linux, a web server or a firewall.")

# ------------------------------------------------------------------ sidebar: input
with st.sidebar:
    st.header("1. Log file")
    upload = st.file_uploader("Upload CSV", type=["csv", "txt"])
    samples = sorted(p.name for p in SAMPLES.glob("*.csv")) if SAMPLES.exists() else []
    sample = st.selectbox("...or try a sample", samples) if samples else None

if upload is not None:
    source, label = upload, upload.name
elif sample:
    source, label = SAMPLES / sample, sample
else:
    st.info("Upload a CSV file in the sidebar to begin.")
    st.stop()

try:
    raw = tk.load_csv(source)
except tk.LogError as exc:
    st.error(f"Could not analyse the file: {exc}")
    st.stop()

# ------------------------------------------------------------------ sidebar: mapping + thresholds
auto = tk.auto_map(raw.columns)
with st.sidebar:
    st.header("2. Column mapping")
    st.caption("Auto-detected. Change a dropdown if a guess is wrong.")
    mapping = {}
    with st.expander("Columns", expanded="source_ip" not in auto and "message" not in auto):
        options = ["(none)"] + list(raw.columns)
        for fld in tk.CANONICAL:
            default = options.index(auto[fld]) if fld in auto else 0
            choice = st.selectbox(fld, options, index=default, help=FIELD_HELP[fld],
                                  key=f"map_{label}_{fld}")
            if choice != "(none)":
                mapping[fld] = choice

    # status values we do not recognise -> let the user decide what they mean
    value_map = {}
    if "status" in mapping:
        vals = raw[mapping["status"]].dropna().astype(str).unique()
        unknown = [v for v in vals if pd.isna(tk.normalise_status(v)) and not v.strip().isdigit()][:8]
        if unknown:
            with st.expander("Status values", expanded=True):
                st.caption("These values are not recognised. What do they mean?")
                for v in unknown:
                    pick = st.selectbox(f"“{v}” means", ["ignore", "failed", "success", "blocked", "allowed"],
                                        key=f"val_{label}_{v}")
                    if pick != "ignore":
                        value_map[v] = pick

    st.header("3. Thresholds")
    T = dict(tk.DEFAULT_THRESHOLDS)
    with st.expander("Detection sensitivity"):
        T["failed_logins"] = st.slider("Failed logins → brute force", 2, 20, T["failed_logins"])
        T["spray_users"] = st.slider("Distinct accounts → spraying", 2, 15, T["spray_users"])
        T["compromise_fails"] = st.slider("Failures before success", 1, 10, T["compromise_fails"])
        T["scan_ports"] = st.slider("Distinct ports → port scan", 3, 50, T["scan_ports"])
        T["sweep_hosts"] = st.slider("Distinct hosts → sweep", 3, 50, T["sweep_hosts"])
        T["fw_blocks"] = st.slider("Firewall blocks → alert", 3, 100, T["fw_blocks"])
        T["web_404"] = st.slider("HTTP 404s → enumeration", 5, 100, T["web_404"])

# ------------------------------------------------------------------ analyse
try:
    rep = tk.analyze(raw, mapping=mapping, thresholds=T, value_map=value_map)
except tk.LogError as exc:
    st.error(f"Could not analyse the file: {exc}")
    st.stop()

for w in rep.warnings:
    st.warning(w)

kinds = ", ".join(f"{k}: {v}" for k, v in rep.kinds.items()) or "none"
st.caption(f"**{label}**  ·  detected event types → {kinds}")

cols = st.columns(8)
cols[0].metric("Rows read", rep.rows)
cols[1].metric("Valid events", rep.valid)
cols[2].metric("Skipped", len(rep.skipped))
for c, sev in zip(cols[3:], tk.SEVERITY_ORDER):
    c.metric(sev, rep.count(sev))

if rep.skipped:
    with st.expander(f"{len(rep.skipped)} row(s) skipped - click to see why"):
        st.dataframe(pd.DataFrame(rep.skipped, columns=["row", "reason"]), hide_index=True)

if not rep.findings:
    st.error("No valid events to analyse. Check the column mapping in the sidebar.")
    st.stop()

# ------------------------------------------------------------------ findings table
st.subheader("Findings")
chosen = st.multiselect("Show severities", tk.SEVERITY_ORDER, default=tk.SEVERITY_ORDER)
fdf = tk.findings_frame(rep.findings)
view = fdf[fdf["severity"].isin(chosen)]

def colour(row):
    return [f"background-color: {COLORS[row['severity']]}; color: white" if c == "severity" else ""
            for c in row.index]

st.dataframe(view.drop(columns=["next_steps"]).style.apply(colour, axis=1),
             hide_index=True, width="stretch")
st.download_button("⬇ Download findings.csv", fdf.to_csv(index=False).encode(),
                   "findings.csv", "text/csv")

# ------------------------------------------------------------------ charts
st.subheader("Charts")
c1, c2 = st.columns(2)
with c1:
    st.markdown("**Findings by severity**")
    sev = pd.Series({s: rep.count(s) for s in tk.SEVERITY_ORDER})
    st.bar_chart(sev)
with c2:
    st.markdown("**Top source IPs by findings**")
    ip_counts = fdf[fdf["source"].str.match(r"^[0-9a-fA-F:.]+$")]["source"].value_counts().head(10)
    if len(ip_counts):
        st.bar_chart(ip_counts)
    else:
        st.caption("No IP-based findings.")

d = rep.data
c3, c4 = st.columns(2)
with c3:
    st.markdown("**Failed / blocked events per IP**")
    bad = d[d["status"].isin(["failed", "blocked"])]["source_ip"].value_counts().head(10)
    if len(bad):
        st.bar_chart(bad)
    else:
        st.caption("None found.")
with c4:
    st.markdown("**Events over time**")
    ts = d.dropna(subset=["timestamp"])
    if len(ts) > 1 and ts["timestamp"].nunique() > 1:
        span = ts["timestamp"].max() - ts["timestamp"].min()
        freq = "min" if span < pd.Timedelta(hours=6) else "h"
        st.line_chart(ts.set_index("timestamp").resample(freq).size())
    else:
        st.caption("Not enough timestamp data.")

# ------------------------------------------------------------------ details
st.subheader("Details and suggested next steps")
for f in rep.findings:
    if f.severity not in chosen:
        continue
    with st.expander(f"[{f.severity}] {f.title}"):
        st.markdown(f"**Evidence:** {f.evidence}")
        st.markdown(f"**Next steps:** {f.next_steps}")
        meta = [f"Rule: {f.rule}"]
        if f.mitre:
            meta.append(f"MITRE ATT&CK: {f.mitre}")
        if f.first_seen:
            meta.append(f"Seen: {f.first_seen} → {f.last_seen} UTC")
        st.caption("  ·  ".join(meta))

with st.expander("Normalised data (what the engine actually analysed)"):
    st.dataframe(d.head(500), hide_index=True)

st.caption("INFO means 'no rule matched', not 'safe'. Rules cover common patterns only.")
