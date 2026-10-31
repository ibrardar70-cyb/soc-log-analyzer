# SOC Log Analyzer

A Streamlit dashboard that analyses CSV log exports (Splunk, Windows, Linux SSH, web server, firewall) and flags common attack patterns with severity, evidence, MITRE ATT&CK tags and suggested next steps.

> Built as a learning project for SOC analyst skills. It is **not** a SIEM replacement.

## Screenshots

**Windows incident: spraying, brute force, compromise, persistence, log clearing**
![Windows incident](screenshots/windows.png)

**Web attacks: SQL injection, path traversal, scanner tools, enumeration**
![Web attacks](screenshots/web.png)

**Clean baseline: no attack, so no false alarm**
![Clean baseline](screenshots/clean.png)

## What it detects

| Log type | Detections | MITRE ATT&CK |
|---|---|---|
| Windows Security | brute force, password spraying, success after failures, log cleared (1102), account created (4720), admin group change (4732), new service (7045), scheduled task (4698) | T1110, T1078, T1070.001, T1136, T1098, T1543.003, T1053.005 |
| Linux SSH | brute force, password spraying, success after failures (also parses raw `sshd` lines) | T1110, T1078 |
| Web access | SQL injection, XSS, path traversal, command injection, scanner tools, sensitive path probing, 404 enumeration, 401 brute force | T1190, T1083, T1595 |
| Firewall | port scan, host sweep, repeated blocks | T1046, T1595 |

Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO.

## How it works
1. **Load** the CSV as text.
2. **Auto-detect columns** (`src_ip`, `clientip`, `Source_Network_Address` all become `source_ip`). Wrong guess? Fix it in the sidebar column mapping.
3. **Normalise** values (`Audit Failure`, `FAIL`, `4625` all become `failed`), validate IPs and timestamps, and parse raw log lines with regex.
4. **Detect** by grouping events per source IP and applying rules with adjustable thresholds.
5. **Display** findings, charts and per-finding next steps in Streamlit.

## Run it
```bash
git clone https://github.com/ibrardar70-cyb/soc-log-analyzer.git
cd soc-log-analyzer
pip install -r requirements.txt
python test_toolkit.py          # 9 tests should pass
python -m streamlit run app.py  # opens http://localhost:8501
```
Pick a file from the sidebar sample dropdown, or upload your own CSV.

## Project files
- `app.py` - Streamlit dashboard
- `soc_toolkit.py` - detection engine (pandas + regex)
- `make_samples.py` - generates fake sample logs (documentation-range IPs only)
- `test_toolkit.py` - automated tests
- `sample_logs/` - practice logs with planted attacks (all IPs are fake)

## Limitations
- Only the rules above; no malware or phishing detection.
- **INFO means "no rule matched", not "safe".**
- Fixed thresholds (adjustable by slider), no machine learning.
- "Success after failures" has no time window yet, so it can raise false positives.
- Works on CSV files, not live data.

## Skills shown
Python, pandas, regex log parsing, Streamlit, detection engineering, MITRE ATT&CK mapping, false-positive tuning, automated testing.
