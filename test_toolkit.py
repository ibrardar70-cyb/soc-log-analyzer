"""Run with:  python -m pytest -q   (or: python test_toolkit.py)"""
import warnings
from pathlib import Path

import soc_toolkit as s

LOGS = Path(__file__).parent / "sample_logs"
warnings.simplefilter("error")          # any pandas warning = test failure

def run(name, **kw):
    return s.analyze(s.load_csv(LOGS / name), **kw)

def rules(rep):
    return {(f.severity, f.rule, f.source) for f in rep.findings}

def test_windows_security():
    r = run("sample_windows_security.csv")
    got = rules(r)
    assert ("HIGH", "Brute force login", "203.0.113.50") in got
    assert ("HIGH", "Password spraying", "203.0.113.60") in got
    assert ("CRITICAL", "Success after failures", "198.51.100.77") in got
    assert ("CRITICAL", "Event 1102", "n/a") in got            # audit log cleared
    assert ("HIGH", "Event 4732", "n/a") in got                # added to admins
    assert ("MEDIUM", "Event 4720", "n/a") in got              # account created
    assert r.skipped == []                                     # "-" IPs kept for audit events

def test_linux_ssh_from_raw_column():
    got = rules(run("sample_linux_ssh.csv"))
    assert ("HIGH", "Brute force login", "203.0.113.50") in got
    assert ("HIGH", "Password spraying", "203.0.113.60") in got
    assert ("CRITICAL", "Success after failures", "198.51.100.77") in got

def test_web_access():
    got = rules(run("sample_web_access.csv"))
    assert ("CRITICAL", "SQL injection", "203.0.113.99") in got
    assert ("CRITICAL", "Path traversal", "203.0.113.99") in got
    assert ("HIGH", "Cross-site scripting", "203.0.113.99") in got
    assert ("HIGH", "Scanner tool detected", "203.0.113.99") in got
    assert ("MEDIUM", "Directory enumeration", "203.0.113.100") in got
    assert ("MEDIUM", "Sensitive path probing", "203.0.113.101") in got
    assert ("HIGH", "Web login brute force", "203.0.113.102") in got

def test_firewall():
    got = rules(run("sample_firewall.csv"))
    assert ("MEDIUM", "Port scan", "198.51.100.88") in got
    assert ("MEDIUM", "Host sweep", "198.51.100.90") in got
    assert ("MEDIUM", "Repeated firewall blocks", "203.0.113.120") in got

def test_original_format_still_works():
    r = run("sample_original_format.csv")
    assert (r.count("HIGH"), r.count("MEDIUM")) == (1, 1)

def test_threshold_slider_changes_result():
    r = run("sample_original_format.csv", thresholds={"failed_logins": 7})
    assert r.count("HIGH") == 0 and r.count("INFO") >= 1

def test_invalid_ip_rows_skipped_with_reason():
    r = run("test_invalid_ip.csv")
    assert (r.rows, r.valid, len(r.skipped)) == (3, 1, 2)
    assert all("WARNING" in why for _, why in r.skipped)

def test_unknown_columns_error_then_manual_mapping():
    raw = s.load_csv(LOGS / "test_unknown_columns.csv")
    try:
        s.analyze(raw)
        assert False, "should have raised LogError"
    except s.LogError:
        pass
    r = s.analyze(raw, mapping={"timestamp": "when", "source_ip": "attacker",
                                "username": "who", "status": "result"},
                  value_map={"FAIL": "failed"})
    assert r.count("HIGH") == 1

def test_no_attack_is_info_not_safe():
    r = s.analyze(s.load_csv(LOGS / "test_invalid_ip.csv"))
    assert r.findings[0].severity == "INFO" and "NOT prove" in r.findings[0].evidence

if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("PASS", name)
