"""Smoke tests for regexlab. No network. Run: python -m pytest tests/ -q

Also runnable directly: python tests/test_smoke.py
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from regexlab import (  # noqa: E402
    TOOL_NAME, TOOL_VERSION, SECURITY_PATTERNS,
    explain_pattern, test_pattern, benchmark_pattern, scan_text,
    detect_redos_risk,
)
from regexlab.cli import main, _redact  # noqa: E402


def test_metadata():
    assert TOOL_NAME == "regexlab"
    assert TOOL_VERSION
    assert len(SECURITY_PATTERNS) >= 5


def test_explain_basic():
    parts = explain_pattern(r"\d{3}-\w+")
    tokens = [t for t, _ in parts]
    assert r"\d" in tokens
    assert any("-" == t for t in tokens)


def test_test_pattern_matches():
    res = test_pattern(r"\d+", "abc 123 def 456")
    assert res.valid
    assert res.match_count == 2
    assert res.matches[0].text == "123"


def test_test_pattern_invalid():
    res = test_pattern("(unclosed", "x")
    assert not res.valid
    assert res.error


def test_redos_detection():
    risk, notes = detect_redos_risk(r"(a+)+$")
    assert risk == "high"
    assert notes
    low, _ = detect_redos_risk(r"\d{3}")
    assert low == "none"


def test_benchmark_runs():
    res = benchmark_pattern(r"\d+", "1 22 333", iterations=50)
    assert res.valid
    assert res.iterations == 50
    assert res.match_count == 3
    assert res.total_seconds >= 0.0


def test_scan_finds_secrets():
    text = "key AKIAIOSFODNN7EXAMPLE and mail a@b.com"
    matches = scan_text(text)
    names = {m.pattern for m in matches}
    assert "aws_access_key_id" in names
    assert "email_address" in names


def test_scan_min_severity_filter():
    text = "a@b.com"  # email is 'low'
    assert scan_text(text, min_severity="high") == []
    assert scan_text(text, min_severity="low")


def test_redact():
    assert _redact("AKIAIOSFODNN7EXAMPLE").startswith("AKI")
    assert "*" in _redact("AKIAIOSFODNN7EXAMPLE")


def test_cli_version(capsys=None):
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0


def test_cli_scan_exit_code(tmp_path=None):
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        fh.write("token AKIAIOSFODNN7EXAMPLE")
        path = fh.name
    try:
        rc = main(["scan", "-i", path, "--format", "json"])
        assert rc == 1  # findings -> non-zero
    finally:
        os.unlink(path)


def test_cli_test_no_match_exit():
    rc = main(["test", r"zzz", "-t", "abc", "--format", "json"])
    assert rc == 1  # no matches -> non-zero


def test_cli_explain_runs():
    rc = main(["explain", r"\d+", "--format", "json"])
    assert rc == 0


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: {exc}")
    sys.exit(1 if failures else 0)
