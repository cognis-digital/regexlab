"""Hardening tests: edge cases, bad input, and error-path coverage.

Covers: missing files, invalid flags, out-of-range args, empty input,
invalid min_severity, non-zero exit codes on CLI error paths.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from regexlab.core import (
    benchmark_pattern,
    scan_text,
    parse_flags,
)
from regexlab.core import test_pattern as _test_pattern  # alias avoids pytest collection
from regexlab.cli import main


# ---------------------------------------------------------------------------
# core.parse_flags
# ---------------------------------------------------------------------------
def test_parse_flags_unknown_raises():
    with pytest.raises(ValueError, match="unknown flag"):
        parse_flags("z")


def test_parse_flags_empty_string():
    assert parse_flags("") == 0


# ---------------------------------------------------------------------------
# core.test_pattern edge cases
# ---------------------------------------------------------------------------
def test_test_pattern_empty_subject():
    res = _test_pattern(r"\d+", "")
    assert res.valid
    assert res.match_count == 0
    assert res.matches == []


def test_test_pattern_empty_pattern_matches_everything():
    res = _test_pattern("", "abc")
    assert res.valid
    # empty pattern matches at every position (4 positions for "abc")
    assert res.match_count >= 1


def test_test_pattern_max_matches_clamps():
    # "aaa" has 3 single-char matches for \w
    res = _test_pattern(r"\w", "aaa", max_matches=2)
    assert res.match_count == 2


def test_test_pattern_max_matches_below_one_raises():
    with pytest.raises(ValueError, match="max_matches"):
        _test_pattern(r"\d", "1", max_matches=0)


def test_test_pattern_invalid_flag_raises():
    with pytest.raises(ValueError, match="unknown flag"):
        _test_pattern(r"\d", "1", flag_str="z")


# ---------------------------------------------------------------------------
# core.benchmark_pattern edge cases
# ---------------------------------------------------------------------------
def test_benchmark_zero_iterations_raises():
    with pytest.raises(ValueError, match="iterations"):
        benchmark_pattern(r"\d", "1", iterations=0)


def test_benchmark_negative_iterations_raises():
    with pytest.raises(ValueError, match="iterations"):
        benchmark_pattern(r"\d", "1", iterations=-5)


def test_benchmark_empty_subject():
    res = benchmark_pattern(r"\d+", "", iterations=10)
    assert res.valid
    assert res.match_count == 0
    assert res.total_seconds >= 0.0


# ---------------------------------------------------------------------------
# core.scan_text edge cases
# ---------------------------------------------------------------------------
def test_scan_empty_subject():
    matches = scan_text("")
    assert matches == []


def test_scan_invalid_min_severity_raises():
    with pytest.raises(ValueError, match="min_severity"):
        scan_text("some text", min_severity="bogus")


def test_scan_empty_patterns_list():
    matches = scan_text("AKIAIOSFODNN7EXAMPLE", patterns=[])
    assert matches == []


def test_scan_max_matches_clamps():
    # A text containing many email addresses
    text = " ".join(f"user{i}@example.com" for i in range(20))
    matches = scan_text(text, max_matches=3)
    assert len(matches) == 3


def test_scan_max_matches_below_one_raises():
    with pytest.raises(ValueError, match="max_matches"):
        scan_text("text", max_matches=0)


# ---------------------------------------------------------------------------
# CLI: missing / invalid input file
# ---------------------------------------------------------------------------
def test_cli_missing_input_file_exits_2(tmp_path):
    nonexistent = str(tmp_path / "no_such_file.txt")
    rc = main(["scan", "-i", nonexistent])
    assert rc == 2


def test_cli_test_missing_input_file_exits_2(tmp_path):
    nonexistent = str(tmp_path / "ghost.txt")
    rc = main(["test", r"\d+", "-i", nonexistent])
    assert rc == 2


# ---------------------------------------------------------------------------
# CLI: invalid range arguments
# ---------------------------------------------------------------------------
def test_cli_bench_zero_iterations_exits_2():
    rc = main(["bench", r"\d+", "-t", "hello", "--iterations", "0"])
    assert rc == 2


def test_cli_test_zero_max_matches_exits_2():
    rc = main(["test", r"\d+", "-t", "123", "--max-matches", "0"])
    assert rc == 2


# ---------------------------------------------------------------------------
# CLI: invalid regex exits 2
# ---------------------------------------------------------------------------
def test_cli_test_invalid_regex_exits_2():
    rc = main(["test", "(unclosed", "-t", "abc"])
    assert rc == 2


def test_cli_bench_invalid_regex_exits_2():
    rc = main(["bench", "[bad", "-t", "abc"])
    assert rc == 2


# ---------------------------------------------------------------------------
# CLI: empty text (no matches) still exits 1 for test/scan
# ---------------------------------------------------------------------------
def test_cli_test_empty_subject_exits_1():
    rc = main(["test", r"\d+", "-t", ""])
    assert rc == 1  # valid regex, 0 matches -> 1


def test_cli_scan_no_findings_exits_0():
    rc = main(["scan", "-t", "no secrets here at all"])
    assert rc == 0  # clean scan -> 0


# ---------------------------------------------------------------------------
# CLI: explain on empty regex still returns 0
# ---------------------------------------------------------------------------
def test_cli_explain_empty_regex():
    rc = main(["explain", ""])
    assert rc == 0
