"""REGEXLAB - test, explain & benchmark regexes + a library of security patterns.

regex without footguns. Defensive analysis/triage only.
"""
from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    SECURITY_PATTERNS,
    SecurityPattern,
    Match,
    TestResult,
    BenchResult,
    explain_pattern,
    test_pattern,
    benchmark_pattern,
    scan_text,
    detect_redos_risk,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "SECURITY_PATTERNS",
    "SecurityPattern",
    "Match",
    "TestResult",
    "BenchResult",
    "explain_pattern",
    "test_pattern",
    "benchmark_pattern",
    "scan_text",
    "detect_redos_risk",
]
