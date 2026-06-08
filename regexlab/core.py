"""REGEXLAB engine: explain, test, benchmark, scan, and ReDoS-risk detection.

Standard library only. No network. Defensive use: analyze artifacts you own.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

TOOL_NAME = "regexlab"
TOOL_VERSION = "1.0.0"


@dataclass
class SecurityPattern:
    """A named, documented detection pattern for security triage."""
    name: str
    regex: str
    severity: str  # info | low | medium | high | critical
    description: str
    flags: int = 0


# Library of defensive detection patterns. These FIND secrets/markers in
# artifacts you own (logs, dumps, source) so you can remediate them.
SECURITY_PATTERNS: List[SecurityPattern] = [
    SecurityPattern(
        "aws_access_key_id",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "critical",
        "AWS access key ID (long-term or temporary).",
    ),
    SecurityPattern(
        "private_key_block",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        "critical",
        "PEM/OpenSSH private key header.",
    ),
    SecurityPattern(
        "github_token",
        r"\bgh[pousr]_[0-9A-Za-z]{36}\b",
        "critical",
        "GitHub personal access / OAuth / app token.",
    ),
    SecurityPattern(
        "slack_token",
        r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b",
        "high",
        "Slack API token.",
    ),
    SecurityPattern(
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        "medium",
        "JSON Web Token (header.payload.signature).",
    ),
    SecurityPattern(
        "generic_api_key_assign",
        r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"]?[0-9A-Za-z/+_=-]{12,}",
        "high",
        "Generic 'key = value' secret assignment.",
    ),
    SecurityPattern(
        "email_address",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "low",
        "Email address (PII).",
    ),
    SecurityPattern(
        "ipv4_address",
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        "info",
        "IPv4 address.",
    ),
    SecurityPattern(
        "credit_card",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "high",
        "Candidate credit-card number (Luhn-shaped).",
    ),
]


@dataclass
class Match:
    start: int
    end: int
    text: str
    line: int
    groups: Tuple[Optional[str], ...] = ()
    pattern: str = ""
    severity: str = ""


@dataclass
class TestResult:
    regex: str
    flags: List[str]
    valid: bool
    error: Optional[str]
    match_count: int
    matches: List[Match] = field(default_factory=list)
    redos_risk: str = "none"
    redos_notes: List[str] = field(default_factory=list)


@dataclass
class BenchResult:
    regex: str
    valid: bool
    error: Optional[str]
    iterations: int
    total_seconds: float
    per_match_us: float
    match_count: int
    redos_risk: str
    redos_notes: List[str] = field(default_factory=list)


FLAG_MAP = {
    "i": re.IGNORECASE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "x": re.VERBOSE,
    "a": re.ASCII,
    "u": re.UNICODE,
}


def parse_flags(flag_str: str) -> int:
    bits = 0
    for ch in (flag_str or ""):
        if ch in FLAG_MAP:
            bits |= FLAG_MAP[ch]
        else:
            raise ValueError(f"unknown flag: {ch!r}")
    return bits


def flags_to_list(bits: int) -> List[str]:
    return [name for name, bit in FLAG_MAP.items() if bits & bit and name != "u"]


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


# ---------------------------------------------------------------------------
# ReDoS heuristic (catastrophic backtracking risk). Static, conservative.
# ---------------------------------------------------------------------------
_NESTED_QUANT = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*]")
_QUANT_AFTER_GROUP_QUANT = re.compile(r"\)[+*]\s*[+*?]?")
_ADJACENT_OVERLAP = re.compile(r"(\[[^\]]+\]|\\[wWsSdD]|\.)[+*].*\1[+*]")


def detect_redos_risk(pattern: str) -> Tuple[str, List[str]]:
    """Static heuristic for catastrophic-backtracking risk.

    Returns (risk_level, notes). risk_level in none|low|medium|high.
    This is advisory, not a proof; it flags common footguns.
    """
    notes: List[str] = []
    risk = "none"

    def bump(level: str) -> None:
        nonlocal risk
        order = ["none", "low", "medium", "high"]
        if order.index(level) > order.index(risk):
            risk = level

    # Nested quantifiers like (a+)+ or (a*)* -- the classic ReDoS shape.
    if _NESTED_QUANT.search(pattern):
        notes.append("Nested quantifier on a group, e.g. (x+)+ -> exponential backtracking.")
        bump("high")

    if _QUANT_AFTER_GROUP_QUANT.search(pattern):
        notes.append("Quantifier applied to an already-quantified group.")
        bump("medium")

    # Overlapping adjacent quantified classes, e.g. \d+\d+ or .*.* .
    if _ADJACENT_OVERLAP.search(pattern):
        notes.append("Overlapping adjacent quantifiers can cause ambiguous matching.")
        bump("medium")

    # Alternation with overlapping branches inside a quantified group: (a|a)+
    if re.search(r"\(([^)|]+)\|\1\)[+*]", pattern):
        notes.append("Quantified group with duplicate alternation branches, e.g. (a|a)+.")
        bump("high")

    # Unbounded quantifier directly before a literal it can also match.
    if re.search(r"\.\*\.\*", pattern) or re.search(r"\.\+\.\+", pattern):
        notes.append("Multiple unbounded wildcards (.* .*) inflate backtracking.")
        bump("medium")

    if risk == "none":
        notes.append("No common catastrophic-backtracking shapes detected.")
    return risk, notes


# ---------------------------------------------------------------------------
# Explain: token-by-token plain-English breakdown.
# ---------------------------------------------------------------------------
_TOKEN_DOC = {
    r"\d": "any digit (0-9)",
    r"\D": "any non-digit",
    r"\w": "any word char (letter, digit, underscore)",
    r"\W": "any non-word char",
    r"\s": "any whitespace",
    r"\S": "any non-whitespace",
    r"\b": "a word boundary",
    r"\B": "a non-word boundary",
    ".": "any char (except newline unless DOTALL)",
    "^": "start of string/line",
    "$": "end of string/line",
    "*": "repeat previous 0 or more times",
    "+": "repeat previous 1 or more times",
    "?": "previous is optional (0 or 1) / makes quantifier lazy",
    "|": "OR (alternation)",
}


def explain_pattern(pattern: str) -> List[Tuple[str, str]]:
    """Return [(token, explanation)] segments for a regex string."""
    out: List[Tuple[str, str]] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        two = pattern[i:i + 2]
        if two in _TOKEN_DOC:
            out.append((two, _TOKEN_DOC[two]))
            i += 2
            continue
        if ch == "\\" and i + 1 < n:
            out.append((two, f"literal {pattern[i+1]!r} (escaped)"))
            i += 2
            continue
        if ch == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                j = n - 1
            seg = pattern[i:j + 1]
            neg = seg.startswith("[^")
            out.append((seg, ("NOT one of: " if neg else "one of: ") + seg.strip("[]^")))
            i = j + 1
            continue
        if ch == "(":
            if pattern[i:i + 3] == "(?:":
                out.append(("(?:", "start non-capturing group"))
                i += 3
            elif pattern[i:i + 3] in ("(?=", "(?!"):
                kind = "lookahead" if pattern[i + 2] == "=" else "negative lookahead"
                out.append((pattern[i:i + 3], f"start {kind}"))
                i += 3
            else:
                out.append(("(", "start capturing group"))
                i += 1
            continue
        if ch == ")":
            out.append((")", "end group"))
            i += 1
            continue
        if ch == "{":
            j = pattern.find("}", i + 1)
            if j != -1:
                seg = pattern[i:j + 1]
                out.append((seg, f"repeat previous {seg.strip('{}')} times"))
                i = j + 1
                continue
        if ch in _TOKEN_DOC:
            out.append((ch, _TOKEN_DOC[ch]))
            i += 1
            continue
        out.append((ch, f"literal {ch!r}"))
        i += 1
    return out


def _compile(pattern: str, flag_bits: int) -> Tuple[Optional[re.Pattern], Optional[str]]:
    try:
        return re.compile(pattern, flag_bits), None
    except re.error as exc:
        return None, str(exc)


def test_pattern(pattern: str, subject: str, flag_str: str = "",
                 max_matches: int = 1000) -> TestResult:
    flag_bits = parse_flags(flag_str)
    risk, notes = detect_redos_risk(pattern)
    rx, err = _compile(pattern, flag_bits)
    if rx is None:
        return TestResult(pattern, flags_to_list(flag_bits), False, err, 0,
                          redos_risk=risk, redos_notes=notes)
    matches: List[Match] = []
    for m in rx.finditer(subject):
        matches.append(Match(
            start=m.start(), end=m.end(), text=m.group(0),
            line=_line_of(subject, m.start()), groups=tuple(m.groups()),
        ))
        if len(matches) >= max_matches:
            break
    return TestResult(pattern, flags_to_list(flag_bits), True, None,
                      len(matches), matches, risk, notes)


def benchmark_pattern(pattern: str, subject: str, flag_str: str = "",
                      iterations: int = 1000) -> BenchResult:
    flag_bits = parse_flags(flag_str)
    risk, notes = detect_redos_risk(pattern)
    rx, err = _compile(pattern, flag_bits)
    if rx is None:
        return BenchResult(pattern, False, err, iterations, 0.0, 0.0, 0, risk, notes)
    count = 0
    start = time.perf_counter()
    for _ in range(iterations):
        count = sum(1 for _ in rx.finditer(subject))
    total = time.perf_counter() - start
    per = (total / iterations) * 1_000_000 if iterations else 0.0
    return BenchResult(pattern, True, None, iterations, total, per, count, risk, notes)


def scan_text(subject: str, patterns: Optional[List[SecurityPattern]] = None,
              min_severity: str = "info", max_matches: int = 5000) -> List[Match]:
    """Scan text for security patterns. Returns Match objects tagged with pattern+severity."""
    patterns = patterns if patterns is not None else SECURITY_PATTERNS
    order = ["info", "low", "medium", "high", "critical"]
    floor = order.index(min_severity) if min_severity in order else 0
    found: List[Match] = []
    for sp in patterns:
        if order.index(sp.severity) < floor:
            continue
        try:
            rx = re.compile(sp.regex, sp.flags)
        except re.error:
            continue
        for m in rx.finditer(subject):
            found.append(Match(
                start=m.start(), end=m.end(), text=m.group(0),
                line=_line_of(subject, m.start()), groups=tuple(m.groups()),
                pattern=sp.name, severity=sp.severity,
            ))
            if len(found) >= max_matches:
                return found
    return found


def match_to_dict(m: Match) -> Dict:
    return asdict(m)
