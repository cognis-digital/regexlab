#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations
import argparse
import sys
import urllib.request
import urllib.error


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Forward JSON findings from stdin to a webhook URL."
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https)")
    ap.add_argument("--header", action="append", default=[], help="Key: Value")
    ap.add_argument(
        "--timeout", type=int, default=15,
        help="HTTP timeout in seconds (default: 15)"
    )
    args = ap.parse_args()

    if not args.url.startswith(("http://", "https://")):
        print(
            f"webhook: error: --url must start with http:// or https://, got {args.url!r}",
            file=sys.stderr,
        )
        return 2
    if args.timeout < 1:
        print(
            f"webhook: error: --timeout must be >= 1, got {args.timeout!r}",
            file=sys.stderr,
        )
        return 2

    payload = sys.stdin.buffer.read()
    if not payload:
        print("webhook: warning: empty payload from stdin", file=sys.stderr)

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        k = k.strip()
        v = v.strip()
        if not k:
            print(f"webhook: warning: skipping malformed header {h!r}", file=sys.stderr)
            continue
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as exc:
        print(f"webhook error: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"webhook error: {exc.reason}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
