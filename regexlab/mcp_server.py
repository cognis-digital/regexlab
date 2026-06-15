"""REGEXLAB MCP server — exposes scan_text() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
import sys
from regexlab.core import scan_text
from dataclasses import asdict


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-regexlab[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "Install the MCP extra: pip install 'cognis-regexlab[mcp]'",
            file=sys.stderr,
        )
        return 1
    app = FastMCP("regexlab")

    @app.tool()
    def regexlab_scan(target: str) -> str:
        """Scan text with the built-in security pattern library. Returns JSON findings."""
        if not isinstance(target, str):
            return json.dumps({"error": "target must be a string"})
        matches = scan_text(target)
        return json.dumps(
            {"findings": len(matches), "matches": [asdict(m) for m in matches]},
            indent=2,
        )

    app.run()
    return 0
