"""REGEXLAB MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from regexlab.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-regexlab[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-regexlab[mcp]'")
        return 1
    app = FastMCP("regexlab")

    @app.tool()
    def regexlab_scan(target: str) -> str:
        """Test, explain & benchmark regexes + a library of security patterns. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
