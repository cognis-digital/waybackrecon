"""WAYBACKRECON MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from waybackrecon.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-waybackrecon[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-waybackrecon[mcp]'")
        return 1
    app = FastMCP("waybackrecon")

    @app.tool()
    def waybackrecon_scan(target: str) -> str:
        """Mine archived URLs/params/endpoints from a Wayback/CDX export. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
