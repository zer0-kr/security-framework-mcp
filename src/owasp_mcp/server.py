from __future__ import annotations

import logging
import sys

from fastmcp import FastMCP

from owasp_mcp import __version__
from owasp_mcp.config import get_config
from owasp_mcp.index import IndexManager
from owasp_mcp.tools.owasp_tools import register_tools

mcp = FastMCP(
    name="owasp-mcp",
    instructions=(
        "OWASP MCP server providing unified access to all OWASP projects, "
        "standards, and security guidelines. Tools: search_owasp (cross-source), "
        "list_projects/search_projects/get_project (418+ projects), "
        "get_top10 (Top 10 2021), get_api_top10 (API Security 2023), "
        "get_llm_top10 (LLM Top 10 2025), get_asvs (ASVS 5.0), "
        "get_wstg (WSTG), get_masvs (Mobile MASVS), "
        "get_proactive_controls (defensive controls), "
        "get_cheatsheet (113+ sheets), cross_reference (CWE mapping), "
        "assess_stack (tech stack security assessment)."
    ),
)


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    config = get_config()
    index_mgr = IndexManager(config)

    register_tools(mcp, index_mgr)

    @mcp.resource("owasp://about")
    def about() -> str:
        info = index_mgr.status()
        return (
            "# OWASP MCP Server\n\n"
            f"- **Version:** {__version__}\n"
            f"- **Database available:** {'Yes' if info['exists'] else 'No'}\n"
            f"- **Database built:** {info.get('built_at', 'never')}\n"
            f"- **Database path:** `{info['path']}`\n\n"
            "## Tools\n\n"
            "- `list_projects` — Browse all 418+ OWASP projects\n"
            "- `search_projects` — Search projects by keyword\n"
            "- `get_project` — Get project details\n"
            "- `search_owasp` — Cross-source search (projects + ASVS + WSTG + Top 10 + Cheat Sheets)\n"
            "- `get_top10` — OWASP Top 10 2021 with CWE mappings\n"
            "- `get_asvs` — ASVS 5.0 requirements\n"
            "- `get_wstg` — WSTG test cases\n"
            "- `get_cheatsheet` — Cheat Sheets (100+)\n"
            "- `cross_reference` — CWE ↔ Top 10 ↔ ASVS mapping\n"
            "- `update_database` / `database_status` — Manage local index\n"
        )

    mcp.run(transport="stdio")
