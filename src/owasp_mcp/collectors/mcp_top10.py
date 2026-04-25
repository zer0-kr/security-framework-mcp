from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS mcp_top10 (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    impact TEXT,
    url TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS mcp_top10_fts USING fts5(
    id, name, description, impact,
    content='mcp_top10', content_rowid='rowid'
);
"""

# OWASP Top 10 for MCP Servers 2025 (Beta v0.1) — https://owasp.org/www-project-mcp-top-10/
MCP_TOP10_2025 = [
    {
        "id": "MCP01:2025",
        "name": "Token Mismanagement & Secret Exposure",
        "description": (
            "Tokens and credentials embedded in configuration files, environment variables, prompt "
            "templates, or persisted within model context memory. MCP enables long-lived sessions "
            "where tokens can be inadvertently stored, indexed, or retrieved through user prompts, "
            "system recalls, or log inspection, creating contextual secret leakage."
        ),
        "impact": "Complete environment compromise, unauthorized code modifications, lateral movement across integrated services, data exfiltration",
    },
    {
        "id": "MCP02:2025",
        "name": "Privilege Escalation via Scope Creep",
        "description": (
            "Temporary or narrowly scoped permissions granted to an MCP agent are expanded over time "
            "through convenience or configuration drift until the agent holds broad privileges. "
            "Especially dangerous in agentic systems because agents act autonomously with over-privileged access."
        ),
        "impact": "Unauthorized modifications to code and infrastructure, unreviewed deployments, full environment control, regulatory exposure",
    },
    {
        "id": "MCP03:2025",
        "name": "Tool Poisoning",
        "description": (
            "An adversary compromises the tools, plugins, or their outputs that an AI model depends on — "
            "injecting malicious context to manipulate model behavior. Includes rug pulls (malicious updates "
            "to trusted tools), schema poisoning (corrupting interface definitions), and tool shadowing "
            "(introducing fake duplicate tools). 84.2% success rate with auto-approval."
        ),
        "impact": "Data loss or corruption, privilege abuse, silent policy bypass, widespread compromise across agents/tenants",
    },
    {
        "id": "MCP04:2025",
        "name": "Software Supply Chain Attacks & Dependency Tampering",
        "description": (
            "MCP environments rely on third-party SDKs, connectors, protocol servers, plugins, and "
            "model-side tool integrations. A compromised dependency can alter agent behavior, introduce "
            "backdoors, or modify protocol semantics without triggering detection."
        ),
        "impact": "Unauthorized access and code execution, context poisoning, privilege escalation, cross-tenant compromise",
    },
    {
        "id": "MCP05:2025",
        "name": "Command Injection & Execution",
        "description": (
            "An AI agent constructs and executes system commands using untrusted input without proper "
            "validation. Unlike traditional command injection, MCP-based injection is mediated through "
            "the model layer: instructions hidden in prompts, documents, or context cause the agent "
            "to generate malicious commands that appear syntactically valid."
        ),
        "impact": "Arbitrary code execution, system breakout, data exfiltration, privilege escalation, lateral movement",
    },
    {
        "id": "MCP06:2025",
        "name": "Intent Flow Subversion",
        "description": (
            "Malicious instructions embedded within retrieved context cause the agent to pivot away from "
            "the user's goal toward an attacker's objective while still appearing to fulfill the original "
            "request. Attackers inject meta-instructions into long-lived MCP contexts that alter behavior "
            "across multiple unrelated sessions."
        ),
        "impact": "Goal hijacking, unauthorized autonomous actions, trust erosion, stealthy persistence through context contamination",
    },
    {
        "id": "MCP07:2025",
        "name": "Insufficient Authentication & Authorization",
        "description": (
            "MCP servers, tools, or agents fail to properly verify identities or enforce access controls. "
            "41% of 518 servers in the official MCP Registry have zero authentication. Manifests as missing "
            "API key validation, hard-coded shared secrets, static credentials, and insecure token issuance."
        ),
        "impact": "Unauthorized actions, privilege escalation, cross-agent impersonation, data leakage, service compromise",
    },
    {
        "id": "MCP08:2025",
        "name": "Lack of Audit and Telemetry",
        "description": (
            "When audit logging and telemetry are absent, organizations lose visibility into what actions "
            "agents perform, what data they access, and how decisions are made. 100% of audited servers "
            "lack permission declarations. An unmonitored agent can silently perform sensitive operations "
            "for weeks without detection."
        ),
        "impact": "No traceability, compliance failure (GDPR, PCI DSS, ISO 27001), delayed breach detection, operational blind spots",
    },
    {
        "id": "MCP09:2025",
        "name": "Shadow MCP Servers",
        "description": (
            "Unapproved or unsupervised MCP deployments operating outside formal security governance. "
            "Spun up by developers for experimentation using default credentials, permissive configurations, "
            "or unsecured APIs. These become invisible backdoors into enterprise systems, bypassing "
            "centralized authentication, monitoring, and data governance controls."
        ),
        "impact": "Data exposure, attack surface expansion, policy noncompliance, supply chain contamination",
    },
    {
        "id": "MCP10:2025",
        "name": "Context Injection & Over-Sharing",
        "description": (
            "Context acts as the working memory for agents. When shared, persistently stored, or "
            "insufficiently scoped, sensitive information from one session leaks into another. "
            "Context Injection embeds malicious content into shared memory. Over-Sharing reuses context "
            "across agents or workflows that should be isolated."
        ),
        "impact": "Cross-agent data leakage, privacy regulation violations, persistent model behavior contamination",
    },
]


def scrape_mcp_top10(conn: sqlite3.Connection) -> int:
    rows = [
        (
            item["id"], item["name"], item["description"], item["impact"],
            f"https://owasp.org/www-project-mcp-top-10/",
        )
        for item in MCP_TOP10_2025
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO mcp_top10 (id, name, description, impact, url) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d MCP Top 10 items", len(rows))
    return len(rows)
