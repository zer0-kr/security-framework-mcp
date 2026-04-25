from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS proactive_controls (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    related_top10 TEXT,
    url TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS proactive_controls_fts USING fts5(
    id, name, description, related_top10,
    content='proactive_controls', content_rowid='rowid'
);
"""

# OWASP Proactive Controls 2024 — https://owasp.org/www-project-proactive-controls/archive/2024/
PROACTIVE_CONTROLS_2024 = [
    {
        "id": "C1",
        "name": "Implement Access Control",
        "description": (
            "Access Control (or Authorization) is allowing or denying specific requests from a user, "
            "program, or process. It must be designed up front and applied consistently across all access "
            "paths and levels. Implement centralized access control, deny by default, apply the principle "
            "of least privilege, and avoid hard-coded roles in favor of attribute-based access control."
        ),
        "related_top10": "A01:2021 Broken Access Control, CWE-862, CWE-863",
    },
    {
        "id": "C2",
        "name": "Use Cryptography to Protect Data",
        "description": (
            "Sensitive data requires cryptographic protection both at rest and in transit. Never transmit "
            "plain-text data; use TLSv1.2+. Store passwords using key-derivation functions with salt. "
            "Manage secrets securely in vaults rather than in code. Support cryptographic agility to "
            "allow algorithm changes over time."
        ),
        "related_top10": "A02:2021 Cryptographic Failures",
    },
    {
        "id": "C3",
        "name": "Validate all Input & Handle Exceptions",
        "description": (
            "Ensure only properly formatted data enters the system. Check syntactic validity (format) "
            "and semantic validity (range/context). Use allowlist validation, always validate on the "
            "server side, use prepared statements for queries, and sanitize HTML when user-provided "
            "HTML must be accepted."
        ),
        "related_top10": "A03:2021 Injection, CWE-89, CWE-78, CWE-94",
    },
    {
        "id": "C4",
        "name": "Address Security from the Start",
        "description": (
            "Design with simplicity and transparency, making it easy to do the right thing by default. "
            "Articulate trust boundaries and enforce them with controls. Identify and minimize attack "
            "surface. Use well-known secure architecture patterns and leverage established frameworks "
            "rather than reimplementing security features."
        ),
        "related_top10": "A04:2021 Insecure Design",
    },
    {
        "id": "C5",
        "name": "Secure By Default Configurations",
        "description": (
            "Products should be resilient against prevalent exploitation techniques out of the box. "
            "Default settings must always be the most secure option. Deny access by default, use "
            "container images scanned for vulnerabilities, prefer declarative infrastructure-as-code, "
            "and ensure debugging is disabled in production."
        ),
        "related_top10": "A05:2021 Security Misconfiguration",
    },
    {
        "id": "C6",
        "name": "Keep your Components Secure",
        "description": (
            "Leverage secure libraries and frameworks rather than implementing security from scratch. "
            "Maintain an inventory of third-party components using SBOM. Perform continuous vulnerability "
            "checks using tools like OWASP Dependency-Track. Integrate SCA tools early in development "
            "and proactively update libraries."
        ),
        "related_top10": "A06:2021 Vulnerable and Outdated Components",
    },
    {
        "id": "C7",
        "name": "Secure Digital Identities",
        "description": (
            "Implement authentication assurance levels: Level 1 (passwords for low-risk), Level 2 (MFA "
            "for higher-risk), Level 3 (cryptographic/WebAuthn for highest-risk). Enforce strong "
            "password requirements. Use server-side session management by default. Set secure cookie "
            "flags (Secure, HttpOnly, SameSite)."
        ),
        "related_top10": "A07:2021 Identification and Authentication Failures",
    },
    {
        "id": "C8",
        "name": "Leverage Browser Security Features",
        "description": (
            "Use HTTP headers to enforce security: HSTS for HTTPS-only, CSP to prevent XSS, "
            "X-Frame-Options for clickjacking prevention, Referrer-Policy for information disclosure "
            "control, Permission Policy to restrict browser capabilities. These are hardening measures "
            "that complement server-side defenses."
        ),
        "related_top10": "A03:2021 Injection (XSS), A05:2021 Security Misconfiguration",
    },
    {
        "id": "C9",
        "name": "Implement Security Logging and Monitoring",
        "description": (
            "Log security-relevant events: submitted data outside expected ranges, access control "
            "violations, and suspicious patterns. Use a common logging format. Log timestamps, source "
            "IP, and user identifiers but avoid logging sensitive data. Forward logs to a central "
            "secure logging service."
        ),
        "related_top10": "A09:2021 Security Logging and Monitoring Failures",
    },
    {
        "id": "C10",
        "name": "Stop Server Side Request Forgery",
        "description": (
            "SSRF occurs when an attacker tricks a server into making unintended requests to internal "
            "or external services. Prevent through input validation, allowlist validation of target "
            "URLs, and secure XML parser configuration to prevent XXE. Be aware of Unicode and "
            "character transformations that can bypass validation."
        ),
        "related_top10": "A10:2021 Server-Side Request Forgery (SSRF)",
    },
]


def scrape_proactive_controls(conn: sqlite3.Connection) -> int:
    rows = [
        (
            item["id"], item["name"], item["description"],
            item["related_top10"],
            f"https://owasp.org/www-project-proactive-controls/archive/2024/{item['id'].lower()}-{item['name'].lower().replace(' ', '-')}/",
        )
        for item in PROACTIVE_CONTROLS_2024
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO proactive_controls (id, name, description, related_top10, url) "
        "VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d Proactive Controls", len(rows))
    return len(rows)
