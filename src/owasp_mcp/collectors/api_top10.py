from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS api_top10 (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    cwes TEXT,
    url TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS api_top10_fts USING fts5(
    id, name, description, cwes,
    content='api_top10', content_rowid='rowid'
);
"""

# OWASP API Security Top 10 2023
API_TOP10_2023 = [
    {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization",
        "description": (
            "APIs tend to expose endpoints that handle object identifiers, creating a wide attack "
            "surface of Object Level Access Control issues. Object level authorization checks should "
            "be considered in every function that accesses a data source using an ID from the user."
        ),
        "cwes": "CWE-285, CWE-639",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    },
    {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "description": (
            "Authentication mechanisms are often implemented incorrectly, allowing attackers to "
            "compromise authentication tokens or to exploit implementation flaws to assume other "
            "user's identities temporarily or permanently."
        ),
        "cwes": "CWE-204, CWE-307",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    },
    {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization",
        "description": (
            "This category combines API3:2019 Excessive Data Exposure and API6:2019 Mass Assignment, "
            "focusing on the root cause: the lack of or improper authorization validation at the "
            "object property level. This leads to information exposure or manipulation by unauthorized parties."
        ),
        "cwes": "CWE-213, CWE-915",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    },
    {
        "id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "description": (
            "Satisfying API requests requires resources such as network bandwidth, CPU, memory, and "
            "storage. APIs that do not limit the number or size of resources requested by the client "
            "can lead to denial of service and increased operational costs."
        ),
        "cwes": "CWE-770, CWE-400, CWE-799",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    },
    {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
        "description": (
            "Complex access control policies with different hierarchies, groups, and roles, and an "
            "unclear separation between administrative and regular functions, tend to lead to "
            "authorization flaws. Attackers can gain access to other users' resources or administrative functions."
        ),
        "cwes": "CWE-285",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    },
    {
        "id": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": (
            "APIs vulnerable to this risk expose a business flow without compensating for the damage "
            "it can cause if the flow is excessively used in an automated manner. This can include "
            "purchasing flows, comment/post creation, or reservation systems."
        ),
        "cwes": "CWE-799",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
    },
    {
        "id": "API7:2023",
        "name": "Server Side Request Forgery",
        "description": (
            "Server-Side Request Forgery flaws can occur when an API is fetching a remote resource "
            "without validating the user-supplied URI. This allows an attacker to coerce the "
            "application to send a crafted request to an unexpected destination."
        ),
        "cwes": "CWE-918",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
    },
    {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
        "description": (
            "APIs and the systems supporting them typically contain complex configurations. "
            "Software and DevOps engineers can miss these configurations or don't follow security "
            "best practices, opening the door for various types of attacks."
        ),
        "cwes": "CWE-2, CWE-16, CWE-209, CWE-319, CWE-388, CWE-444, CWE-942",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    },
    {
        "id": "API9:2023",
        "name": "Improper Inventory Management",
        "description": (
            "APIs tend to expose more endpoints than traditional web applications. Proper and "
            "updated documentation is essential. An up-to-date inventory of hosts and deployed "
            "API versions is important to mitigate issues such as deprecated API versions and exposed debug endpoints."
        ),
        "cwes": "CWE-1059",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
    },
    {
        "id": "API10:2023",
        "name": "Unsafe Consumption of APIs",
        "description": (
            "Developers tend to trust data received from third-party APIs more than user input. "
            "Attackers target integrated third-party services to indirectly compromise APIs that "
            "trust the external data without proper validation."
        ),
        "cwes": "CWE-285, CWE-346, CWE-918",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
    },
]


def scrape_api_top10(conn: sqlite3.Connection) -> int:
    rows = [
        (item["id"], item["name"], item["description"], item["cwes"], item["url"])
        for item in API_TOP10_2023
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO api_top10 (id, name, description, cwes, url) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d API Top 10 items", len(rows))
    return len(rows)
