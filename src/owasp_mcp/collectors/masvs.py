from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS masvs (
    control_id TEXT PRIMARY KEY,
    category_id TEXT,
    category_name TEXT,
    statement TEXT,
    description TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS masvs_fts USING fts5(
    control_id, category_name, statement, description,
    content='masvs', content_rowid='rowid'
);
"""

# OWASP MASVS (Mobile Application Security Verification Standard) — https://github.com/OWASP/owasp-masvs
MASVS_DATA = [
    ("MASVS-STORAGE", "Storage", [
        ("MASVS-STORAGE-1", "The app securely stores sensitive data",
         "Apps handle sensitive data from many sources and usually need to store it locally. This control ensures that any sensitive data intentionally stored by the app is properly protected independently of the target location."),
        ("MASVS-STORAGE-2", "The app prevents leakage of sensitive data",
         "There are cases when sensitive data is unintentionally stored or exposed to publicly accessible locations, typically as a side-effect of using certain APIs, system capabilities such as backups or logs."),
    ]),
    ("MASVS-CRYPTO", "Cryptography", [
        ("MASVS-CRYPTO-1", "The app employs current strong cryptography and uses it according to industry best practices",
         "Cryptography plays an especially important role in securing the user's data, even more so in a mobile environment where attackers having physical access to the device is a likely scenario."),
        ("MASVS-CRYPTO-2", "The app performs key management according to industry best practices",
         "Even the strongest cryptography would be compromised by poor key management. This control covers the management of cryptographic keys throughout their lifecycle, including generation, storage and protection."),
    ]),
    ("MASVS-AUTH", "Authentication and Authorization", [
        ("MASVS-AUTH-1", "The app uses secure authentication and authorization protocols and follows the relevant best practices",
         "Most apps connecting to a remote endpoint require user authentication. While the majority of auth logic resides on the server, MASVS defines requirements for the app's side of authentication and authorization."),
        ("MASVS-AUTH-2", "The app performs local authentication securely according to the platform best practices",
         "To protect sensitive data or functions within the app, it is common to enforce local authentication such as a PIN, biometric, or passphrase to unlock the app."),
    ]),
    ("MASVS-NETWORK", "Network Communication", [
        ("MASVS-NETWORK-1", "The app secures all network traffic according to the current best practices",
         "The purpose of this control is to ensure the app is in fact setting up a secure connection in any situation. Enforcing TLS for any data exchange over the network is essential."),
        ("MASVS-NETWORK-2", "The app performs identity pinning for all remote endpoints under the developer's control",
         "Instead of relying solely on the certificate chain, certificate or public key pinning binds the app to a specific set of certificates or public keys for trusted remote endpoints."),
    ]),
    ("MASVS-PLATFORM", "Platform Interaction", [
        ("MASVS-PLATFORM-1", "The app uses IPC mechanisms securely",
         "Apps typically use platform-provided IPC mechanisms to intentionally or unintentionally expose data or functionality. This control ensures apps protect IPC mechanisms properly."),
        ("MASVS-PLATFORM-2", "The app uses WebViews securely",
         "WebViews are in-app browser components for displaying web content. This control ensures that WebViews are configured securely to prevent sensitive data leakage and code execution."),
        ("MASVS-PLATFORM-3", "The app uses the user interface securely",
         "This control ensures that the app protects sensitive data displayed on the UI and prevents common UI security issues such as overlay attacks and clipboard data leakage."),
    ]),
    ("MASVS-CODE", "Code Quality", [
        ("MASVS-CODE-1", "The app requires an up-to-date platform version",
         "Every update of the mobile platform includes security patches for known vulnerabilities. Requiring a minimum platform version ensures that known critical security issues are addressed."),
        ("MASVS-CODE-2", "The app has a mechanism for enforcing app updates",
         "Ensuring the app is always running the latest version allows developers to deploy critical security patches that users install in a timely manner."),
        ("MASVS-CODE-3", "The app only uses software components without known vulnerabilities",
         "Apps use third-party libraries and components that may have known security vulnerabilities. This control ensures apps are built with up-to-date and vulnerability-free components."),
        ("MASVS-CODE-4", "The app validates and sanitizes all untrusted inputs",
         "Apps process data from many sources. This control ensures that all input data is properly validated and sanitized before being processed, regardless of the source."),
    ]),
    ("MASVS-RESILIENCE", "Resilience", [
        ("MASVS-RESILIENCE-1", "The app validates the integrity of the platform",
         "Running the app on a compromised platform (rooted/jailbroken) voids many security guarantees. This control detects platform integrity violations."),
        ("MASVS-RESILIENCE-2", "The app implements anti-tampering mechanisms",
         "This control verifies that the app's own integrity has not been compromised, detecting modifications to the code or resources at runtime."),
        ("MASVS-RESILIENCE-3", "The app implements anti-static analysis mechanisms",
         "This control raises the bar for static analysis by obfuscating the app's code, making reverse engineering significantly more difficult."),
        ("MASVS-RESILIENCE-4", "The app implements anti-dynamic analysis mechanisms",
         "This control detects and responds to dynamic analysis tools such as debuggers, hooking frameworks, and instrumentation platforms at runtime."),
    ]),
    ("MASVS-PRIVACY", "Privacy", [
        ("MASVS-PRIVACY-1", "The app minimizes access to sensitive data and resources",
         "Apps should only request access to the data and resources they strictly need. This control ensures apps follow the principle of least privilege for data collection and access."),
        ("MASVS-PRIVACY-2", "The app is transparent in the way it collects, uses, shares, and processes user data",
         "Users should be fully informed about how their data is used. This control ensures proper disclosure and consent for data collection and processing."),
        ("MASVS-PRIVACY-3", "The app offers user control over their data",
         "Users should have the ability to manage their personal data. This control ensures apps provide mechanisms for users to access, modify, delete, and export their data."),
        ("MASVS-PRIVACY-4", "The app uses the latest privacy-preserving protocols and technologies",
         "Apps should use cutting-edge privacy-enhancing technologies such as on-device processing, differential privacy, and anonymization to minimize data exposure."),
    ]),
]


def scrape_masvs(conn: sqlite3.Connection) -> int:
    rows = []
    for cat_id, cat_name, controls in MASVS_DATA:
        for ctrl_id, statement, description in controls:
            rows.append((ctrl_id, cat_id, cat_name, statement, description))

    conn.executemany(
        "INSERT OR REPLACE INTO masvs "
        "(control_id, category_id, category_name, statement, description) "
        "VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d MASVS controls", len(rows))
    return len(rows)
