from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS nist_glossary (
    term TEXT PRIMARY KEY,
    definition TEXT,
    source TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS nist_glossary_fts USING fts5(
    term, definition, source,
    content='nist_glossary', content_rowid='rowid'
);
"""

# Curated NIST cybersecurity glossary — key terms from SP 800-53, FIPS 200, SP 800-39
_GLOSSARY: list[tuple[str, str, str]] = [
    ("Access Control", "The process of granting or denying specific requests to obtain and use information and related information processing services.", "SP 800-53"),
    ("Advanced Persistent Threat", "An adversary that possesses sophisticated levels of expertise and significant resources which allow it to create opportunities to achieve its objectives by using multiple attack vectors.", "SP 800-39"),
    ("Assessment", "The testing or evaluation of security controls to determine the extent to which the controls are implemented correctly, operating as intended, and producing the desired outcome.", "SP 800-53A"),
    ("Audit", "Independent review and examination of records and activities to assess the adequacy of system controls and ensure compliance with established policies.", "SP 800-53"),
    ("Authentication", "Verifying the identity of a user, process, or device, often as a prerequisite to allowing access to resources in an information system.", "FIPS 200"),
    ("Authorization", "Access privileges granted to a user, program, or process or the act of granting those privileges.", "SP 800-53"),
    ("Availability", "Ensuring timely and reliable access to and use of information.", "FIPS 199"),
    ("Boundary Protection", "Monitoring and control of communications at the external boundary and at key internal boundaries within the information system.", "SP 800-53"),
    ("Certification", "A comprehensive assessment of the management, operational, and technical security controls to determine the extent to which controls are implemented correctly.", "SP 800-37"),
    ("Confidentiality", "Preserving authorized restrictions on information access and disclosure, including means for protecting personal privacy and proprietary information.", "FIPS 199"),
    ("Configuration Management", "A collection of activities focused on establishing and maintaining the integrity of products and systems, through control of the processes for initializing, changing, and monitoring the configurations.", "SP 800-53"),
    ("Continuous Monitoring", "Maintaining ongoing awareness of information security, vulnerabilities, and threats to support organizational risk management decisions.", "SP 800-137"),
    ("Control", "A safeguard or countermeasure prescribed for an information system or an organization designed to protect the confidentiality, integrity, and availability of its information.", "FIPS 200"),
    ("Control Baseline", "The set of minimum security controls defined for a low-impact, moderate-impact, or high-impact information system.", "SP 800-53B"),
    ("Cybersecurity Framework", "A risk-based approach to managing cybersecurity risk composed of three parts: Framework Core, Framework Implementation Tiers, and Framework Profiles.", "CSF 2.0"),
    ("Defense in Depth", "Information security strategy integrating people, technology, and operations capabilities to establish variable barriers across multiple layers and dimensions.", "NIST SP 800-53"),
    ("Encryption", "The process of transforming plaintext into ciphertext.", "FIPS 140-3"),
    ("Federal Information Processing Standard", "A standard for adoption and use by Federal agencies issued under the Information Technology Management Reform Act.", "FIPS"),
    ("FISMA", "Federal Information Security Modernization Act of 2014 requiring Federal agencies to develop, document, and implement programs for information security.", "FISMA"),
    ("Impact Level", "The magnitude of harm that can be expected to result from the consequences of unauthorized disclosure, modification, or destruction of information.", "FIPS 199"),
    ("Incident", "An occurrence that actually or potentially jeopardizes the confidentiality, integrity, or availability of an information system.", "SP 800-61"),
    ("Incident Response", "The mitigation of violations of security policies and recommended practices.", "SP 800-61"),
    ("Information Security", "The protection of information and information systems from unauthorized access, use, disclosure, disruption, modification, or destruction.", "44 U.S.C. §3542"),
    ("Integrity", "Guarding against improper information modification or destruction, and includes ensuring information non-repudiation and authenticity.", "FIPS 199"),
    ("Least Privilege", "The principle that a security architecture should be designed so that each entity is granted the minimum system resources and authorizations needed to perform its function.", "SP 800-53"),
    ("Multi-Factor Authentication", "Authentication using two or more different factors to achieve authentication. Factors include something you know, something you have, or something you are.", "SP 800-63"),
    ("OSCAL", "Open Security Controls Assessment Language — a set of formats for representing security control catalogs, baselines, and assessment results in machine-readable form.", "NIST OSCAL"),
    ("Penetration Testing", "A test methodology in which assessors, using all available documentation and working under specific constraints, attempt to circumvent security features of an information system.", "SP 800-53A"),
    ("Plan of Action and Milestones", "A document that identifies tasks needing to be accomplished. It details resources required, milestones, and scheduled completion dates.", "SP 800-37"),
    ("Privacy", "The right of a party to maintain control over and confidentiality of information about itself.", "SP 800-122"),
    ("Risk", "A measure of the extent to which an entity is threatened by a potential circumstance or event.", "SP 800-30"),
    ("Risk Assessment", "The process of identifying risks to organizational operations, assets, individuals, and other organizations.", "SP 800-30"),
    ("Risk Management Framework", "A structured approach for managing risk that includes categorize, select, implement, assess, authorize, and monitor steps.", "SP 800-37"),
    ("Security Control", "The management, operational, and technical controls prescribed for an information system to protect its confidentiality, integrity, and availability.", "FIPS 200"),
    ("Supply Chain Risk Management", "The process of identifying, assessing, and mitigating the risks associated with the global and distributed nature of ICT product and service supply chains.", "SP 800-161"),
    ("System Security Plan", "Formal document that provides an overview of the security requirements for an information system and describes the security controls in place or planned.", "SP 800-18"),
    ("Threat", "Any circumstance or event with the potential to adversely impact organizational operations through unauthorized access, destruction, disclosure, modification of information.", "SP 800-30"),
    ("Vulnerability", "Weakness in an information system, system security procedures, internal controls, or implementation that could be exploited by a threat source.", "SP 800-30"),
    ("Zero Trust Architecture", "A cybersecurity paradigm that assumes no implicit trust is granted to assets or user accounts based solely on their physical or network location.", "SP 800-207"),
]


def scrape_nist_glossary(conn: sqlite3.Connection) -> int:
    conn.executemany(
        "INSERT OR REPLACE INTO nist_glossary (term, definition, source) VALUES (?, ?, ?)",
        _GLOSSARY,
    )
    conn.commit()
    log.info("Loaded %d NIST glossary terms", len(_GLOSSARY))
    return len(_GLOSSARY)
