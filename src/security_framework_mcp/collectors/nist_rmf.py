from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS nist_rmf (
    step_id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    tasks TEXT,
    key_documents TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS nist_rmf_fts USING fts5(
    step_id, name, description, tasks,
    content='nist_rmf', content_rowid='rowid'
);
"""

# SP 800-37 Rev. 2 — Risk Management Framework 6-step process
_RMF_STEPS: list[tuple[str, str, str, str, str]] = [
    (
        "PREPARE",
        "Prepare",
        "Carry out essential activities at the organization, mission/business process, and information system levels to help prepare the organization to manage its security and privacy risks using the RMF. Establishes context and priorities for managing security and privacy risk.",
        "P-1: Risk Management Roles; P-2: Risk Management Strategy; P-3: Risk Assessment (Organization); P-4: Organizationally-Tailored Control Baselines; P-5: Common Controls; P-6: Impact-Level Prioritization; P-7: Continuous Monitoring Strategy (Organization); P-8: Mission/Business Focus; P-9: System Stakeholders; P-10: Asset Identification; P-11: Authorization Boundary; P-12: Information Types; P-13: Information Life Cycle; P-14: Risk Assessment (System); P-15: Requirements Definition; P-16: Enterprise Architecture; P-17: Requirements Allocation; P-18: System Registration",
        "SP 800-37, SP 800-39, SP 800-30",
    ),
    (
        "CATEGORIZE",
        "Categorize",
        "Categorize the information system and the information processed, stored, and transmitted by the system based on an impact analysis. The security categorization results determine the scope of the controls applicable to the system.",
        "C-1: System Description; C-2: Security Categorization; C-3: Security Categorization Review and Approval",
        "FIPS 199, SP 800-60, SP 800-37",
    ),
    (
        "SELECT",
        "Select",
        "Select an initial set of controls for the information system based on the security categorization and tailor and supplement the controls as needed based on an organizational risk assessment and local conditions.",
        "S-1: Control Selection; S-2: Control Tailoring; S-3: Control Allocation; S-4: Documentation of Planned Control Implementations; S-5: Continuous Monitoring Strategy (System); S-6: Plan Review and Approval",
        "SP 800-53, SP 800-53B, SP 800-37",
    ),
    (
        "IMPLEMENT",
        "Implement",
        "Implement the controls in the security and privacy plans for the information system and the organization, and document the specifics of the control implementation in the plans.",
        "I-1: Control Implementation; I-2: Update Control Implementation Information",
        "SP 800-53, SP 800-160, SP 800-37",
    ),
    (
        "ASSESS",
        "Assess",
        "Assess the controls in the information system to determine the extent to which the controls are implemented correctly, operating as intended, and producing the desired outcome with respect to meeting the security and privacy requirements.",
        "A-1: Assessor Selection; A-2: Assessment Plan; A-3: Control Assessment; A-4: Assessment Reports; A-5: Remediation Actions; A-6: Plan of Action and Milestones",
        "SP 800-53A, SP 800-115, SP 800-37",
    ),
    (
        "AUTHORIZE",
        "Authorize",
        "Authorize information system operation based on a determination that the risk to organizational operations, assets, individuals, other organizations, and the Nation is acceptable.",
        "R-1: Authorization Package; R-2: Risk Analysis and Determination; R-3: Risk Response; R-4: Authorization Decision; R-5: Authorization Reporting",
        "SP 800-37, SP 800-39, SP 800-30",
    ),
    (
        "MONITOR",
        "Monitor",
        "Monitor the information system and its environment of operation on an ongoing basis to verify compliance, determine the effectiveness of risk response measures, and identify changes that may impact security and privacy.",
        "M-1: System and Environment Changes; M-2: Ongoing Assessments; M-3: Ongoing Risk Response; M-4: Authorization Package Updates; M-5: Security and Privacy Reporting; M-6: Ongoing Authorization; M-7: System Disposal",
        "SP 800-137, SP 800-53A, SP 800-37",
    ),
]


def scrape_nist_rmf(conn: sqlite3.Connection) -> int:
    conn.executemany(
        "INSERT OR REPLACE INTO nist_rmf (step_id, name, description, tasks, key_documents) VALUES (?, ?, ?, ?, ?)",
        _RMF_STEPS,
    )
    conn.commit()
    log.info("Loaded %d RMF steps", len(_RMF_STEPS))
    return len(_RMF_STEPS)
