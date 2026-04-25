from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS nist_pf (
    id TEXT PRIMARY KEY,
    function_id TEXT,
    function_name TEXT,
    category_id TEXT,
    category_name TEXT,
    title TEXT,
    level TEXT
);
CREATE INDEX IF NOT EXISTS idx_pf_function ON nist_pf(function_id);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS nist_pf_fts USING fts5(
    id, function_name, category_name, title,
    content='nist_pf', content_rowid='rowid'
);
"""

# NIST Privacy Framework 1.0 (CSWP 10) — https://www.nist.gov/privacy-framework
_PF_DATA: list[tuple[str, str, str, str, str, str, str]] = [
    ("ID-P", "ID-P", "Identify-P", "", "", "Identify-P", "function"),
    ("ID.IM-P", "ID-P", "Identify-P", "ID.IM-P", "Inventory and Mapping", "Inventory and Mapping", "category"),
    ("ID.IM-P1", "ID-P", "Identify-P", "ID.IM-P", "Inventory and Mapping", "Systems/products/services that process data are inventoried", "subcategory"),
    ("ID.IM-P2", "ID-P", "Identify-P", "ID.IM-P", "Inventory and Mapping", "Owners or operators of systems/products/services that process data are inventoried", "subcategory"),
    ("ID.IM-P3", "ID-P", "Identify-P", "ID.IM-P", "Inventory and Mapping", "Categories of individuals whose data are processed are inventoried", "subcategory"),
    ("ID.IM-P4", "ID-P", "Identify-P", "ID.IM-P", "Inventory and Mapping", "Data actions of the systems/products/services are inventoried", "subcategory"),
    ("ID.IM-P5", "ID-P", "Identify-P", "ID.IM-P", "Inventory and Mapping", "The purposes for the data actions are inventoried", "subcategory"),
    ("ID.IM-P6", "ID-P", "Identify-P", "ID.IM-P", "Inventory and Mapping", "Data elements within the data actions are inventoried", "subcategory"),
    ("ID.IM-P7", "ID-P", "Identify-P", "ID.IM-P", "Inventory and Mapping", "The data processing environment is identified", "subcategory"),
    ("ID.IM-P8", "ID-P", "Identify-P", "ID.IM-P", "Inventory and Mapping", "Data processing is mapped, illustrating the data actions and associated data elements", "subcategory"),
    ("ID.BE-P", "ID-P", "Identify-P", "ID.BE-P", "Business Environment", "Business Environment", "category"),
    ("ID.BE-P1", "ID-P", "Identify-P", "ID.BE-P", "Business Environment", "The organization's role(s) in the data processing ecosystem are identified and communicated", "subcategory"),
    ("ID.BE-P2", "ID-P", "Identify-P", "ID.BE-P", "Business Environment", "Priorities for organizational mission, objectives, and activities are established and communicated", "subcategory"),
    ("ID.BE-P3", "ID-P", "Identify-P", "ID.BE-P", "Business Environment", "Systems/products/services that support organizational priorities are identified and key requirements communicated", "subcategory"),
    ("ID.RA-P", "ID-P", "Identify-P", "ID.RA-P", "Risk Assessment", "Risk Assessment", "category"),
    ("ID.RA-P1", "ID-P", "Identify-P", "ID.RA-P", "Risk Assessment", "Contextual factors related to the systems/products/services and the data actions are identified", "subcategory"),
    ("ID.RA-P2", "ID-P", "Identify-P", "ID.RA-P", "Risk Assessment", "Data analytic inputs and outputs are identified and evaluated", "subcategory"),
    ("ID.RA-P3", "ID-P", "Identify-P", "ID.RA-P", "Risk Assessment", "Potential problematic data actions and associated problems are identified", "subcategory"),
    ("ID.RA-P4", "ID-P", "Identify-P", "ID.RA-P", "Risk Assessment", "Problematic data actions, likelihood, and impact are used to determine risk", "subcategory"),
    ("ID.RA-P5", "ID-P", "Identify-P", "ID.RA-P", "Risk Assessment", "Risk responses are identified, prioritized, and implemented", "subcategory"),
    ("ID.DE-P", "ID-P", "Identify-P", "ID.DE-P", "Data Processing Ecosystem Risk Management", "Data Processing Ecosystem Risk Management", "category"),
    ("ID.DE-P1", "ID-P", "Identify-P", "ID.DE-P", "Data Processing Ecosystem Risk Management", "Data processing ecosystem risk management policies, processes, and procedures are identified and managed", "subcategory"),
    ("ID.DE-P2", "ID-P", "Identify-P", "ID.DE-P", "Data Processing Ecosystem Risk Management", "Data processing ecosystem parties are identified, prioritized, and assessed using a privacy risk assessment process", "subcategory"),
    ("ID.DE-P3", "ID-P", "Identify-P", "ID.DE-P", "Data Processing Ecosystem Risk Management", "Contracts with data processing ecosystem parties are established, maintained, and implemented", "subcategory"),
    ("ID.DE-P4", "ID-P", "Identify-P", "ID.DE-P", "Data Processing Ecosystem Risk Management", "Interoperability frameworks or similar agreements are established", "subcategory"),
    ("ID.DE-P5", "ID-P", "Identify-P", "ID.DE-P", "Data Processing Ecosystem Risk Management", "Data processing ecosystem parties are routinely assessed using audits, test results, or other forms of evaluation", "subcategory"),

    ("GV-P", "GV-P", "Govern-P", "", "", "Govern-P", "function"),
    ("GV.PO-P", "GV-P", "Govern-P", "GV.PO-P", "Governance Policies, Processes, and Procedures", "Governance Policies, Processes, and Procedures", "category"),
    ("GV.PO-P1", "GV-P", "Govern-P", "GV.PO-P", "Governance Policies, Processes, and Procedures", "Organizational privacy values and policies are established and communicated", "subcategory"),
    ("GV.PO-P2", "GV-P", "Govern-P", "GV.PO-P", "Governance Policies, Processes, and Procedures", "Processes to instill organizational privacy values within system/product/service development and operations are established", "subcategory"),
    ("GV.PO-P3", "GV-P", "Govern-P", "GV.PO-P", "Governance Policies, Processes, and Procedures", "Roles and responsibilities for the workforce are established with respect to privacy", "subcategory"),
    ("GV.PO-P4", "GV-P", "Govern-P", "GV.PO-P", "Governance Policies, Processes, and Procedures", "Privacy roles and responsibilities are coordinated and aligned with third-party stakeholders", "subcategory"),
    ("GV.PO-P5", "GV-P", "Govern-P", "GV.PO-P", "Governance Policies, Processes, and Procedures", "Legal, regulatory, and contractual requirements regarding privacy are understood and managed", "subcategory"),
    ("GV.PO-P6", "GV-P", "Govern-P", "GV.PO-P", "Governance Policies, Processes, and Procedures", "Governance and risk management processes address privacy risks", "subcategory"),
    ("GV.RM-P", "GV-P", "Govern-P", "GV.RM-P", "Risk Management Strategy", "Risk Management Strategy", "category"),
    ("GV.RM-P1", "GV-P", "Govern-P", "GV.RM-P", "Risk Management Strategy", "Risk management processes are established, managed, and agreed to by organizational stakeholders", "subcategory"),
    ("GV.RM-P2", "GV-P", "Govern-P", "GV.RM-P", "Risk Management Strategy", "Organizational risk tolerance is determined and clearly expressed", "subcategory"),
    ("GV.RM-P3", "GV-P", "Govern-P", "GV.RM-P", "Risk Management Strategy", "The organization's determination of risk tolerance is informed by its role(s) in the data processing ecosystem", "subcategory"),
    ("GV.AT-P", "GV-P", "Govern-P", "GV.AT-P", "Awareness and Training", "Awareness and Training", "category"),
    ("GV.AT-P1", "GV-P", "Govern-P", "GV.AT-P", "Awareness and Training", "The workforce is informed and trained on its roles and responsibilities", "subcategory"),
    ("GV.AT-P2", "GV-P", "Govern-P", "GV.AT-P", "Awareness and Training", "Senior executives understand their roles and responsibilities", "subcategory"),
    ("GV.AT-P3", "GV-P", "Govern-P", "GV.AT-P", "Awareness and Training", "Privacy personnel understand their roles and responsibilities", "subcategory"),
    ("GV.AT-P4", "GV-P", "Govern-P", "GV.AT-P", "Awareness and Training", "Third parties understand their roles and responsibilities", "subcategory"),
    ("GV.MT-P", "GV-P", "Govern-P", "GV.MT-P", "Monitoring and Review", "Monitoring and Review", "category"),
    ("GV.MT-P1", "GV-P", "Govern-P", "GV.MT-P", "Monitoring and Review", "Privacy risk is re-evaluated on an ongoing basis and as key factors change", "subcategory"),

    ("CT-P", "CT-P", "Control-P", "", "", "Control-P", "function"),
    ("CT.PO-P", "CT-P", "Control-P", "CT.PO-P", "Data Processing Policies, Processes, and Procedures", "Data Processing Policies, Processes, and Procedures", "category"),
    ("CT.PO-P1", "CT-P", "Control-P", "CT.PO-P", "Data Processing Policies, Processes, and Procedures", "Policies, processes, and procedures for authorizing data processing are maintained and communicated", "subcategory"),
    ("CT.PO-P2", "CT-P", "Control-P", "CT.PO-P", "Data Processing Policies, Processes, and Procedures", "Policies, processes, and procedures for enabling data review, transfer, sharing or disclosure are maintained", "subcategory"),
    ("CT.PO-P3", "CT-P", "Control-P", "CT.PO-P", "Data Processing Policies, Processes, and Procedures", "Policies, processes, and procedures for enabling individuals' data processing preferences are maintained", "subcategory"),
    ("CT.PO-P4", "CT-P", "Control-P", "CT.PO-P", "Data Processing Policies, Processes, and Procedures", "A data life cycle to manage data is aligned and implemented with the system development life cycle", "subcategory"),
    ("CT.DM-P", "CT-P", "Control-P", "CT.DM-P", "Data Processing Management", "Data Processing Management", "category"),
    ("CT.DM-P1", "CT-P", "Control-P", "CT.DM-P", "Data Processing Management", "Data elements can be accessed for review", "subcategory"),
    ("CT.DM-P2", "CT-P", "Control-P", "CT.DM-P", "Data Processing Management", "Data elements can be accessed for transmission or disclosure", "subcategory"),
    ("CT.DM-P3", "CT-P", "Control-P", "CT.DM-P", "Data Processing Management", "Data elements can be accessed for alteration", "subcategory"),
    ("CT.DM-P4", "CT-P", "Control-P", "CT.DM-P", "Data Processing Management", "Data elements can be accessed for deletion", "subcategory"),
    ("CT.DP-P", "CT-P", "Control-P", "CT.DP-P", "Disassociated Processing", "Disassociated Processing", "category"),
    ("CT.DP-P1", "CT-P", "Control-P", "CT.DP-P", "Disassociated Processing", "Data are processed to limit observability and linkability", "subcategory"),
    ("CT.DP-P2", "CT-P", "Control-P", "CT.DP-P", "Disassociated Processing", "Data are processed to limit the identification of individuals", "subcategory"),
    ("CT.DP-P3", "CT-P", "Control-P", "CT.DP-P", "Disassociated Processing", "Data are processed to limit the formulation of inferences about individuals' behavior or activities", "subcategory"),

    ("CM-P", "CM-P", "Communicate-P", "", "", "Communicate-P", "function"),
    ("CM.AW-P", "CM-P", "Communicate-P", "CM.AW-P", "Communication Policies, Processes, and Procedures", "Communication Policies, Processes, and Procedures", "category"),
    ("CM.AW-P1", "CM-P", "Communicate-P", "CM.AW-P", "Communication Policies, Processes, and Procedures", "Mechanisms for individuals to inquire about the processing of their data and the results are established", "subcategory"),
    ("CM.AW-P2", "CM-P", "Communicate-P", "CM.AW-P", "Communication Policies, Processes, and Procedures", "Mechanisms for reporting on the organization's data processing activities are established", "subcategory"),
    ("CM.AW-P3", "CM-P", "Communicate-P", "CM.AW-P", "Communication Policies, Processes, and Procedures", "System/product/service design enables data processing visibility", "subcategory"),
    ("CM.AW-P4", "CM-P", "Communicate-P", "CM.AW-P", "Communication Policies, Processes, and Procedures", "Records of data disclosures and sharing are maintained", "subcategory"),
    ("CM.AW-P5", "CM-P", "Communicate-P", "CM.AW-P", "Communication Policies, Processes, and Procedures", "Data corrections or deletions can be communicated to individuals or organizations", "subcategory"),
    ("CM.AW-P6", "CM-P", "Communicate-P", "CM.AW-P", "Communication Policies, Processes, and Procedures", "Data provenance and lineage are maintained and can be accessed for review or transmission/disclosure", "subcategory"),

    ("PR-P", "PR-P", "Protect-P", "", "", "Protect-P", "function"),
    ("PR.AC-P", "PR-P", "Protect-P", "PR.AC-P", "Identity Management, Authentication, and Access Control", "Identity Management, Authentication, and Access Control", "category"),
    ("PR.AC-P1", "PR-P", "Protect-P", "PR.AC-P", "Identity Management, Authentication, and Access Control", "Identities and credentials are issued, managed, verified, revoked, and audited for authorized individuals", "subcategory"),
    ("PR.AC-P2", "PR-P", "Protect-P", "PR.AC-P", "Identity Management, Authentication, and Access Control", "Physical access to data and devices is managed", "subcategory"),
    ("PR.AC-P3", "PR-P", "Protect-P", "PR.AC-P", "Identity Management, Authentication, and Access Control", "Remote access is managed", "subcategory"),
    ("PR.AC-P4", "PR-P", "Protect-P", "PR.AC-P", "Identity Management, Authentication, and Access Control", "Access permissions and authorizations are managed", "subcategory"),
    ("PR.AC-P5", "PR-P", "Protect-P", "PR.AC-P", "Identity Management, Authentication, and Access Control", "Network integrity is protected", "subcategory"),
    ("PR.AC-P6", "PR-P", "Protect-P", "PR.AC-P", "Identity Management, Authentication, and Access Control", "Individuals and devices are proofed and bound to credentials and authenticated", "subcategory"),
    ("PR.DS-P", "PR-P", "Protect-P", "PR.DS-P", "Data Security", "Data Security", "category"),
    ("PR.DS-P1", "PR-P", "Protect-P", "PR.DS-P", "Data Security", "Data-at-rest are protected", "subcategory"),
    ("PR.DS-P2", "PR-P", "Protect-P", "PR.DS-P", "Data Security", "Data-in-transit are protected", "subcategory"),
    ("PR.DS-P3", "PR-P", "Protect-P", "PR.DS-P", "Data Security", "Systems/products/services and associated data are formally managed throughout removal, transfers, and disposition", "subcategory"),
    ("PR.DS-P4", "PR-P", "Protect-P", "PR.DS-P", "Data Security", "Adequate capacity to ensure availability is maintained", "subcategory"),
    ("PR.DS-P5", "PR-P", "Protect-P", "PR.DS-P", "Data Security", "Protections against data leaks are implemented", "subcategory"),
    ("PR.DS-P6", "PR-P", "Protect-P", "PR.DS-P", "Data Security", "Integrity checking mechanisms are used to verify software, firmware, and information integrity", "subcategory"),
    ("PR.DS-P7", "PR-P", "Protect-P", "PR.DS-P", "Data Security", "The development and testing environment(s) are separate from the production environment", "subcategory"),
    ("PR.MA-P", "PR-P", "Protect-P", "PR.MA-P", "Maintenance", "Maintenance", "category"),
    ("PR.MA-P1", "PR-P", "Protect-P", "PR.MA-P", "Maintenance", "Maintenance and repair of organizational assets are performed and logged", "subcategory"),
    ("PR.MA-P2", "PR-P", "Protect-P", "PR.MA-P", "Maintenance", "Remote maintenance of organizational assets is approved, logged, and performed in a manner that prevents unauthorized access", "subcategory"),
    ("PR.PT-P", "PR-P", "Protect-P", "PR.PT-P", "Protective Technology", "Protective Technology", "category"),
    ("PR.PT-P1", "PR-P", "Protect-P", "PR.PT-P", "Protective Technology", "Removable media use is limited according to policy", "subcategory"),
    ("PR.PT-P2", "PR-P", "Protect-P", "PR.PT-P", "Protective Technology", "The principle of least functionality is incorporated by configuring systems to provide only essential capabilities", "subcategory"),
    ("PR.PT-P3", "PR-P", "Protect-P", "PR.PT-P", "Protective Technology", "Communications and control networks are protected", "subcategory"),
    ("PR.PT-P4", "PR-P", "Protect-P", "PR.PT-P", "Protective Technology", "Mechanisms (e.g., failsafe, load balancing, hot swap) are implemented to achieve resilience requirements", "subcategory"),
]


def scrape_nist_pf(conn: sqlite3.Connection) -> int:
    conn.executemany(
        "INSERT OR REPLACE INTO nist_pf "
        "(id, function_id, function_name, category_id, category_name, title, level) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        _PF_DATA,
    )
    conn.commit()
    log.info("Loaded %d Privacy Framework entries", len(_PF_DATA))
    return len(_PF_DATA)
