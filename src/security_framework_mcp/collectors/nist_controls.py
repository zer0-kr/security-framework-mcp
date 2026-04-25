from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from security_framework_mcp.http_utils import fetch_json

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS nist_controls (
    id TEXT PRIMARY KEY,
    family_id TEXT,
    family_name TEXT,
    title TEXT,
    statement TEXT,
    guidance TEXT,
    baselines TEXT,
    is_withdrawn INTEGER DEFAULT 0,
    assessment_objectives TEXT,
    assessment_methods TEXT
);
CREATE INDEX IF NOT EXISTS idx_nist_ctrl_family ON nist_controls(family_id);
CREATE INDEX IF NOT EXISTS idx_nist_ctrl_baselines ON nist_controls(baselines);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS nist_controls_fts USING fts5(
    id, family_name, title, statement, guidance, assessment_objectives,
    content='nist_controls', content_rowid='rowid'
);
"""

_CATALOG_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/"
    "main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

_BASELINE_URLS = {
    "LOW": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_LOW-baseline-resolved-profile_catalog.json",
    "MODERATE": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json",
    "HIGH": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog.json",
}


def _extract_prose(parts: list[dict[str, Any]] | None) -> str:
    if not parts:
        return ""
    texts = []
    for part in parts:
        if part.get("prose"):
            texts.append(part["prose"])
        if part.get("parts"):
            texts.append(_extract_prose(part["parts"]))
    return " ".join(texts)


def _extract_assessment(parts: list[dict[str, Any]]) -> tuple[str, str]:
    objectives = _extract_prose([p for p in parts if p.get("name") == "assessment-objective"])
    methods_parts = [p for p in parts if p.get("name") == "assessment-method"]
    methods = []
    for mp in methods_parts:
        method_id = mp.get("id", "")
        method_type = "examine" if "examine" in method_id else "interview" if "interview" in method_id else "test"
        objects_prose = _extract_prose([sp for sp in mp.get("parts", []) if sp.get("name") == "assessment-objects"])
        if objects_prose:
            methods.append(f"[{method_type.upper()}] {objects_prose[:500]}")
    return objectives[:3000], "; ".join(methods)[:3000]


def _parse_one_control(ctrl: dict, family_id: str, family_name: str, baseline_ids: dict) -> tuple:
    ctrl_id = ctrl.get("id", "")
    title = ctrl.get("title", "")
    is_withdrawn = 1 if any(
        True for p in ctrl.get("props", [])
        if p.get("name") == "status" and p.get("value") == "withdrawn"
    ) else 0

    parts = ctrl.get("parts", [])
    statement = _extract_prose([p for p in parts if p.get("name") == "statement"])
    guidance = _extract_prose([p for p in parts if p.get("name") == "guidance"])
    assess_obj, assess_methods = _extract_assessment(parts)

    baselines = []
    norm_id = ctrl_id.lower()
    for level in ["LOW", "MODERATE", "HIGH"]:
        if norm_id in baseline_ids.get(level, set()):
            baselines.append(level)

    return (
        ctrl_id, family_id, family_name, title,
        statement[:5000], guidance[:5000],
        ",".join(baselines), is_withdrawn,
        assess_obj, assess_methods,
    )


def _parse_controls(groups: list[dict], baseline_ids: dict) -> list[tuple]:
    rows = []
    for group in groups:
        family_id = group.get("id", "")
        family_name = group.get("title", "")
        for ctrl in group.get("controls", []):
            rows.append(_parse_one_control(ctrl, family_id, family_name, baseline_ids))
            for enh in ctrl.get("controls", []):
                rows.append(_parse_one_control(enh, family_id, family_name, baseline_ids))
    return rows


def _collect_baseline_ids(url: str) -> set[str]:
    try:
        data = fetch_json(url, timeout=60)
        ids: set[str] = set()
        catalog = data.get("catalog", {})
        for group in catalog.get("groups", []):
            for ctrl in group.get("controls", []):
                ids.add(ctrl.get("id", "").lower())
                for enh in ctrl.get("controls", []):
                    ids.add(enh.get("id", "").lower())
        return ids
    except Exception as exc:
        log.warning("Failed to fetch baseline %s: %s", url, exc)
        return set()


def scrape_nist_controls(conn: sqlite3.Connection) -> int:
    catalog_data = fetch_json(_CATALOG_URL, timeout=90)
    catalog = catalog_data.get("catalog", {})
    groups = catalog.get("groups", [])

    baseline_ids: dict[str, set[str]] = {}
    for level, url in _BASELINE_URLS.items():
        baseline_ids[level] = _collect_baseline_ids(url)

    rows = _parse_controls(groups, baseline_ids)

    conn.executemany(
        "INSERT OR REPLACE INTO nist_controls "
        "(id, family_id, family_name, title, statement, guidance, baselines, is_withdrawn, assessment_objectives, assessment_methods) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d NIST SP 800-53 controls", len(rows))
    return len(rows)
