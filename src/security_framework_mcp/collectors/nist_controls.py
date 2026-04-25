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
    is_withdrawn INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_nist_ctrl_family ON nist_controls(family_id);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS nist_controls_fts USING fts5(
    id, family_name, title, statement, guidance,
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


def _parse_controls(groups: list[dict], baseline_ids: set[str]) -> list[tuple]:
    rows = []
    for group in groups:
        family_id = group.get("id", "")
        family_name = group.get("title", "")
        for ctrl in group.get("controls", []):
            ctrl_id = ctrl.get("id", "")
            title = ctrl.get("title", "")
            is_withdrawn = 1 if any(
                p.get("class") == "assessment" for p in ctrl.get("props", [])
                if p.get("name") == "status" and p.get("value") == "withdrawn"
            ) else 0

            statement = _extract_prose(
                [p for p in ctrl.get("parts", []) if p.get("name") == "statement"]
            )
            guidance = _extract_prose(
                [p for p in ctrl.get("parts", []) if p.get("name") == "guidance"]
            )

            baselines = []
            norm_id = ctrl_id.lower()
            for level in ["LOW", "MODERATE", "HIGH"]:
                if norm_id in baseline_ids.get(level, set()):
                    baselines.append(level)

            rows.append((
                ctrl_id, family_id, family_name, title,
                statement[:5000] if statement else "",
                guidance[:5000] if guidance else "",
                ",".join(baselines) if baselines else "",
                is_withdrawn,
            ))

            for enh in ctrl.get("controls", []):
                enh_id = enh.get("id", "")
                enh_title = enh.get("title", "")
                enh_statement = _extract_prose(
                    [p for p in enh.get("parts", []) if p.get("name") == "statement"]
                )
                enh_guidance = _extract_prose(
                    [p for p in enh.get("parts", []) if p.get("name") == "guidance"]
                )
                enh_baselines = []
                enh_norm = enh_id.lower()
                for level in ["LOW", "MODERATE", "HIGH"]:
                    if enh_norm in baseline_ids.get(level, set()):
                        enh_baselines.append(level)

                rows.append((
                    enh_id, family_id, family_name, enh_title,
                    enh_statement[:5000] if enh_statement else "",
                    enh_guidance[:5000] if enh_guidance else "",
                    ",".join(enh_baselines) if enh_baselines else "",
                    0,
                ))
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
        "(id, family_id, family_name, title, statement, guidance, baselines, is_withdrawn) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d NIST SP 800-53 controls", len(rows))
    return len(rows)
