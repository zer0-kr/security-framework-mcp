from __future__ import annotations

import logging
import sqlite3
from typing import Any

from security_framework_mcp.http_utils import fetch_json

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS nist_csf (
    id TEXT PRIMARY KEY,
    function_id TEXT,
    function_name TEXT,
    category_id TEXT,
    category_name TEXT,
    title TEXT,
    level TEXT
);
CREATE INDEX IF NOT EXISTS idx_csf_function ON nist_csf(function_id);
CREATE INDEX IF NOT EXISTS idx_csf_level ON nist_csf(level);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS nist_csf_fts USING fts5(
    id, function_name, category_name, title,
    content='nist_csf', content_rowid='rowid'
);
"""

_CSF_OSCAL_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/"
    "main/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json"
)


def _parse_oscal_csf(data: dict) -> list[tuple]:
    rows = []
    catalog = data.get("catalog", {})
    for group in catalog.get("groups", []):
        func_id = group.get("id", "").upper()
        func_name = group.get("title", "")
        rows.append((func_id, func_id, func_name, "", "", func_name, "function"))

        for cat in group.get("controls", []):
            cat_id = cat.get("id", "").upper()
            cat_name = cat.get("title", "")
            rows.append((cat_id, func_id, func_name, cat_id, cat_name, cat_name, "category"))

            for sub in cat.get("controls", []):
                sub_id = sub.get("id", "").upper()
                sub_title = sub.get("title", sub_id)
                rows.append((sub_id, func_id, func_name, cat_id, cat_name, sub_title, "subcategory"))

    return rows


def scrape_nist_csf(conn: sqlite3.Connection) -> int:
    data = fetch_json(_CSF_OSCAL_URL, timeout=60)
    rows = _parse_oscal_csf(data)

    conn.executemany(
        "INSERT OR REPLACE INTO nist_csf "
        "(id, function_id, function_name, category_id, category_name, title, level) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d CSF 2.0 entries", len(rows))
    return len(rows)
