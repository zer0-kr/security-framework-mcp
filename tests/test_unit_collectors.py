from __future__ import annotations

from owasp_mcp.collectors.top10 import TOP10_2021
from owasp_mcp.collectors.api_top10 import API_TOP10_2023
from owasp_mcp.collectors.llm_top10 import LLM_TOP10_2025
from owasp_mcp.collectors.proactive_controls import PROACTIVE_CONTROLS_2024
from owasp_mcp.collectors.mcp_top10 import MCP_TOP10_2025
from owasp_mcp.collectors.masvs import MASVS_DATA
from owasp_mcp.collectors.cwe_data import CWE_DATABASE


class TestTop10Data:
    def test_has_10_items(self):
        assert len(TOP10_2021) == 10

    def test_all_have_required_fields(self):
        for item in TOP10_2021:
            assert "id" in item and "name" in item and "cwes" in item

    def test_ids_sequential(self):
        for i, item in enumerate(TOP10_2021, 1):
            assert item["id"] == f"A{str(i).zfill(2)}:2021"


class TestApiTop10Data:
    def test_has_10_items(self):
        assert len(API_TOP10_2023) == 10

    def test_all_have_required_fields(self):
        for item in API_TOP10_2023:
            assert all(k in item for k in ["id", "name", "description", "cwes", "url"])

    def test_ids_sequential(self):
        for i, item in enumerate(API_TOP10_2023, 1):
            assert item["id"] == f"API{i}:2023"


class TestLlmTop10Data:
    def test_has_10_items(self):
        assert len(LLM_TOP10_2025) == 10

    def test_ids_format(self):
        for i, item in enumerate(LLM_TOP10_2025, 1):
            assert item["id"] == f"LLM{str(i).zfill(2)}:2025"


class TestMcpTop10Data:
    def test_has_10_items(self):
        assert len(MCP_TOP10_2025) == 10

    def test_ids_format(self):
        for i, item in enumerate(MCP_TOP10_2025, 1):
            assert item["id"] == f"MCP{str(i).zfill(2)}:2025"

    def test_all_have_impact(self):
        for item in MCP_TOP10_2025:
            assert "impact" in item and len(item["impact"]) > 10


class TestProactiveControlsData:
    def test_has_10_items(self):
        assert len(PROACTIVE_CONTROLS_2024) == 10

    def test_ids_format(self):
        for i, item in enumerate(PROACTIVE_CONTROLS_2024, 1):
            assert item["id"] == f"C{i}"


class TestMasvsData:
    def test_has_8_categories(self):
        assert len(MASVS_DATA) == 8

    def test_category_ids(self):
        expected = ["MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-AUTH", "MASVS-NETWORK",
                    "MASVS-PLATFORM", "MASVS-CODE", "MASVS-RESILIENCE", "MASVS-PRIVACY"]
        actual = [cat_id for cat_id, _, _ in MASVS_DATA]
        assert actual == expected

    def test_total_controls(self):
        total = sum(len(controls) for _, _, controls in MASVS_DATA)
        assert total == 23


class TestCweDatabase:
    def test_has_entries(self):
        assert len(CWE_DATABASE) >= 30

    def test_all_tuples(self):
        for entry in CWE_DATABASE:
            assert len(entry) == 3
            cwe_id, name, desc = entry
            assert cwe_id.startswith("CWE-")
            assert len(name) > 5
            assert len(desc) > 20

    def test_key_cwes_present(self):
        ids = {e[0] for e in CWE_DATABASE}
        for key in ["CWE-79", "CWE-89", "CWE-918", "CWE-352", "CWE-287"]:
            assert key in ids, f"{key} missing from CWE database"
