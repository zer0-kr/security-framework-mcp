<p align="center">
  <h1 align="center">security-framework-mcp</h1>
  <p align="center">
    <strong>Unified NIST + OWASP security framework MCP server</strong>
  </p>
  <p align="center">
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
    <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-green.svg" alt="MCP Compatible"></a>
    <a href="https://nist.gov"><img src="https://img.shields.io/badge/NIST-data%20source-orange.svg" alt="NIST"></a>
    <a href="https://owasp.org"><img src="https://img.shields.io/badge/OWASP-data%20source-orange.svg" alt="OWASP"></a>
  </p>
  <p align="center">
    <a href="./README.ko.md">한국어</a>
  </p>
</p>

---

Search and query **3,439 security data points** through a single MCP interface — **NIST** (1,196 SP 800-53 controls with 53A assessments and 53B baselines, CSF 2.0, PF 1.0, SP 800-37 RMF, 613 publications, CMVP, NICE, glossary, CSF↔800-53 mappings) and **OWASP** (Top 10, API/LLM/MCP Top 10, ASVS 5.0, WSTG, MASVS, Proactive Controls, 113+ Cheat Sheets, 418+ projects) — with **live NVD/CVE + CISA KEV**, PDF reading, compliance mapping, STRIDE threat modeling, and MCP security assessment.

## Quick Start

```bash
pip install git+https://github.com/zer0-kr/security-framework-mcp.git
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "security": {
      "command": "security-framework-mcp"
    }
  }
}
```

Claude CLI (Claude Code):

```bash
claude mcp add security -- security-framework-mcp
```

<details>
<summary>Other MCP clients (Cursor, OpenCode)</summary>

```json
{ "security": { "command": "security-framework-mcp" } }
```

</details>

## Data Sources (21 local + 2 live)

### NIST (10)

| Source | Records |
|--------|---------|
| SP 800-53 Rev. 5 Controls (+ 53A assessments + 53B baselines) | 1,196 |
| CSF 2.0 | 225 |
| PF 1.0 | 92 |
| SP 800-37 RMF | 7 steps |
| Publications (SP 800, FIPS, IR, CSWP) | 613 |
| CSF ↔ 800-53 Mappings | 57 |
| Glossary | 39 |
| Synonyms | 53 |
| CMVP (FIPS 140) | 15 |
| NICE Work Roles | 43 |

### OWASP (11)

| Source | Records |
|--------|---------|
| Projects | 418 |
| ASVS 5.0 | 345 |
| WSTG | 111 |
| Top 10 2021 / API Top 10 2023 / LLM Top 10 2025 / MCP Top 10 2025 | 10 each |
| Proactive Controls 2024 | 10 |
| MASVS | 23 |
| CWE Database | 39 |
| Cheat Sheets | 113+ |

### Live APIs

| Source | Description |
|--------|-------------|
| NVD CVE API 2.0 | Real-time CVE search |
| CISA KEV | Known Exploited Vulnerabilities catalog |

## Tools (36)

### NIST

| Tool | Description |
|------|-------------|
| `search_nist` | Search all 10 NIST sources |
| `get_nist_control` | SP 800-53 control — statement, guidance, **53A assessment**, **53B baseline** filter (LOW/MODERATE/HIGH), family filter |
| `get_nist_csf` | CSF 2.0 functions/categories/subcategories |
| `get_nist_pf` | PF 1.0 |
| `get_nist_rmf` | SP 800-37 RMF steps, tasks, key documents |
| `get_nist_publication` | 613 publications (SP 800, FIPS, IR, CSWP) |
| `read_publication` | Download + convert NIST PDFs to Markdown |
| `get_nist_mapping` | CSF 2.0 ↔ SP 800-53 bidirectional mappings |
| `get_nist_glossary` | Cybersecurity terms |
| `get_nist_cmvp` | FIPS 140 validated modules |
| `get_nice_roles` | NICE workforce roles |

### OWASP

| Tool | Description |
|------|-------------|
| `list_projects` | Browse 418+ projects by level/type |
| `search_projects` | Full-text search across projects |
| `get_project` | Project details |
| `get_asvs` | ASVS 5.0 — filter by chapter, level, query |
| `get_wstg` | WSTG test cases — filter by category, query |
| `get_top10` | Top 10 2021 + CWE mappings |
| `get_api_top10` | API Security Top 10 2023 |
| `get_llm_top10` | LLM Top 10 2025 |
| `get_mcp_top10` | MCP Top 10 2025 |
| `get_proactive_controls` | Proactive Controls 2024 |
| `get_masvs` | MASVS mobile security |
| `get_cheatsheet` | 113+ Cheat Sheets |

### Vulnerability & CWE

| Tool | Description |
|------|-------------|
| `get_cwe` | CWE lookup + auto OWASP cross-references |
| `search_cve` | Live NVD search |
| `get_cve_detail` | Full CVE details |
| `search_kev` | CISA Known Exploited Vulnerabilities |

### Analysis & Assessment

| Tool | Description |
|------|-------------|
| `search_owasp` | Search all 21 sources (NIST + OWASP unified) |
| `cross_reference` | CWE → Top 10 / ASVS / WSTG |
| `compliance_map` | ASVS → PCI-DSS 4.0 / ISO 27001:2022 / NIST 800-53 |
| `assess_stack` | Tech stack security assessment |
| `generate_checklist` | Security checklist (web/api/mobile/llm/full × basic/standard/comprehensive) |
| `assess_mcp_security` | MCP Top 10 assessment |
| `threat_model` | STRIDE threat modeling |
| `update_database` | Rebuild index |
| `database_status` | DB status |

## Prompts (4)

| Prompt | Description |
|--------|-------------|
| `security_review` | Guided security review |
| `threat_analysis` | Threat analysis workflow |
| `compliance_check` | Compliance assessment |
| `secure_code_review` | Code security review |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURITY_MCP_DATA_DIR` | `~/.security-framework-mcp` | Database directory |
| `SECURITY_MCP_UPDATE_INTERVAL` | `604800` (7 days) | Refresh interval |
| `NVD_API_KEY` | _(none)_ | Optional NVD API key |

## Architecture

```
┌─────────────────────────────────┐
│         MCP Client              │
│  (Claude / Cursor / OpenCode)   │
└──────────────┬──────────────────┘
               │ stdio
┌──────────────▼──────────────────┐
│   security-framework-mcp        │
│  36 tools · 4 prompts · 6 rsrc │
├──────────────┬──────────────────┤
│  SQLite FTS5 │  Live APIs       │
│  (~6.2MB)    │  NVD + CISA KEV │
├──────────────┴──────────────────┤
│  NIST Collectors (10)           │
│  OWASP Collectors (11)          │
└──────────────┬──────────────────┘
               │ httpx (retry)
┌──────────────▼──────────────────┐
│  NIST OSCAL/CSRC · OWASP GitHub │
└─────────────────────────────────┘
```

## Development

```bash
git clone https://github.com/zer0-kr/security-framework-mcp.git
cd security-framework-mcp
pip install -e ".[dev]"
python -m pytest tests/test_unit_db.py tests/test_unit_collectors.py -v
python tests/test_comprehensive.py
```

## Contributing

1. Fork → 2. Branch → 3. Test (`python -m pytest`) → 4. PR

## License

[MIT](LICENSE)

---

Not affiliated with OWASP Foundation or NIST. Data sourced from public repositories.
