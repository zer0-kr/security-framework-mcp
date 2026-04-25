<p align="center">
  <h1 align="center">security-framework-mcp</h1>
  <p align="center">
    <strong>Unified OWASP + NIST security framework MCP server</strong>
  </p>
  <p align="center">
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
    <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-green.svg" alt="MCP Compatible"></a>
    <a href="https://owasp.org"><img src="https://img.shields.io/badge/OWASP-data%20source-orange.svg" alt="OWASP"></a>
    <a href="https://nist.gov"><img src="https://img.shields.io/badge/NIST-data%20source-orange.svg" alt="NIST"></a>
  </p>
</p>

---

Search and query **3,230+ security data points** through a single MCP interface — **OWASP** (Top 10, API Top 10, LLM Top 10, MCP Top 10, ASVS, WSTG, MASVS, Proactive Controls, Cheat Sheets, 418+ projects) and **NIST** (1,196 SP 800-53 controls, CSF 2.0, 613 publications, CMVP, NICE work roles, glossary) — with **live NVD/CVE**, cross-references, compliance mapping, STRIDE threat modeling, and MCP security assessment.

## Why security-framework-mcp?

OWASP and NIST resources are scattered across dozens of repositories with different formats. This server unifies them into one searchable interface:

- Search across **17 data sources** (OWASP + NIST) with a single query
- Look up any **NIST SP 800-53 control** with statement, guidance, and baseline levels
- Query **CSF 2.0** functions, categories, and subcategories
- Browse all **613 NIST cybersecurity publications** (SP 800, FIPS, IR, CSWP)
- Cross-reference CWEs with Top 10, ASVS, WSTG, and **NIST 800-53 controls**
- Map ASVS requirements to **PCI-DSS, ISO 27001, and NIST 800-53** for compliance
- Search **live NVD** for CVE vulnerabilities by keyword, CWE, or severity
- Generate **STRIDE-based threat models** with OWASP + NIST mitigations
- Assess MCP server deployments against the **OWASP MCP Top 10**
- Generate security checklists tailored to your project type and depth
- Use pre-built **prompt templates** for guided security reviews and threat analysis

No API keys required for local data. NVD API works without a key (rate-limited) or with an optional `NVD_API_KEY` for higher throughput.

## Quick Start

### Install

```bash
pip install git+https://github.com/zer0-kr/security-framework-mcp.git
```

### Connect to Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security": {
      "command": "security-framework-mcp"
    }
  }
}
```

The local database builds automatically on first run (~15-20 seconds) and refreshes weekly.

### Connect to Other MCP Clients

<details>
<summary><strong>Cursor / Windsurf</strong></summary>

```json
{
  "security": {
    "command": "security-framework-mcp"
  }
}
```

</details>

<details>
<summary><strong>OpenCode / CLI</strong></summary>

```json
{
  "mcpServers": {
    "security": {
      "type": "stdio",
      "command": "security-framework-mcp"
    }
  }
}
```

</details>

## Data Sources (17 local + 1 live)

### OWASP (11 sources)

| Source | Records | Origin |
|--------|---------|--------|
| **Projects** | 418+ | [owasp.github.io](https://raw.githubusercontent.com/OWASP/owasp.github.io/main/_data/projects.json) |
| **ASVS 5.0** | 345 | [OWASP/ASVS](https://github.com/OWASP/ASVS) |
| **WSTG** | 111 | [OWASP/wstg](https://github.com/OWASP/wstg) |
| **Top 10 2021** | 10 | [OWASP/Top10](https://github.com/OWASP/Top10) |
| **API Security Top 10 2023** | 10 | [OWASP API Security](https://owasp.org/API-Security/) |
| **LLM Top 10 2025** | 10 | [OWASP GenAI](https://genai.owasp.org/llm-top-10/) |
| **MCP Top 10 2025** | 10 | [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) |
| **Proactive Controls 2024** | 10 | [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/) |
| **MASVS** | 23 | [OWASP/owasp-masvs](https://github.com/OWASP/owasp-masvs) |
| **CWE Database** | 39 | [MITRE CWE](https://cwe.mitre.org/) |
| **Cheat Sheets** | 113+ | [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) |

### NIST (6 sources)

| Source | Records | Origin |
|--------|---------|--------|
| **SP 800-53 Rev. 5** | 1,196 | [OSCAL Content](https://github.com/usnistgov/oscal-content) (OSCAL JSON) |
| **CSF 2.0** | 225 | [OSCAL Content](https://github.com/usnistgov/oscal-content) (OSCAL JSON) |
| **Publications** | 613 | [CSRC XLSX](https://csrc.nist.gov/) (SP 800, FIPS, IR, CSWP) |
| **Glossary** | 39 | Curated from SP 800-53, FIPS, CSF |
| **CMVP** | 15 | Curated FIPS 140 validated modules |
| **NICE Work Roles** | 43 | SP 800-181 Rev. 1 (v2.1) |

### Live API

| Source | Origin |
|--------|--------|
| **NVD/CVE** | [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) |

## Tools Reference (31 tools)

### OWASP — Project Discovery

| Tool | Description |
|------|-------------|
| `list_projects` | Browse all 418+ projects. Filter by `level` and `type` |
| `search_projects` | Full-text search across projects |
| `get_project` | Get detailed project metadata |

### OWASP — Standards & Guidelines

| Tool | Description |
|------|-------------|
| `get_asvs` | ASVS 5.0 requirements. Filter by `chapter`, `level`, `query` |
| `get_wstg` | WSTG test cases. Filter by `category` or `query` |
| `get_top10` | Top 10 2021 with CWE mappings |
| `get_api_top10` | API Security Top 10 2023 |
| `get_llm_top10` | LLM Top 10 2025 |
| `get_mcp_top10` | MCP Top 10 2025 — MCP server security risks |
| `get_proactive_controls` | Proactive Controls 2024 |
| `get_masvs` | MASVS mobile security controls |
| `get_cheatsheet` | 113+ Cheat Sheets (on-demand content) |

### NIST — Controls & Frameworks

| Tool | Description |
|------|-------------|
| `search_nist` | Search across all 6 NIST sources at once |
| `get_nist_control` | Look up SP 800-53 control by ID — statement, guidance, baselines (LOW/MODERATE/HIGH) |
| `get_nist_csf` | CSF 2.0 functions, categories, subcategories |
| `get_nist_publication` | Browse/search all 613 NIST cybersecurity publications |
| `get_nist_glossary` | NIST cybersecurity terms and definitions |
| `get_nist_cmvp` | FIPS 140 validated cryptographic modules |
| `get_nice_roles` | NICE Workforce Framework work roles |

### Vulnerability & CWE

| Tool | Description |
|------|-------------|
| `get_cwe` | CWE lookup with auto OWASP cross-references |
| `search_cve` | Live NVD CVE search by keyword, CWE, or severity |
| `get_cve_detail` | Full CVE details — CVSS, weaknesses, references |

### Cross-Referencing & Assessment

| Tool | Description |
|------|-------------|
| `search_owasp` | Search across **all 17 local sources** (OWASP + NIST) |
| `cross_reference` | CWE → Top 10 / ASVS / WSTG mapping |
| `compliance_map` | ASVS → PCI-DSS 4.0 / ISO 27001:2022 / NIST 800-53 Rev. 5 |
| `assess_stack` | Tech stack → tailored security recommendations |
| `generate_checklist` | Security checklist by project type and depth |
| `assess_mcp_security` | MCP server assessment against MCP Top 10 |
| `threat_model` | STRIDE-based threat model with OWASP + NIST mitigations |

### Database Management

| Tool | Description |
|------|-------------|
| `update_database` | Rebuild local index from upstream sources |
| `database_status` | Database availability, build time, size |

## Prompt Templates (4 prompts)

| Prompt | Description |
|--------|-------------|
| `security_review` | Guided security review using OWASP + NIST standards |
| `threat_analysis` | Threat analysis — identifies threats, maps to CWEs, recommends controls |
| `compliance_check` | Compliance assessment — ASVS with testing procedures |
| `secure_code_review` | Code review — vulnerabilities with CWE IDs and secure alternatives |

## Resources (6 URIs)

| URI | Description |
|-----|-------------|
| `owasp://about` | Server version, database status, tools and prompts |
| `owasp://stats` | Record counts per source, DB size |
| `owasp://top10/2021` | Full Top 10 2021 content |
| `owasp://api-top10/2023` | Full API Security Top 10 2023 |
| `owasp://llm-top10/2025` | Full LLM Top 10 2025 |
| `owasp://proactive-controls/2024` | Full Proactive Controls 2024 |

## Usage Examples

```
> Search all OWASP and NIST data for "access control"

> Look up NIST control AC-1

> Show CSF 2.0 Protect function categories

> Search NIST publications about zero trust

> What FIPS 140 validated crypto modules does AWS have?

> What NICE work roles are in the Protect and Defend category?

> Cross-reference CWE-79 with OWASP and NIST standards

> Map ASVS chapter V4 to PCI-DSS, ISO 27001, and NIST 800-53

> Generate a STRIDE threat model for my e-commerce API

> Assess my MCP server: shell exec, no auth, community plugins

> Search NVD for critical log4j CVEs

> Generate a comprehensive security checklist for a web API

> Show ASVS requirements for authentication at level 2

> What are the LLM Top 10 security risks?
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SECURITY_MCP_DATA_DIR` | `~/.security-framework-mcp` | Local database directory |
| `SECURITY_MCP_UPDATE_INTERVAL` | `604800` (7 days) | Auto-refresh interval in seconds |
| `NVD_API_KEY` | _(none)_ | Optional NVD API key for higher rate limits |

## Architecture

```
┌─────────────────────────────────┐
│         MCP Client              │
│  (Claude / Cursor / OpenCode)   │
└──────────────┬──────────────────┘
               │ stdio
┌──────────────▼──────────────────┐
│   security-framework-mcp        │
│  31 tools · 4 prompts · 6 rsrc │
├──────────────┬──────────────────┤
│  SQLite FTS5 │  Live APIs       │
│  (~4.5MB)    │  NVD CVE 2.0    │
├──────────────┴──────────────────┤
│  OWASP Collectors (11)          │
│  projects · asvs · wstg · top10 │
│  api/llm/mcp top10 · masvs     │
│  proactive · cheatsheets · cwes │
├─────────────────────────────────┤
│  NIST Collectors (6)            │
│  800-53 · CSF 2.0 · pubs       │
│  glossary · CMVP · NICE        │
└──────────────┬──────────────────┘
               │ httpx
┌──────────────▼──────────────────┐
│  OWASP GitHub · NIST OSCAL/CSRC │
│  Raw JSON/XLSX/Markdown          │
└─────────────────────────────────┘
```

## Development

```bash
git clone https://github.com/zer0-kr/security-framework-mcp.git
cd security-framework-mcp
pip install -e ".[dev]"

# Unit tests (fast, no network)
python -m pytest tests/test_unit_db.py tests/test_unit_collectors.py -v

# Full integration tests
python tests/test_comprehensive.py

# Run server
python -m security_framework_mcp
```

### Project Structure

```
src/security_framework_mcp/
├── server.py              # FastMCP entry point + prompts + resources
├── config.py              # Environment-based configuration
├── db.py                  # SQLite FTS5 query helpers
├── index.py               # IndexManager — builds DB from all collectors
├── nvd.py                 # NVD API client (live CVE search)
├── http_utils.py          # HTTP fetch with exponential backoff retry
├── collectors/
│   ├── projects.py        # OWASP 418+ project metadata
│   ├── asvs.py            # OWASP ASVS 5.0
│   ├── wstg.py            # OWASP WSTG
│   ├── top10.py           # OWASP Top 10 2021
│   ├── api_top10.py       # OWASP API Security Top 10 2023
│   ├── llm_top10.py       # OWASP LLM Top 10 2025
│   ├── mcp_top10.py       # OWASP MCP Top 10 2025
│   ├── proactive_controls.py  # OWASP Proactive Controls 2024
│   ├── masvs.py           # OWASP MASVS
│   ├── cwe_data.py        # CWE database (39 entries)
│   ├── cheatsheets.py     # OWASP Cheat Sheets (on-demand)
│   ├── nist_controls.py   # NIST SP 800-53 Rev. 5 (1,196 controls)
│   ├── nist_csf.py        # NIST CSF 2.0 (225 entries)
│   ├── nist_publications.py   # NIST Publications (613 from CSRC)
│   ├── nist_glossary.py   # NIST Glossary (39 terms)
│   ├── nist_cmvp.py       # NIST CMVP (15 modules)
│   └── nist_nice.py       # NICE Work Roles (43 roles)
└── tools/
    └── owasp_tools.py     # All 31 MCP tool definitions
```

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feat/my-feature`)
3. Run tests (`python -m pytest tests/ -v` or `python tests/test_comprehensive.py`)
4. Commit your changes
5. Open a Pull Request

## Disclaimer

This project is not officially affiliated with or endorsed by the OWASP Foundation or NIST. All data is sourced from publicly available repositories under their respective licenses.

## License

[MIT](LICENSE)
