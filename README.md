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

Search and query **4,700+ security data points** through a single MCP interface — **NIST** (1,196 SP 800-53 controls with 53A assessments and 53B baselines, CSF 2.0, PF 1.0, SP 800-37 RMF, 613 publications, CMVP, NICE, glossary, CSF↔800-53 mappings) and **OWASP** (Top 10, API/LLM/MCP Top 10, ASVS 5.0, WSTG, MASVS, Proactive Controls, 815+ CWEs, 559 CAPEC attack patterns, 113+ Cheat Sheets, 418+ projects) — with **live NVD/CVE + CISA KEV + EPSS**, PDF reading, compliance mapping, STRIDE threat modeling, and MCP security assessment.

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

First run automatically builds the local database (~15-20 seconds). Auto-refreshes weekly.

## Data Sources (22 local + 3 live)

### NIST (10)

| Source | Records | Description |
|--------|---------|-------------|
| SP 800-53 Rev. 5 Controls | 1,196 | Security/privacy controls + **53A assessment objectives/methods** + **53B baselines (LOW/MODERATE/HIGH)** |
| CSF 2.0 | 225 | Cybersecurity Framework (6 functions, 22 categories, 197 subcategories) |
| PF 1.0 | 92 | Privacy Framework (5 functions) |
| SP 800-37 RMF | 7 steps | Risk Management Framework (7-step process) |
| Publications | 613 | Full NIST cybersecurity publications (SP 800, FIPS, IR, CSWP) |
| CSF ↔ 800-53 Mappings | 57 | Framework cross-references |
| Glossary | 39 | Core cybersecurity terms |
| Synonyms | 53 | Security acronym expansions (MFA↔multi-factor authentication, etc.) |
| CMVP | 15 | FIPS 140 validated crypto modules |
| NICE Work Roles | 43 | Cybersecurity Workforce Framework roles |

### OWASP (12)

| Source | Records | Description |
|--------|---------|-------------|
| Projects | 418 | Flagship/Production/Lab/Incubator projects |
| ASVS 5.0 | 345 | Application Security Verification Standard |
| WSTG | 111 | Web Security Testing Guide |
| Top 10 2021 / API Top 10 2023 / LLM Top 10 2025 / MCP Top 10 2025 | 10 each | Web/API/LLM/MCP security risks + CWE mappings |
| Proactive Controls 2024 | 10 | Developer defense controls |
| MASVS | 23 | Mobile Application Security Verification Standard |
| CWE Database | 815+ | Full MITRE CWE + OWASP cross-references |
| Cheat Sheets | 113+ | Security implementation guides (on-demand) |
| CAPEC Attack Patterns | 559 | MITRE CAPEC attack patterns + CWE cross-references |

### Live APIs

| Source | Description |
|--------|-------------|
| NVD CVE API 2.0 | Real-time CVE search |
| CISA KEV | Known Exploited Vulnerabilities catalog |
| FIRST EPSS | Exploit Prediction Scoring System |

## Tools (41)

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
| `search_kev` | CISA KEV — vendor/product/date/ransomware filters |

### Analysis & Assessment

| Tool | Description |
|------|-------------|
| `lookup_compliance` | Reverse lookup: PCI-DSS/ISO 27001 requirement → NIST/ASVS |
| `triage_cve` | CVE triage with EPSS + CVSS + KEV composite scoring |
| `map_finding` | CWE/CVE → complete remediation chain |
| `get_attack_pattern` | CAPEC attack patterns with CWE cross-references |
| `search_owasp` | Search all 22 sources (NIST + OWASP unified) |
| `cross_reference` | CWE → Top 10 / ASVS / WSTG |
| `compliance_map` | ASVS → PCI-DSS 4.0 / ISO 27001:2022 / NIST 800-53 |
| `nist_compliance_map` | SP 800-53 families → PCI-DSS 4.0 / ISO 27001:2022 |
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

## Use Cases

### Vulnerability Management
```
> Triage CVE-2021-44228 and CVE-2023-44487 — show EPSS, CVSS, KEV status

> Show all CISA KEV entries for Microsoft added after 2025-01-01

> Show only KEV vulnerabilities with known ransomware campaign use

> What attack patterns target CWE-502 (deserialization)?

> Map CWE-79 to OWASP Top 10, ASVS requirements, WSTG tests, and remediation guidance
```

### Compliance & Audit
```
> What NIST SP 800-53 controls and ASVS requirements map to PCI-DSS 8.3?

> Map ASVS V4 to PCI-DSS 4.0, ISO 27001, and NIST 800-53

> Map NIST SP 800-53 AC family to PCI-DSS and ISO 27001

> Show SP 800-53 LOW baseline controls for the IA (Identification and Authentication) family

> Show SP 800-53 AC-1 control with 53A assessment objectives
```

### Threat Modeling & Architecture Review
```
> Generate a STRIDE threat model: payment API, JWT auth, PostgreSQL, Redis cache

> Assess my stack: React, Node.js, PostgreSQL, REST API, AWS Lambda

> Find CAPEC attack patterns related to SQL injection

> Search all NIST and OWASP sources for "zero trust"
```

### Development Security
```
> Generate a comprehensive security checklist for a web API project

> Show OWASP Cheat Sheet for Authentication

> Cross-reference CWE-352 (CSRF) to Top 10, ASVS, and WSTG test cases

> Show ASVS V3 (Session Management) level 2 requirements

> Search NVD for critical log4j CVEs
```

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
│  41 tools · 4 prompts · 6 rsrc │
├──────────────┬──────────────────┤
│  SQLite FTS5 │  Live APIs       │
│  (~6.2MB)    │  NVD+KEV+EPSS   │
├──────────────┴──────────────────┤
│  NIST Collectors (10)           │
│  OWASP Collectors (12)          │
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
