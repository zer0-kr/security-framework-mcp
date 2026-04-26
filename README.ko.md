<p align="center">
  <h1 align="center">security-framework-mcp</h1>
  <p align="center">
    <strong>NIST + OWASP 통합 보안 프레임워크 MCP 서버</strong>
  </p>
  <p align="center">
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
    <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-green.svg" alt="MCP Compatible"></a>
    <a href="https://nist.gov"><img src="https://img.shields.io/badge/NIST-data%20source-orange.svg" alt="NIST"></a>
    <a href="https://owasp.org"><img src="https://img.shields.io/badge/OWASP-data%20source-orange.svg" alt="OWASP"></a>
  </p>
  <p align="center">
    <a href="./README.md">English</a>
  </p>
</p>

---

**4,700+개 보안 데이터**를 단일 MCP 인터페이스로 검색 — **NIST** (SP 800-53 1,196개 컨트롤 + 53A 평가 + 53B 기준선, CSF 2.0, PF 1.0, SP 800-37 RMF, 613개 출판물, CSF↔800-53 매핑, CMVP, NICE, 용어사전, 동의어)와 **OWASP** (Top 10, API/LLM/MCP Top 10, ASVS 5.0, WSTG, MASVS, Proactive Controls, 815+ CWE, 559 CAPEC 공격 패턴, 113+ Cheat Sheets, 418+ 프로젝트) — **실시간 NVD/CVE + CISA KEV + EPSS**, PDF 읽기, 컴플라이언스 매핑, STRIDE 위협 모델링, MCP 보안 평가 포함.

## 빠른 시작

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
<summary>기타 MCP 클라이언트 (Cursor, OpenCode)</summary>

```json
{ "security": { "command": "security-framework-mcp" } }
```

</details>

첫 실행 시 로컬 데이터베이스가 자동으로 생성됩니다 (~15-20초). 이후 주 1회 자동 갱신.

## 데이터 소스 (22개 로컬 + 3개 실시간)

### NIST (10개)

| 소스 | 레코드 | 설명 |
|------|--------|------|
| **SP 800-53 Rev. 5** | 1,196 | 보안/프라이버시 컨트롤 + **53A 평가 목표/방법** + **53B 기준선(LOW/MODERATE/HIGH)** |
| **CSF 2.0** | 225 | 사이버보안 프레임워크 (6개 기능, 22개 카테고리, 197개 서브카테고리) |
| **PF 1.0** | 92 | 프라이버시 프레임워크 (5개 기능) |
| **SP 800-37 RMF** | 7 | 위험 관리 프레임워크 (7단계 프로세스) |
| **출판물** | 613 | NIST 사이버보안 전체 출판물 (SP 800, FIPS, IR, CSWP) |
| **CSF ↔ 800-53 매핑** | 57 | 프레임워크 교차 참조 |
| **용어사전** | 39 | 사이버보안 핵심 용어 |
| **동의어** | 53 | 보안 약어 확장 (MFA↔multi-factor authentication 등) |
| **CMVP** | 15 | FIPS 140 인증 암호 모듈 |
| **NICE** | 43 | 사이버보안 인력 프레임워크 직무 역할 |

### OWASP (12개)

| 소스 | 레코드 | 설명 |
|------|--------|------|
| **프로젝트** | 418 | Flagship/Production/Lab/Incubator 전체 |
| **ASVS 5.0** | 345 | 애플리케이션 보안 검증 표준 |
| **WSTG** | 111 | 웹 보안 테스트 가이드 |
| **Top 10 2021** | 10 | 웹 10대 보안 위험 + CWE 매핑 |
| **API Top 10 2023** | 10 | API 보안 위험 |
| **LLM Top 10 2025** | 10 | AI/LLM 보안 위험 |
| **MCP Top 10 2025** | 10 | MCP 서버 보안 위험 |
| **Proactive Controls 2024** | 10 | 개발자 방어 통제 |
| **MASVS** | 23 | 모바일 앱 보안 검증 표준 |
| **CWE 데이터베이스** | 815+ | MITRE CWE 전체 + OWASP 교차 참조 |
| **Cheat Sheets** | 113+ | 보안 구현 가이드 (온디맨드) |
| **CAPEC 공격 패턴** | 559 | MITRE CAPEC 공격 패턴 + CWE 교차 참조 |

### 실시간 API

| 소스 | 설명 |
|------|------|
| NVD CVE API 2.0 | 실시간 CVE 검색 |
| CISA KEV | 실제 악용된 취약점 카탈로그 |
| FIRST EPSS | 익스플로잇 예측 스코어링 시스템 |

## 도구 (41개)

### NIST 도구

| 도구 | 설명 |
|------|------|
| `search_nist` | 10개 NIST 소스 통합 검색 |
| `get_nist_control` | SP 800-53 컨트롤 조회 — 문장, 가이드, **53A 평가**, **53B 기준선** 필터 (LOW/MODERATE/HIGH), 패밀리 필터 |
| `get_nist_csf` | CSF 2.0 기능/카테고리/서브카테고리 |
| `get_nist_pf` | PF 1.0 |
| `get_nist_rmf` | SP 800-37 RMF 단계별 태스크 |
| `get_nist_publication` | 613개 출판물 검색/조회 |
| `read_publication` | NIST 출판물 PDF 다운로드 + Markdown 변환 |
| `get_nist_mapping` | CSF 2.0 ↔ SP 800-53 프레임워크 교차 매핑 |
| `get_nist_glossary` | 사이버보안 용어 정의 |
| `get_nist_cmvp` | FIPS 140 인증 모듈 |
| `get_nice_roles` | NICE 직무 역할 |

### OWASP 도구

| 도구 | 설명 |
|------|------|
| `list_projects` | 418+ 프로젝트 목록 (레벨/타입 필터) |
| `search_projects` | 프로젝트 전문 검색 |
| `get_project` | 프로젝트 상세 정보 |
| `get_asvs` | ASVS 5.0 요구사항 (챕터/레벨/검색 필터) |
| `get_wstg` | WSTG 테스트 케이스 (카테고리/검색 필터) |
| `get_top10` | Top 10 2021 + CWE 매핑 |
| `get_api_top10` | API Security Top 10 2023 |
| `get_llm_top10` | LLM Top 10 2025 |
| `get_mcp_top10` | MCP Top 10 2025 |
| `get_proactive_controls` | Proactive Controls 2024 |
| `get_masvs` | MASVS 모바일 보안 통제 |
| `get_cheatsheet` | 113+ Cheat Sheets |

### 취약점 & CWE

| 도구 | 설명 |
|------|------|
| `get_cwe` | CWE 조회 + OWASP 자동 교차 참조 |
| `search_kev` | CISA KEV — 벤더/제품/날짜/랜섬웨어 필터 |
| `search_cve` | 실시간 NVD CVE 검색 |
| `get_cve_detail` | CVE 상세 정보 (CVSS, 약점, 참조) |

### 분석 & 평가

| 도구 | 설명 |
|------|------|
| `lookup_compliance` | 역방향 조회: PCI-DSS/ISO 27001 요구사항 → NIST/ASVS |
| `triage_cve` | CVE 분류: EPSS + CVSS + KEV 복합 스코어링 |
| `map_finding` | CWE/CVE → 전체 개선 체인 |
| `get_attack_pattern` | CAPEC 공격 패턴 + CWE 교차 참조 |
| `search_owasp` | 22개 소스 통합 검색 (OWASP + NIST) |
| `cross_reference` | CWE → Top 10 / ASVS / WSTG 교차 참조 |
| `compliance_map` | ASVS → PCI-DSS 4.0 / ISO 27001:2022 / NIST 800-53 매핑 |
| `nist_compliance_map` | SP 800-53 패밀리 → PCI-DSS 4.0 / ISO 27001:2022 매핑 |
| `assess_stack` | 기술 스택 보안 진단 |
| `generate_checklist` | 보안 체크리스트 생성 (프로젝트 타입 × 깊이) |
| `assess_mcp_security` | MCP 서버 보안 평가 (MCP Top 10 기준) |
| `threat_model` | STRIDE 위협 모델링 |
| `update_database` | 인덱스 재빌드 |
| `database_status` | DB 상태 확인 |

## 프롬프트 템플릿 (4개)

| 프롬프트 | 설명 |
|---------|------|
| `security_review` | OWASP + NIST 기반 보안 리뷰 워크플로우 |
| `threat_analysis` | 위협 분석 — CWE 매핑, 컨트롤 추천 |
| `compliance_check` | 컴플라이언스 평가 — ASVS + 테스트 절차 |
| `secure_code_review` | 코드 보안 리뷰 — CWE ID + 안전한 대안 |

## 사용 예시

### 취약점 관리
```
> CVE-2021-44228, CVE-2023-44487 트리아지해줘 — EPSS, CVSS, KEV 상태 보여줘

> 2025년 이후 추가된 Microsoft CISA KEV 목록 보여줘

> 랜섬웨어 캠페인에 사용된 KEV만 보여줘

> CWE-502(역직렬화)를 노리는 공격 패턴은?

> CWE-79를 Top 10 매핑, ASVS 요구사항, WSTG 테스트, 대응 가이드까지 한번에 보여줘
```

### 컴플라이언스 & 감사
```
> PCI-DSS 8.3 요구사항에 매핑되는 NIST 컨트롤과 ASVS 항목 찾아줘

> ASVS V4를 PCI-DSS 4.0, ISO 27001, NIST 800-53에 매핑해줘

> NIST SP 800-53 AC 패밀리를 PCI-DSS, ISO 27001에 매핑해줘

> SP 800-53 LOW 기준선에서 IA(식별 및 인증) 패밀리 컨트롤 목록

> SP 800-53 AC-1 컨트롤을 53A 평가 목표와 함께 보여줘
```

### 위협 모델링 & 아키텍처 리뷰
```
> STRIDE 위협 모델을 생성해줘: 결제 API, JWT 인증, PostgreSQL, Redis 캐시

> 내 스택(React, Node.js, PostgreSQL, REST API, AWS Lambda)의 보안을 진단해줘

> SQL 인젝션 관련 CAPEC 공격 패턴을 찾아줘

> OWASP와 NIST 전체에서 "제로 트러스트"를 검색해줘
```

### 개발 보안
```
> 웹 API 프로젝트용 포괄적 보안 체크리스트를 생성해줘

> OWASP Authentication Cheat Sheet 보여줘

> CWE-352(CSRF)를 Top 10, ASVS, WSTG 테스트 케이스와 교차 참조해줘

> ASVS V3(세션 관리) 레벨 2 요구사항 보여줘

> NVD에서 critical log4j CVE를 검색해줘
```

## 설정

| 환경변수 | 기본값 | 설명 |
|---------|--------|------|
| `SECURITY_MCP_DATA_DIR` | `~/.security-framework-mcp` | 로컬 DB 디렉토리 |
| `SECURITY_MCP_UPDATE_INTERVAL` | `604800` (7일) | 자동 갱신 주기 (초) |
| `NVD_API_KEY` | _(없음)_ | NVD API 키 (선택, 속도 향상) |

## 아키텍처

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

## 개발

```bash
git clone https://github.com/zer0-kr/security-framework-mcp.git
cd security-framework-mcp
pip install -e ".[dev]"
python -m pytest tests/test_unit_db.py tests/test_unit_collectors.py -v
python tests/test_comprehensive.py
```

## 기여

1. Fork → 2. 브랜치 생성 → 3. 테스트 실행 → 4. PR 생성

## 라이선스

[MIT](LICENSE)

---

이 프로젝트는 OWASP 재단 또는 NIST와 공식적으로 제휴하거나 보증받지 않았습니다.
