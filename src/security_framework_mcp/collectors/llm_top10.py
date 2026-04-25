from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS llm_top10 (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    cwes TEXT,
    url TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS llm_top10_fts USING fts5(
    id, name, description, cwes,
    content='llm_top10', content_rowid='rowid'
);
"""

# OWASP Top 10 for LLM Applications 2025 (v2.0) — https://genai.owasp.org/llm-top-10/
LLM_TOP10_2025 = [
    {
        "id": "LLM01:2025",
        "name": "Prompt Injection",
        "description": (
            "A Prompt Injection Vulnerability occurs when user prompts alter the LLM's behavior or "
            "output in unintended ways. These inputs can affect the model even if imperceptible to "
            "humans. While techniques like RAG and fine-tuning aim to make LLM outputs more relevant, "
            "research shows they do not fully mitigate prompt injection vulnerabilities."
        ),
        "cwes": "CWE-94, CWE-95",
        "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    },
    {
        "id": "LLM02:2025",
        "name": "Sensitive Information Disclosure",
        "description": (
            "Sensitive information can affect both the LLM and its application context. This includes "
            "PII, financial details, health records, confidential business data, security credentials, "
            "and legal documents. LLMs risk exposing sensitive data, proprietary algorithms, or "
            "confidential details through their output, resulting in unauthorized data access and privacy violations."
        ),
        "cwes": "CWE-200, CWE-532",
        "url": "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
    },
    {
        "id": "LLM03:2025",
        "name": "Supply Chain",
        "description": (
            "LLM supply chains are susceptible to various vulnerabilities affecting the integrity of "
            "training data, models, and deployment platforms. Risks extend to third-party pre-trained "
            "models and data that can be manipulated through tampering or poisoning attacks. The rise "
            "of open-access LLMs and new fine-tuning methods introduce new supply-chain risks."
        ),
        "cwes": "CWE-426, CWE-427, CWE-506",
        "url": "https://genai.owasp.org/llmrisk/llm03-supply-chain/",
    },
    {
        "id": "LLM04:2025",
        "name": "Data and Model Poisoning",
        "description": (
            "Data poisoning occurs when pre-training, fine-tuning, or embedding data is manipulated "
            "to introduce vulnerabilities, backdoors, or biases. This can compromise model security, "
            "performance, or ethical behavior. Data poisoning is an integrity attack since tampering "
            "with training data impacts the model's ability to make accurate predictions."
        ),
        "cwes": "CWE-400, CWE-434",
        "url": "https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
    },
    {
        "id": "LLM05:2025",
        "name": "Improper Output Handling",
        "description": (
            "Improper Output Handling refers to insufficient validation, sanitization, and handling "
            "of LLM-generated outputs before they are passed downstream to other components. "
            "Successful exploitation can result in XSS and CSRF in web browsers as well as SSRF, "
            "privilege escalation, or remote code execution on backend systems."
        ),
        "cwes": "CWE-79, CWE-89, CWE-94",
        "url": "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
    },
    {
        "id": "LLM06:2025",
        "name": "Excessive Agency",
        "description": (
            "An LLM-based system is often granted agency — the ability to call functions or interface "
            "with other systems via extensions to undertake actions in response to a prompt. Excessive "
            "Agency enables damaging actions to be performed in response to unexpected or manipulated "
            "LLM outputs, typically caused by excessive functionality, permissions, or autonomy."
        ),
        "cwes": "CWE-269, CWE-276",
        "url": "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
    },
    {
        "id": "LLM07:2025",
        "name": "System Prompt Leakage",
        "description": (
            "The system prompt leakage vulnerability refers to the risk that system prompts or "
            "instructions used to steer the model's behavior can contain sensitive information not "
            "intended to be discovered. System prompts should not be considered secrets, and sensitive "
            "data such as credentials or connection strings should not be contained within them."
        ),
        "cwes": "CWE-200, CWE-532",
        "url": "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
    },
    {
        "id": "LLM08:2025",
        "name": "Vector and Embedding Weaknesses",
        "description": (
            "Weaknesses in how vectors and embeddings are generated, stored, or retrieved can be "
            "exploited to inject harmful content, manipulate model outputs, or access sensitive "
            "information in RAG-based systems. These vulnerabilities present significant security "
            "risks in systems utilizing Retrieval Augmented Generation with LLMs."
        ),
        "cwes": "CWE-200, CWE-400",
        "url": "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
    },
    {
        "id": "LLM09:2025",
        "name": "Misinformation",
        "description": (
            "Misinformation from LLMs poses a core vulnerability for applications relying on these "
            "models. Misinformation occurs when LLMs produce false or misleading information that "
            "appears credible, often caused by hallucination — when the LLM generates content that "
            "seems accurate but is fabricated by filling gaps using statistical patterns."
        ),
        "cwes": "CWE-200, CWE-471",
        "url": "https://genai.owasp.org/llmrisk/llm09-misinformation/",
    },
    {
        "id": "LLM10:2025",
        "name": "Unbounded Consumption",
        "description": (
            "Unbounded Consumption occurs when an LLM application allows users to conduct excessive "
            "and uncontrolled inferences, leading to denial of service, economic losses, model theft, "
            "and service degradation. The high computational demands of LLMs make them particularly "
            "vulnerable to resource exploitation and unauthorized usage."
        ),
        "cwes": "CWE-400, CWE-770",
        "url": "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
    },
]


def scrape_llm_top10(conn: sqlite3.Connection) -> int:
    rows = [
        (item["id"], item["name"], item["description"], item["cwes"], item["url"])
        for item in LLM_TOP10_2025
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO llm_top10 (id, name, description, cwes, url) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d LLM Top 10 items", len(rows))
    return len(rows)
