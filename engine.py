import os
import time
from typing import List
from dotenv import load_dotenv
from google import genai
from google.genai import types

from schemas import ReviewResult, ReviewTelemetry, FullReviewReport

load_dotenv()

MODEL_CASCADE: List[str] = [
    "gemini-3.8-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
]

INPUT_COST_PER_MILLION = 0.10
OUTPUT_COST_PER_MILLION = 0.40


def calculate_cost(prompt_tokens: int, completion_tokens: int) -> float:
    input_cost = (prompt_tokens / 1_000_000) * INPUT_COST_PER_MILLION
    output_cost = (completion_tokens / 1_000_000) * OUTPUT_COST_PER_MILLION
    return round(input_cost + output_cost, 7)


SYSTEM_INSTRUCTION = """
You are a Principal Security Engineer and Staff Software Architect conducting an automated code review on a Pull Request git diff.

Your review criteria:
1. SECURITY FIRST:
   - Immediately flag hardcoded secrets, API tokens, passwords, or private keys. (CWE-798)
   - Detect injection vectors (SQL injection, command injection, XSS, SSRF, path traversal). (CWE-89, CWE-78)
   - Flag insecure deserialization or unvalidated user inputs.
   - If any high/critical security flaw or credential is detected, the verdict MUST be 'BLOCK_MERGE'.

2. BREAKING CHANGES:
   - Identify modifications to public API contracts, database schemas without migrations, or removed functions.

3. PERFORMANCE & RELIABILITY:
   - Spot N+1 query patterns, unindexed lookups, unclosed network/DB connections, or unhandled exceptions.

4. ACTIONABLE INLINE FEEDBACK:
   - For every flagged issue, provide the exact file path, estimated line number, and a clean, production-ready replacement patch.
"""


def review_diff(diff_text: str) -> FullReviewReport:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable not configured.")

    client = genai.Client(api_key=api_key)
    start_time = time.perf_counter()

    prompt = f"Please review the following git diff according to your security and architectural standards:\n\n```diff\n{diff_text}\n```"

    response = None
    successful_model = None
    last_error = None

    for model_name in MODEL_CASCADE:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_INSTRUCTION,
                    response_mime_type="application/json",
                    response_schema=ReviewResult,
                    temperature=0.1,  # Low temperature for strict evaluation
                ),
            )
            successful_model = model_name
            break
        except Exception as e:
            last_error = e
            continue

    if not response or not response.text:
        raise RuntimeError(f"All review models in cascade failed. Last error: {last_error}")

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    usage = getattr(response, "usage_metadata", None)
    prompt_tokens = getattr(usage, "prompt_token_count", 0) if usage else 0
    completion_tokens = getattr(usage, "candidates_token_count", 0) if usage else 0
    total_tokens = getattr(usage, "total_token_count", 0) if usage else (prompt_tokens + completion_tokens)
    cost_usd = calculate_cost(prompt_tokens, completion_tokens)

    telemetry = ReviewTelemetry(
        model_used=successful_model,
        latency_ms=elapsed_ms,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=cost_usd,
    )

    result = ReviewResult.model_validate_json(response.text)
    return FullReviewReport(result=result, telemetry=telemetry)


def format_github_markdown(report: FullReviewReport) -> str:
    """
    Renders the review as GitHub-flavored Markdown ready to be posted directly
    to a GitHub Pull Request comment via GitHub Actions.
    """
    result = report.result
    telemetry = report.telemetry

    verdict_badge = {
        "APPROVE": "🟢 **APPROVED**",
        "COMMENT": "💬 **COMMENT**",
        "REQUEST_CHANGES": "🟡 **REQUEST CHANGES**",
        "BLOCK_MERGE": "🔴 **BLOCK MERGE (Security / Breaking Flaw Detected)**",
    }.get(result.verdict, result.verdict)

    lines: List[str] = [
        "## 🤖 AI Security & Architecture Gate Review",
        "",
        f"**Verdict:** {verdict_badge}  ",
        f"**Risk Score:** `{result.risk_score} / 100`  ",
        "",
        "### 📋 Summary",
        result.summary,
        "",
    ]

    # Security Flaws Section
    if result.security_vulnerabilities:
        lines.append("### 🚨 Security Vulnerabilities")
        for vuln in result.security_vulnerabilities:
            cwe = f" ({vuln.cwe_identifier})" if vuln.cwe_identifier else ""
            lines.append(f"> [!CAUTION]")
            lines.append(f"> **{vuln.title}{cwe} - Severity: {vuln.severity.upper()}**")
            lines.append(f"> {vuln.description}")
            lines.append(f"> ")
            lines.append(f"> **Remediation:** {vuln.remediation_advice}")
            lines.append("")

    # Breaking Changes Section
    if result.breaking_changes:
        lines.append("### ⚠️ Breaking Changes Detected")
        for bc in result.breaking_changes:
            lines.append(f"- ⚠️ {bc}")
        lines.append("")

    # Inline Comments Section
    if result.inline_comments:
        lines.append("### 📝 Inline Feedback & Suggested Patches")
        for comment in result.inline_comments:
            lines.append(f"#### `{comment.file_path}` : Line {comment.line_number}")
            lines.append(f"**[{comment.category.upper()} - {comment.severity.upper()}] {comment.title}**")
            lines.append(comment.comment)
            if comment.suggested_patch:
                lines.append("<details><summary>Suggested Replacement Patch</summary>")
                lines.append("")
                lines.append("```python")
                lines.append(comment.suggested_patch.strip())
                lines.append("```")
                lines.append("</details>")
            lines.append("")

    # Telemetry Footer
    lines.append("---")
    lines.append(
        f"*Audited with `{telemetry.model_used}` in `{telemetry.latency_ms:,.0f}ms` | "
        f"Tokens: `{telemetry.total_tokens}` | Cost: `${telemetry.estimated_cost_usd:.6f}`*"
    )

    return "\n".join(lines)
