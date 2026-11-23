from typing import Literal, Optional, List
from pydantic import BaseModel, Field

SeverityLevel = Literal["low", "medium", "high", "critical"]
ReviewVerdict = Literal["APPROVE", "COMMENT", "REQUEST_CHANGES", "BLOCK_MERGE"]
IssueCategory = Literal["security", "breaking_change", "performance", "correctness", "code_quality"]


class SecurityVulnerability(BaseModel):
    cwe_identifier: Optional[str] = Field(
        default=None, description="Common Weakness Enumeration ID, e.g. CWE-89 (SQL Injection) or CWE-798 (Hardcoded Credentials)"
    )
    title: str = Field(description="Short title of the vulnerability")
    description: str = Field(description="Detailed explanation of the security risk")
    severity: SeverityLevel = Field(description="Severity impact of the security issue")
    remediation_advice: str = Field(description="Specific actionable instructions on how to patch it")


class InlineComment(BaseModel):
    file_path: str = Field(description="Path of the file being reviewed, matching diff header")
    line_number: int = Field(description="Approximate target line number in the new/modified file")
    category: IssueCategory = Field(description="Type of issue")
    severity: SeverityLevel = Field(description="Severity of this specific issue")
    title: str = Field(description="Short header for the inline comment")
    comment: str = Field(description="Constructive, specific explanation of the problem and why it matters")
    suggested_patch: Optional[str] = Field(
        default=None, description="Drop-in replacement code snippet in unified diff or replacement format"
    )


class ReviewResult(BaseModel):
    summary: str = Field(description="High-level 2-3 sentence executive summary of the changes and overall quality")
    verdict: ReviewVerdict = Field(
        description="Final merge verdict. Use BLOCK_MERGE for critical security issues or credential leaks."
    )
    risk_score: int = Field(
        ge=0, le=100, description="Risk rating from 0 (completely safe) to 100 (catastrophic security/outage risk)"
    )
    breaking_changes: List[str] = Field(
        default_factory=list, description="List of any breaking API, schema, or configuration changes detected"
    )
    security_vulnerabilities: List[SecurityVulnerability] = Field(
        default_factory=list, description="Detected security flaws or secrets leakage"
    )
    inline_comments: List[InlineComment] = Field(
        default_factory=list, description="Targeted inline comments for specific lines in the diff"
    )


class ReviewTelemetry(BaseModel):
    model_used: str
    latency_ms: float
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    estimated_cost_usd: float


class FullReviewReport(BaseModel):
    result: ReviewResult
    telemetry: ReviewTelemetry
