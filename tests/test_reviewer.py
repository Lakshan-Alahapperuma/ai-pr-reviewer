from schemas import ReviewResult, SecurityVulnerability, InlineComment, ReviewTelemetry, FullReviewReport
from engine import format_github_markdown


def test_schema_serialization():
    report = FullReviewReport(
        result=ReviewResult(
            summary="Identified severe hardcoded secrets and SQL injection vulnerabilities.",
            verdict="BLOCK_MERGE",
            risk_score=95,
            security_vulnerabilities=[
                SecurityVulnerability(
                    cwe_identifier="CWE-798",
                    title="Hardcoded AWS Secret",
                    description="AWS master credentials checked into source code.",
                    severity="critical",
                    remediation_advice="Revoke credentials immediately and store in secret manager.",
                )
            ],
            inline_comments=[
                InlineComment(
                    file_path="services/auth_service.py",
                    line_number=5,
                    category="security",
                    severity="critical",
                    title="Remove leaked secret",
                    comment="Hardcoded access key found.",
                    suggested_patch='AWS_KEY = os.environ.get("AWS_KEY")',
                )
            ],
        ),
        telemetry=ReviewTelemetry(
            model_used="gemini-3.5-flash",
            latency_ms=850.0,
            prompt_tokens=400,
            completion_tokens=250,
            total_tokens=650,
            estimated_cost_usd=0.00014,
        ),
    )

    markdown = format_github_markdown(report)
    assert "BLOCK MERGE" in markdown
    assert "CWE-798" in markdown
    assert "Hardcoded AWS Secret" in markdown
    assert "services/auth_service.py" in markdown
