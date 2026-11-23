#!/usr/bin/env python3
import sys
import argparse
import subprocess
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

from engine import review_diff, format_github_markdown
from schemas import FullReviewReport

console = Console()


def get_git_diff() -> str:
    """Fetches diff against main or HEAD~1"""
    try:
        # Try diff against main branch first
        diff = subprocess.check_output(["git", "diff", "main"], text=True)
        if not diff.strip():
            # If empty, check uncommitted changes
            diff = subprocess.check_output(["git", "diff", "HEAD"], text=True)
        return diff
    except Exception as e:
        console.print(f"[bold red]Failed to retrieve git diff:[/bold red] {e}")
        sys.exit(1)


def display_terminal_review(report: FullReviewReport):
    result = report.result
    telemetry = report.telemetry

    verdict_style = {
        "APPROVE": "bold green",
        "COMMENT": "bold cyan",
        "REQUEST_CHANGES": "bold yellow",
        "BLOCK_MERGE": "bold white on red",
    }.get(result.verdict, "bold white")

    # Header Panel
    console.print(
        Panel(
            f"[{verdict_style}] VERDICT: {result.verdict} [/{verdict_style}]  |  "
            f"[bold]Risk Score:[/bold] {result.risk_score}/100\n\n"
            f"[italic]{result.summary}[/italic]",
            title="🛡️ AI Code & Security Gate Review",
            border_style="red" if result.verdict == "BLOCK_MERGE" else "green",
        )
    )

    # Security Table
    if result.security_vulnerabilities:
        table = Table(title="🚨 Detected Security Vulnerabilities", border_style="red")
        table.add_column("Severity", style="bold red")
        table.add_column("CWE", style="yellow")
        table.add_column("Vulnerability", style="white")
        table.add_column("Remediation", style="green")

        for vuln in result.security_vulnerabilities:
            table.add_row(
                vuln.severity.upper(),
                vuln.cwe_identifier or "N/A",
                vuln.title,
                vuln.remediation_advice,
            )
        console.print(table)

    # Inline Comments Table
    if result.inline_comments:
        table = Table(title="📝 Inline Code Comments", border_style="cyan")
        table.add_column("File:Line", style="bold cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Issue", style="white")
        table.add_column("Suggested Fix", style="green")

        for comment in result.inline_comments:
            table.add_row(
                f"{comment.file_path}:{comment.line_number}",
                f"{comment.category} ({comment.severity})",
                comment.comment,
                (comment.suggested_patch[:60] + "...") if comment.suggested_patch else "N/A",
            )
        console.print(table)

    # Telemetry
    console.print(
        f"\n[dim]Audit completed by [bold]{telemetry.model_used}[/bold] in {telemetry.latency_ms:,.0f}ms | "
        f"Tokens: {telemetry.total_tokens} | Cost: ${telemetry.estimated_cost_usd:.6f}[/dim]\n"
    )


def main():
    parser = argparse.ArgumentParser(description="Autonomous AI Pull Request Reviewer & Security Gate")
    parser.add_argument("--file", "-f", type=str, help="Path to a .diff or .patch file")
    parser.add_argument("--git", "-g", action="store_true", help="Analyze local git diff against main/HEAD")
    parser.add_argument("--output-markdown", "-o", type=str, help="Save GitHub PR comment markdown to file")
    parser.add_argument(
        "--fail-on-block",
        action="store_true",
        help="Exit with non-zero status code if verdict is BLOCK_MERGE (for CI pipelines)",
    )

    args = parser.parse_args()

    if args.file:
        diff_path = Path(args.file)
        if not diff_path.exists():
            console.print(f"[bold red]File not found:[/bold red] {args.file}")
            sys.exit(1)
        diff_text = diff_path.read_text()
    elif args.git:
        diff_text = get_git_diff()
    else:
        # Default to vulnerable sample if no args provided
        console.print("[dim]No diff specified. Running against sample_diffs/vulnerable_pr.diff...[/dim]\n")
        diff_text = Path("sample_diffs/vulnerable_pr.diff").read_text()

    if not diff_text.strip():
        console.print("[yellow]Diff is empty. Nothing to review.[/yellow]")
        sys.exit(0)

    console.print("[bold cyan]🔍 Analyzing Pull Request diff with AI Security Gate...[/bold cyan]")
    report = review_diff(diff_text)

    display_terminal_review(report)

    # Save to Markdown if requested
    if args.output_markdown:
        md_content = format_github_markdown(report)
        Path(args.output_markdown).write_text(md_content)
        console.print(f"[green]✓ Saved GitHub PR comment markdown to:[/green] {args.output_markdown}")

    # Enforce CI Gate
    if args.fail_on_block and report.result.verdict == "BLOCK_MERGE":
        console.print("[bold red]❌ CI Security Gate Check Failed! Pull request cannot be merged.[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
