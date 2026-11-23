# Autonomous AI Pull Request Reviewer & Security Gate

An automated, staff-level security and architecture gate that analyzes Git diffs in Pull Requests. Built with **Google GenAI**, **Pydantic**, and **Rich**, it detects credential leakage, injection vulnerabilities, breaking changes, and generates structured inline code reviews.

---

## 🎯 What This System Does

* **CWE Vulnerability Detection**: Automatically identifies CWE-798 (Hardcoded Secrets), CWE-89 (SQL Injection), CWE-78 (Command Injection), and SSRF.
* **Automated CI Merge Blocking**: If a high/critical security risk is found, the tool exits with `BLOCK_MERGE` and fails the CI pipeline.
* **Line-Accurate Inline Fixes**: Suggests replacement patch snippets for offending lines.
* **Multi-Model Fallback Cascade**: Primary review on `gemini-3.8-flash` with automatic fallback to `gemini-3.5-flash` during traffic spikes.
* **Turnkey GitHub Actions Integration**: Ready-to-use workflow file (`.github/workflows/ai-code-review.yml`) that posts reviews straight to GitHub PR comments.

---

## 🚀 Usage

### 1. Review a Sample Vulnerable PR
```bash
./.venv/bin/python cli.py --file sample_diffs/vulnerable_pr.diff
```

### 2. Review a Clean, Well-Architected PR
```bash
./.venv/bin/python cli.py --file sample_diffs/clean_pr.diff
```

### 3. Review Local Git Changes
```bash
./.venv/bin/python cli.py --git
```

### 4. Enforce CI Gate (Fail on Critical Security Risks)
```bash
./.venv/bin/python cli.py --file pr.diff --fail-on-block --output-markdown pr_comment.md
```

---

## 🧪 Testing
```bash
PYTHONPATH=. ./.venv/bin/pytest
```
