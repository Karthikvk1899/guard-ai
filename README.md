# ??? guard-ai

> **Automated linter that catches AI-generated vulnerabilities, hallucinated dependencies, and code truncations before they hit production.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![CI Status](https://github.com/your-username/guard-ai/actions/workflows/guard-ai.yml/badge.svg)](https://github.com/your-username/guard-ai/actions)

---

## ?? The Problem: AI Slopsquatting & Code Hallucinations

Large Language Models (LLMs) write great code, but they also introduce distinct security risks:

1. **Slopsquatting (Hallucinated Packages):** LLMs frequently invent non-existent PyPI and NPM dependencies (e.g., `fake_llm_helper_12345`). Attackers register these hallucinated names to execute supply-chain attacks.
2. **Hardcoded Secret Placeholders:** LLMs fill missing keys with patterns like `openai_key = "your_openai_key_here"`, which developers often accidentally commit.
3. **Truncated Code Comments:** AI models often output incomplete snippets containing `# ... rest of code here` or `// ... existing code`, breaking logic in production.

`guard-ai` runs directly in your CLI and CI/CD pipelines to block these issues instantly.

---

## ? Features

- ?? **Multi-Language Support:** Scans Python (`.py`), JavaScript/TypeScript (`.js`, `.ts`, `.jsx`, `.tsx`), and `package.json`.
- ?? **High Performance Caching:** SQLite-backed local registry lookup engine (24-hr TTL) to query PyPI & NPM without hitting rate limits.
- ?? **Zero False-Positives:** Smart filtering for Python standard libraries, Node built-ins, and local module structures.
- ?? **CI/CD Ready:** Custom exit thresholds (`--fail-on HIGH`) and structured `--json` output for automated pipelines.
- ?? **Ignore Rule Engine:** Seamless support for default ignores (`.venv`, `node_modules`), `.gitignore`, and `.guardignore`.

---

## ? Quick Start

### Installation

Install locally using `pip`:

```bash
pip install .

---

## ?? Pre-Commit Hook Integration

Want to catch AI risks *before* you even commit? Add `guard-ai` to your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: [https://github.com/Karthikvk1899/guard-ai](https://github.com/Karthikvk1899/guard-ai)
    rev: v1.0.0
    hooks:
      - id: guard-ai
        args: ["--fail-on", "HIGH"]
