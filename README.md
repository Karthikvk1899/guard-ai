# Guard-AI

[![CI](https://github.com/Karthikvk1899/guard-ai/actions/workflows/guard-ai.yml/badge.svg)](https://github.com/Karthikvk1899/guard-ai/actions/workflows/guard-ai.yml)

A review-oriented Python CLI for finding suspicious secret strings, placeholder comments, Python syntax errors, and optionally unresolved public package names in Python/JavaScript/TypeScript projects.

**These are heuristics, not proof that code is AI-generated, vulnerable, or safe. False positives and false negatives are possible. A registered package can still be malicious.**

## Install from this repository

Python 3.11+ is required. These commands do not depend on an unverified PyPI release or tag:

```bash
git clone https://github.com/Karthikvk1899/guard-ai.git
cd guard-ai
python -m venv .venv
. .venv/bin/activate
python -m pip install .
guard-ai scan /path/to/project --fail-on HIGH
```

The package metadata name is `guard-ai`; the executable is `guard-ai`. No claim is made that this revision is published to PyPI.

```bash
# Machine-readable findings; never includes matched secret/source lines.
guard-ai scan /path/to/project --json --fail-on HIGH

# Explicit opt-in: submits package names to public PyPI/npm registries.
guard-ai scan /path/to/project --check-registry --fail-on HIGH
```

Without `--check-registry`, scanning makes no registry requests. With it, only HTTP 200/404 answers are cached for 24 hours. Rate limits, timeouts, redirects, and server errors become HIGH-severity “Registry Unavailable” findings; they are not cached as safe or misreported as missing packages. Unknown results are memoized only for the current scan to avoid repeated failing requests. Registry responses are streamed without buffering package metadata.

## Checks and limitations

| Check | Behavior | Limit |
| --- | --- | --- |
| Secret/placeholder patterns | Flags selected suspicious strings; source text redacted from reports | Not a comprehensive secrets scanner; examples and comments can trigger findings |
| Truncation markers | Flags selected placeholder comments | Intent cannot be inferred from a comment |
| Python imports | AST parsing; skips stdlib, relative and root/src-local imports | Distribution names can differ; installed metadata helps but private/namespace imports still need review |
| JS/TS imports | Regex matches common `import … from` and `require` forms | Not a JS parser; multiline imports, aliases, comments and uncommon syntax are incomplete |
| package.json | Parses dependency sections; skips explicit local/workspace/git/HTTP sources; handles npm aliases | Does not validate package versions, provenance, integrity, or private registries |
| File traversal | Root `.gitignore` and `.guardignore` rules, default directory exclusions, no symlink traversal, 1 MiB file limit | Nested ignore files are not loaded; excluded files are outside scan coverage |

Exit codes: **0** means no findings at or above the selected threshold; **1** means blocking findings; **2** means invalid CLI usage. Thresholds: LOW, MEDIUM, HIGH, CRITICAL. Unreadable/oversized source is reported rather than silently treated as clean. Explicit symlink targets are rejected.

Version 0.2 removes automatic `--fix` rewriting. A registry lookup cannot justify deleting an import, and a regex replacement cannot safely rewrite an arbitrary assignment. Review and repair source manually. Cache v2 uses a separate database because older releases cached some network failures as successful lookups.

## Pre-commit

Use a local hook after installing the CLI in the development environment. This avoids referencing a release tag that has not been verified:

```yaml
repos:
  - repo: local
    hooks:
      - id: guard-ai
        name: Guard-AI heuristic scan
        entry: guard-ai scan . --fail-on HIGH
        language: system
        pass_filenames: false
        types: [text]
```

Reports are read-only; `--fix` is rejected. Do not enable public registry lookups on confidential package names without permission.

## Development and verification

```bash
python -m pip install -e '.[test]'
ruff check src tests
ruff format --check src tests
pytest -q
python -m build
```

Tests use mocked registry responses and temporary SQLite databases; they cover 200/404/error classification, timeout handling, cache expiry, import-name mappings, redacted output, malformed files, ignore rules, CLI thresholds, and source preservation. CI also audits installed dependencies, scans with CodeQL, builds wheels/sdist, and smoke-tests the installed wheel. CI does not establish detection accuracy against a representative corpus or absence of vulnerabilities.

MIT licensed. See [security reporting and threat model](SECURITY.md).
