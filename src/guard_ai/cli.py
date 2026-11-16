import json
import os
from pathlib import Path

import pathspec
import typer
from rich.console import Console
from rich.table import Table

from guard_ai.scanner import Scanner

app = typer.Typer(help="Heuristic source checks; findings require review.", add_completion=False)
console = Console()
SEVERITY_WEIGHTS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
DEFAULT_IGNORES = [
    ".git/",
    ".venv/",
    "venv/",
    "node_modules/",
    "__pycache__/",
    "dist/",
    "build/",
    "*.egg-info/",
    ".mypy_cache/",
    ".pytest_cache/",
]


def collect_files(root: Path):
    if root.is_file() or root.is_symlink():
        return [root]
    patterns = list(DEFAULT_IGNORES)
    for filename in [".gitignore", ".guardignore"]:
        path = root / filename
        if path.is_file():
            patterns.extend(path.read_text(encoding="utf-8").splitlines())
    spec = pathspec.GitIgnoreSpec.from_lines(patterns)
    files = []
    for directory, dirs, names in os.walk(root, followlinks=False):
        here = Path(directory)
        dirs[:] = [
            name
            for name in sorted(dirs)
            if not (here / name).is_symlink()
            and not spec.match_file((here / name).relative_to(root).as_posix() + "/")
        ]
        for name in sorted(names):
            path = here / name
            if path.is_symlink() or spec.match_file(path.relative_to(root).as_posix()):
                continue
            if path.suffix in {".py", ".js", ".ts", ".jsx", ".tsx"} or name == "package.json":
                files.append(path)
    return files


def run_scan(path_str: str, json_output=False, fail_on="MEDIUM", fix=False, check_registry=False):
    if fail_on.upper() not in SEVERITY_WEIGHTS:
        raise typer.BadParameter("Choose LOW, MEDIUM, HIGH, or CRITICAL", param_hint="--fail-on")
    if fix:
        raise typer.BadParameter(
            "--fix was removed because heuristic rewriting can corrupt working code"
        )
    target = Path(path_str).absolute()
    if not target.exists():
        raise typer.BadParameter("Scan target does not exist")
    if target.is_symlink():
        raise typer.BadParameter("Scan target must not be a symlink")
    scanner = Scanner(
        project_root=target if target.is_dir() else target.parent, check_registry=check_registry
    )
    try:
        issues = [issue for path in collect_files(target) for issue in scanner.scan_file(path)]
    finally:
        scanner.close()
    if json_output:
        print(
            json.dumps(
                [
                    {
                        "file": i.file_path,
                        "line": i.line_num,
                        "category": i.category,
                        "severity": i.severity,
                        "description": i.description,
                    }
                    for i in issues
                ],
                indent=2,
            )
        )
    else:
        console.print(
            "Registry checks enabled; package names are sent to public registries."
            if check_registry
            else "Registry checks disabled. Use --check-registry to opt in."
        )
        table = Table("Severity", "Category", "Location", "Description")
        for issue in issues:
            # Disable rich markup for untrusted file names and package names.
            from rich.text import Text

            table.add_row(
                Text(issue.severity),
                Text(issue.category),
                Text(f"{issue.file_path}:{issue.line_num}"),
                Text(issue.description),
            )
        if issues:
            console.print(table)
        else:
            console.print(
                "No findings from the enabled checks. This is not a security certification."
            )
    if any(SEVERITY_WEIGHTS[i.severity] >= SEVERITY_WEIGHTS[fail_on.upper()] for i in issues):
        raise typer.Exit(1)


@app.command("scan")
def scan(
    path: str = typer.Argument("."),
    json_output: bool = typer.Option(False, "--json"),
    fail_on: str = typer.Option("MEDIUM", "--fail-on"),
    check_registry: bool = typer.Option(False, "--check-registry"),
    fix: bool = typer.Option(False, "--fix", hidden=True),
):
    run_scan(path, json_output, fail_on, fix, check_registry)


@app.callback()
def main():
    """Scan source without rewriting it. Registry availability is not package safety."""


if __name__ == "__main__":
    app()
