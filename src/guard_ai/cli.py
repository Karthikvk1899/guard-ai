import fnmatch
import json
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from guard_ai.scanner import Scanner

app = typer.Typer(
    name="guard-ai",
    help="Shield your codebase from AI-generated security risks and hallucinated packages.",
    add_completion=False,
)
console = Console()

DEFAULT_IGNORES = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    "dist", "build", "*.egg-info", ".mypy_cache", ".pytest_cache"
}

SEVERITY_WEIGHTS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

def load_ignore_patterns(target_path: Path) -> List[str]:
    patterns = list(DEFAULT_IGNORES)
    root_dir = target_path if target_path.is_dir() else target_path.parent
    
    for ignore_filename in [".gitignore", ".guardignore"]:
        ignore_file = root_dir / ignore_filename
        if ignore_file.is_file():
            try:
                lines = ignore_file.read_text(encoding="utf-8").splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line.rstrip("/"))
            except Exception:
                pass
                
    return patterns

def is_ignored(path: Path, root_path: Path, patterns: List[str]) -> bool:
    try:
        rel_path = path.relative_to(root_path).as_posix()
    except ValueError:
        rel_path = path.as_posix()

    parts = rel_path.split("/")

    for pattern in patterns:
        clean_pat = pattern.strip("/")
        if any(fnmatch.fnmatch(part, clean_pat) for part in parts):
            return True
        if fnmatch.fnmatch(rel_path, clean_pat) or fnmatch.fnmatch(rel_path, f"{clean_pat}/*"):
            return True
            
    return False

def collect_files(target_path: Path, patterns: List[str]) -> List[Path]:
    valid_extensions = {".py", ".js", ".ts", ".jsx", ".tsx"}
    valid_filenames = {"package.json"}
    
    if target_path.is_file():
        return [target_path]

    files_to_scan = []
    for path in target_path.rglob("*"):
        if not path.is_file():
            continue
        if is_ignored(path, target_path, patterns):
            continue
        if path.suffix in valid_extensions or path.name in valid_filenames:
            files_to_scan.append(path)

    return files_to_scan

def run_scan(path_str: str, json_output: bool = False, fail_on: str = "MEDIUM", fix: bool = False):
    target_path = Path(path_str).resolve()
    if not target_path.exists():
        if json_output:
            print(json.dumps({"error": f"Path '{path_str}' does not exist."}))
        else:
            console.print(f"[bold red]Error:[/bold red] Path '{path_str}' does not exist.")
        raise typer.Exit(code=1)

    if not json_output:
        console.print(f"\n?? [bold blue]Running guard-ai scan on:[/bold blue] {target_path}\n")

    ignore_patterns = load_ignore_patterns(target_path)
    files_to_scan = collect_files(target_path, ignore_patterns)

    if not files_to_scan:
        if json_output:
            print(json.dumps([]))
        else:
            console.print("[green]No matching source files found to scan.[/green]")
        raise typer.Exit(code=0)

    scanner = Scanner(project_root=target_path if target_path.is_dir() else target_path.parent)

    if fix:
        total_fixes = 0
        for file_path in files_to_scan:
            total_fixes += scanner.fix_file(file_path)
        console.print(f"??? [bold green]Applied {total_fixes} automatic fix(es) across codebase![/bold green]\n")

    all_issues = []
    for file_path in files_to_scan:
        issues = scanner.scan_file(file_path)
        all_issues.extend(issues)

    if json_output:
        results = [
            {
                "file": issue.file_path,
                "line": issue.line_num,
                "category": issue.category,
                "severity": issue.severity,
                "description": issue.description,
            }
            for issue in all_issues
        ]
        print(json.dumps(results, indent=2))
    else:
        if not all_issues:
            console.print("? [bold green]No AI-generated risks detected! Codebase looks clean.[/bold green]\n")
            return

        table = Table(title=f"?? Found {len(all_issues)} issue(s):", show_lines=True)
        table.add_column("Severity", style="bold")
        table.add_column("Category", style="cyan")
        table.add_column("Location", style="yellow")
        table.add_column("Description")

        severity_styles = {
            "CRITICAL": "red",
            "HIGH": "bright_red",
            "MEDIUM": "orange3",
            "LOW": "blue",
        }

        for issue in all_issues:
            color = severity_styles.get(issue.severity, "white")
            table.add_row(
                f"[{color}]{issue.severity}[/{color}]",
                issue.category,
                f"{Path(issue.file_path).name}:{issue.line_num}",
                issue.description
            )

        console.print(table)
        console.print()

    threshold = SEVERITY_WEIGHTS.get(fail_on.upper(), 0)
    has_blocking_issue = any(SEVERITY_WEIGHTS.get(i.severity, 0) >= threshold for i in all_issues)

    if has_blocking_issue:
        raise typer.Exit(code=1)

@app.command(name="scan")
def scan_cmd(
    path: str = typer.Argument(".", help="File or directory path to scan"),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format"),
    fail_on: str = typer.Option("MEDIUM", "--fail-on", help="Severity threshold to trigger exit code 1"),
    fix: bool = typer.Option(False, "--fix", help="Automatically remediate secrets and hallucinated packages"),
):
    run_scan(path, json_output=json_output, fail_on=fail_on, fix=fix)

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format"),
    fail_on: str = typer.Option("MEDIUM", "--fail-on", help="Severity threshold to trigger exit code 1"),
    fix: bool = typer.Option(False, "--fix", help="Automatically remediate secrets and hallucinated packages"),
):
    if ctx.invoked_subcommand is None:
        run_scan(".", json_output=json_output, fail_on=fail_on, fix=fix)

if __name__ == "__main__":
    app()
