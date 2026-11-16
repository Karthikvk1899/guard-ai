import json
import sqlite3
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from guard_ai.cache import PackageCache
from guard_ai.cli import app, collect_files
from guard_ai.scanner import Scanner


@pytest.fixture
def scanner(tmp_path):
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    item = Scanner(
        tmp_path, client=client, cache=PackageCache(tmp_path / "cache.db"), check_registry=True
    )
    yield item
    item.close()


@pytest.mark.parametrize(
    "status,expected",
    [(200, True), (404, False), (429, None), (500, None), (403, None), (302, None)],
)
def test_only_authoritative_registry_results_are_cached(tmp_path, status, expected):
    cache = PackageCache(tmp_path / "cache.db")
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(status))
    ) as client:
        scanner = Scanner(tmp_path, client=client, cache=cache, check_registry=True)
        assert scanner.is_package_real("pypi", "synthetic-package") is expected
        assert cache.get("pypi", "synthetic-package") is expected


def test_timeout_is_unknown_and_not_cached_as_safe(tmp_path):
    def timeout(request):
        raise httpx.ReadTimeout("timeout", request=request)

    cache = PackageCache(tmp_path / "cache.db")
    with httpx.Client(transport=httpx.MockTransport(timeout)) as client:
        scanner = Scanner(tmp_path, client=client, cache=cache, check_registry=True)
        issues = scanner.package_issues("npm", "synthetic-package", Path("app.ts"), 1)
        assert issues[0].category == "Registry Unavailable"
        assert issues[0].severity == "HIGH"
        assert cache.get("npm", "synthetic-package") is None


def test_registry_checks_are_opt_in(tmp_path):
    def forbidden(request):
        pytest.fail("default scan must not contact registry")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        scanner = Scanner(tmp_path, client=client, cache=PackageCache(tmp_path / "cache.db"))
        assert scanner.scan_python_ast(Path("app.py"), "import not_a_real_dependency") == []


def test_secret_report_does_not_reproduce_source(scanner):
    secret = "sk-" + "A" * 24
    issues = scanner.scan_text_patterns(Path("app.py"), 'token = "' + secret + '"')
    assert issues and issues[0].severity == "HIGH"
    assert secret not in json.dumps([i.__dict__ for i in issues])


def test_stdlib_relative_and_local_imports_skip_registry(scanner, tmp_path):
    (tmp_path / "local.py").write_text("value=1")
    (tmp_path / "src" / "nested").mkdir(parents=True)
    scanner.is_package_real = lambda *args: pytest.fail("unexpected registry call")
    assert (
        scanner.scan_python_ast(
            Path("app.py"), "import json\nimport local\nimport nested\nfrom . import sibling"
        )
        == []
    )


def test_import_to_distribution_mapping(scanner):
    scanner.distributions = {"PIL": ["Pillow"]}
    names = []
    scanner.is_package_real = lambda registry, name: names.append(name) or True
    assert scanner.scan_python_ast(Path("app.py"), "from PIL import Image") == []
    assert names == ["Pillow"]


def test_missing_registry_package_is_review_finding(scanner):
    scanner.is_package_real = lambda *args: False
    issues = scanner.scan_python_ast(Path("app.py"), "import synthetic_missing_dependency")
    assert issues[0].category == "Unresolved Package"
    assert "does not prove hallucination" in issues[0].description


def test_js_scoped_packages_and_builtins(scanner):
    packages = []
    scanner.is_package_real = lambda registry, name: packages.append(name) or True
    scanner.scan_js_ts_imports(
        Path("app.ts"),
        "import x from '@scope/pkg/subpath';\nconst y=require('node:fs');\nimport z from './local';",
    )
    assert packages == ["@scope/pkg"]


def test_manifest_local_dependencies_and_npm_alias(scanner):
    packages = []
    scanner.is_package_real = lambda registry, name: packages.append(name) or True
    manifest = {
        "dependencies": {
            "local": "workspace:*",
            "folder": "file:../pkg",
            "alias": "npm:@scope/pkg@^1",
            "react": "^19",
        }
    }
    assert scanner.scan_package_json(Path("package.json"), json.dumps(manifest)) == []
    assert packages == ["@scope/pkg", "react"]


@pytest.mark.parametrize("content", ["{broken", "[]", '{"dependencies":[]}'])
def test_invalid_manifests_are_not_silently_clean(scanner, content):
    assert scanner.scan_package_json(Path("package.json"), content)[0].severity == "HIGH"


def test_syntax_and_truncation_findings(scanner):
    assert scanner.scan_python_ast(Path("app.py"), "def broken(")[0].category == "Syntax Error"
    assert (
        scanner.scan_text_patterns(Path("app.py"), "# ... rest of code here")[0].severity
        == "MEDIUM"
    )


def test_unreadable_oversized_and_symlink_files(scanner, tmp_path):
    path = tmp_path / "app.py"
    path.write_bytes(b"\xff")
    assert scanner.scan_file(path)[0].category == "Unreadable File"
    path.write_bytes(b"x" * (1024 * 1024 + 1))
    assert scanner.scan_file(path)[0].category == "Skipped File"
    link = tmp_path / "link.py"
    link.symlink_to(path)
    assert scanner.scan_file(link)[0].category == "Skipped File"


def test_ignore_rules_prune_directories_and_honor_negation(tmp_path):
    (tmp_path / ".gitignore").write_text("*.py\n!keep.py\n")
    (tmp_path / "keep.py").write_text("")
    (tmp_path / "drop.py").write_text("")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("")
    (tmp_path / "link.js").symlink_to(tmp_path / "keep.py")
    assert collect_files(tmp_path) == [tmp_path / "keep.py"]


def test_cache_expiration_and_registry_separation(tmp_path):
    cache = PackageCache(tmp_path / "cache.db")
    cache.set("pypi", "Example", True)
    assert cache.get("pypi", "example") is True
    assert cache.get("npm", "example") is None
    with sqlite3.connect(cache.db_path) as db:
        db.execute("UPDATE package_cache SET timestamp=0")
    assert cache.get("pypi", "example") is None


def test_cli_threshold_json_and_source_preservation(tmp_path):
    source = tmp_path / "app.py"
    content = 'key = "your_api_key_here"\n'
    source.write_text(content)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(source), "--json", "--fail-on", "HIGH"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)[0]["category"] == "Secret Placeholder"
    assert content.strip() not in result.stdout
    assert runner.invoke(app, ["scan", str(source), "--fail-on", "CRITICAL"]).exit_code == 0
    assert runner.invoke(app, ["scan", str(source), "--fail-on", "INVALID"]).exit_code == 2
    assert runner.invoke(app, ["scan", str(source), "--fix"]).exit_code == 2
    assert source.read_text() == content
