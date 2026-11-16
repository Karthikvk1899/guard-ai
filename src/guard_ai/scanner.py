import ast
import json
import re
import sys
from dataclasses import dataclass
from importlib.metadata import packages_distributions
from pathlib import Path
from urllib.parse import quote

import httpx

from guard_ai.cache import PackageCache

STDLIB_PYTHON = (
    set(sys.stdlib_module_names)
    if hasattr(sys, "stdlib_module_names")
    else {
        "os",
        "sys",
        "re",
        "math",
        "time",
        "json",
        "typing",
        "ast",
        "pathlib",
        "dataclasses",
        "collections",
        "functools",
        "itertools",
        "datetime",
        "random",
        "logging",
        "asyncio",
        "subprocess",
        "threading",
        "multiprocessing",
        "http",
        "urllib",
        "hashlib",
        "sqlite3",
    }
)

NODE_BUILTINS = {
    "fs",
    "path",
    "http",
    "https",
    "crypto",
    "os",
    "events",
    "stream",
    "util",
    "buffer",
    "child_process",
    "cluster",
    "dns",
    "net",
    "tls",
    "url",
    "zlib",
    "v8",
    "vm",
    "worker_threads",
    "readline",
    "assert",
    "querystring",
}

SECRET_PATTERNS = [
    (r"your[_\-]?openai[_\-]?key", "Hardcoded OpenAI key placeholder"),
    (r"your[_\-]?api[_\-]?key", "Generic API key placeholder"),
    (r"insert[_\-]?key[_\-]?here", "Insert key placeholder marker"),
    (r"sk-[a-zA-Z0-9]{20,}", "Hardcoded secret key string"),
]

TRUNCATION_PATTERNS = [
    (r"#\s*\.\.\.\s*rest of code", "Truncated code comment"),
    (r"#\s*\.\.\.\s*existing code", "Truncated code comment"),
    (r"#\s*TODO:\s*implement", "Unimplemented TODO placeholder"),
    (r"//\s*\.\.\.\s*rest of code", "Truncated code comment"),
    (r"//\s*\.\.\.\s*existing code", "Truncated code comment"),
]


@dataclass
class Issue:
    file_path: str
    line_num: int
    category: str
    description: str
    severity: str


class Scanner:
    def __init__(
        self,
        project_root: Path = Path("."),
        *,
        check_registry: bool = False,
        client=None,
        cache=None,
    ):
        self.client = client or httpx.Client(timeout=3.0, follow_redirects=False, trust_env=False)
        self.check_registry = check_registry
        self.distributions = packages_distributions()
        self._lookups = {}
        self.cache = cache or PackageCache()
        self.project_root = project_root.resolve()

    def is_local_module(self, pkg_name: str) -> bool:
        if (self.project_root / pkg_name).exists() or (
            self.project_root / f"{pkg_name}.py"
        ).exists():
            return True
        src_dir = self.project_root / "src"
        return (src_dir / pkg_name).exists() or (src_dir / f"{pkg_name}.py").exists()

    def close(self):
        self.client.close()

    def is_package_real(self, registry: str, pkg_name: str):
        """Return True/False only for authoritative 200/404, otherwise unknown."""
        if registry not in {"pypi", "npm"}:
            raise ValueError("unsupported registry")
        key = (registry, pkg_name)
        if key in self._lookups:
            return self._lookups[key]
        cached = self.cache.get(registry, pkg_name)
        if cached is not None:
            self._lookups[key] = cached
            return cached
        url = (
            "https://pypi.org/pypi/" + quote(pkg_name, safe="") + "/json"
            if registry == "pypi"
            else "https://registry.npmjs.org/" + quote(pkg_name, safe="")
        )
        result = None
        try:
            # Availability needs only the status; do not buffer registry metadata.
            with self.client.stream("GET", url) as response:
                if response.status_code == 200:
                    result = True
                elif response.status_code == 404:
                    result = False
        except httpx.HTTPError:
            pass
        if result is not None:
            self.cache.set(registry, pkg_name, result)
        self._lookups[key] = result
        return result

    def package_issues(self, registry, package, file_path, line):
        if not self.check_registry:
            return []
        result = self.is_package_real(registry, package)
        if result is True:
            return []
        if result is None:
            return [
                Issue(
                    str(file_path),
                    line,
                    "Registry Unavailable",
                    f"Could not verify {registry} package '{package}'; retry or review manually.",
                    "HIGH",
                )
            ]
        return [
            Issue(
                str(file_path),
                line,
                "Unresolved Package",
                f"{registry} returned 404 for '{package}'. Check private registries, aliases and distribution names; this does not prove hallucination.",
                "HIGH",
            )
        ]

    def _extract_npm_root_package(self, import_str: str) -> str:
        if import_str.startswith("."):
            return ""
        parts = import_str.split("/")
        if import_str.startswith("@") and len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return parts[0]

    def scan_python_ast(self, file_path: Path, code: str) -> list[Issue]:
        issues = []
        try:
            tree = ast.parse(code, filename=str(file_path))
        except SyntaxError as e:
            issues.append(
                Issue(
                    file_path=str(file_path),
                    line_num=e.lineno or 1,
                    category="Syntax Error",
                    description=f"Syntax Error: {e.msg}",
                    severity="HIGH",
                )
            )
            return issues

        for node in ast.walk(tree):
            imported_pkgs = []
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    imported_pkgs.append((root_pkg, node.lineno))
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                root_pkg = node.module.split(".")[0]
                imported_pkgs.append((root_pkg, node.lineno))

            for pkg, line_no in imported_pkgs:
                if pkg in STDLIB_PYTHON or self.is_local_module(pkg):
                    continue
                # Import names and distribution names differ (e.g. PIL/Pillow).
                candidates = self.distributions.get(pkg, [pkg])
                for distribution in candidates:
                    issues.extend(self.package_issues("pypi", distribution, file_path, line_no))

        return issues

    def scan_js_ts_imports(self, file_path: Path, code: str) -> list[Issue]:
        issues = []
        lines = code.splitlines()

        import_regex = re.compile(
            r"(?:import\s+.*?from\s+['\"]([^'\"]+)['\"]|require\(['\"]([^'\"]+)['\"]\))"
        )

        for line_idx, line in enumerate(lines, start=1):
            matches = import_regex.findall(line)
            for m in matches:
                raw_pkg = m[0] or m[1]
                root_pkg = self._extract_npm_root_package(raw_pkg)
                if (
                    not root_pkg
                    or root_pkg in NODE_BUILTINS
                    or root_pkg.startswith("node:")
                    or self.is_local_module(root_pkg)
                ):
                    continue

                issues.extend(self.package_issues("npm", root_pkg, file_path, line_idx))

        return issues

    def scan_package_json(self, file_path: Path, code: str) -> list[Issue]:
        try:
            data = json.loads(code)
            if not isinstance(data, dict):
                raise TypeError("object required")
        except (ValueError, TypeError):
            return [
                Issue(
                    str(file_path),
                    1,
                    "Invalid Manifest",
                    "package.json must contain a valid JSON object",
                    "HIGH",
                )
            ]
        issues = []
        for section in [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ]:
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                issues.append(
                    Issue(
                        str(file_path),
                        1,
                        "Invalid Manifest",
                        f"{section} must be an object",
                        "HIGH",
                    )
                )
                continue
            for package, version in deps.items():
                if not isinstance(version, str):
                    issues.append(
                        Issue(
                            str(file_path),
                            1,
                            "Invalid Manifest",
                            "Dependency versions must be strings",
                            "HIGH",
                        )
                    )
                    continue
                if version.startswith(("file:", "link:", "workspace:", "git", "http:", "https:")):
                    continue
                if version.startswith("npm:"):
                    package = version[4:].rsplit("@", 1)[0] if "@" in version[5:] else version[4:]
                issues.extend(self.package_issues("npm", package, file_path, 1))
        return issues

    def scan_text_patterns(self, file_path: Path, code: str) -> list[Issue]:
        issues = []
        lines = code.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            for pattern, desc in SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(
                        Issue(
                            file_path=str(file_path),
                            line_num=line_idx,
                            category="Secret Placeholder",
                            description=desc + " (source text redacted)",
                            severity="HIGH",
                        )
                    )
                    break

            for pattern, desc in TRUNCATION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(
                        Issue(
                            file_path=str(file_path),
                            line_num=line_idx,
                            category="Truncated Code",
                            description=desc + " (source text redacted)",
                            severity="MEDIUM",
                        )
                    )
                    break

        return issues

    def scan_file(self, file_path: Path) -> list[Issue]:
        try:
            if file_path.is_symlink():
                return [
                    Issue(str(file_path), 1, "Skipped File", "Symlink target was not read", "LOW")
                ]
            if file_path.stat().st_size > 1024 * 1024:
                return [
                    Issue(
                        str(file_path),
                        1,
                        "Skipped File",
                        "Source exceeds the 1 MiB scan limit",
                        "HIGH",
                    )
                ]
            code = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return [
                Issue(
                    str(file_path),
                    1,
                    "Unreadable File",
                    "Source could not be read as UTF-8",
                    "HIGH",
                )
            ]

        issues = []
        issues.extend(self.scan_text_patterns(file_path, code))

        if file_path.suffix == ".py":
            issues.extend(self.scan_python_ast(file_path, code))
        elif file_path.suffix in [".js", ".ts", ".jsx", ".tsx"]:
            issues.extend(self.scan_js_ts_imports(file_path, code))
        elif file_path.name == "package.json":
            issues.extend(self.scan_package_json(file_path, code))

        return issues

    def fix_file(self, file_path: Path) -> int:
        raise ValueError("Automatic rewriting was removed: findings require human review")
