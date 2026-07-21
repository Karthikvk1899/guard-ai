import ast
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple
import httpx
from guard_ai.cache import PackageCache

STDLIB_PYTHON = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else {
    "os", "sys", "re", "math", "time", "json", "typing", "ast", "pathlib", "dataclasses",
    "collections", "functools", "itertools", "datetime", "random", "logging", "asyncio",
    "subprocess", "threading", "multiprocessing", "http", "urllib", "hashlib", "sqlite3"
}

NODE_BUILTINS = {
    "fs", "path", "http", "https", "crypto", "os", "events", "stream", "util", "buffer",
    "child_process", "cluster", "dns", "net", "tls", "url", "zlib", "v8", "vm",
    "worker_threads", "readline", "assert", "querystring"
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
    def __init__(self, project_root: Path = Path(".")):
        self.client = httpx.Client(timeout=3.0)
        self.cache = PackageCache()
        self.project_root = project_root.resolve()

    def is_local_module(self, pkg_name: str) -> bool:
        if (self.project_root / pkg_name).exists() or (self.project_root / f"{pkg_name}.py").exists():
            return True
        src_dir = self.project_root / "src"
        if src_dir.exists():
            if (src_dir / pkg_name).exists() or (src_dir / f"{pkg_name}.py").exists():
                return True
        return False

    def is_package_real(self, registry: str, pkg_name: str) -> bool:
        cached = self.cache.get(registry, pkg_name)
        if cached is not None:
            return cached

        try:
            if registry == "pypi":
                url = f"https://pypi.org/pypi/{pkg_name}/json"
            else:
                url = f"https://registry.npmjs.org/{pkg_name}"
            
            res = self.client.get(url)
            is_real = (res.status_code == 200)
        except Exception:
            is_real = True

        self.cache.set(registry, pkg_name, is_real)
        return is_real

    def _extract_npm_root_package(self, import_str: str) -> str:
        if import_str.startswith('.'):
            return ""
        parts = import_str.split('/')
        if import_str.startswith('@') and len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return parts[0]

    def scan_python_ast(self, file_path: Path, code: str) -> List[Issue]:
        issues = []
        try:
            tree = ast.parse(code, filename=str(file_path))
        except SyntaxError as e:
            issues.append(Issue(
                file_path=str(file_path),
                line_num=e.lineno or 1,
                category="Syntax Error",
                description=f"Syntax Error: {e.msg}",
                severity="HIGH"
            ))
            return issues

        for node in ast.walk(tree):
            imported_pkgs = []
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split('.')[0]
                    imported_pkgs.append((root_pkg, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.level == 0:
                    root_pkg = node.module.split('.')[0]
                    imported_pkgs.append((root_pkg, node.lineno))

            for pkg, line_no in imported_pkgs:
                if pkg in STDLIB_PYTHON or self.is_local_module(pkg):
                    continue
                if not self.is_package_real("pypi", pkg):
                    issues.append(Issue(
                        file_path=str(file_path),
                        line_num=line_no,
                        category="Hallucinated Package",
                        description=f"PyPI package '{pkg}' was not found (Slopsquatting risk).",
                        severity="CRITICAL"
                    ))

        return issues

    def scan_js_ts_imports(self, file_path: Path, code: str) -> List[Issue]:
        issues = []
        lines = code.splitlines()

        import_regex = re.compile(r"(?:import\s+.*?from\s+['\"]([^'\"]+)['\"]|require\(['\"]([^'\"]+)['\"]\))")

        for line_idx, line in enumerate(lines, start=1):
            matches = import_regex.findall(line)
            for m in matches:
                raw_pkg = m[0] or m[1]
                root_pkg = self._extract_npm_root_package(raw_pkg)
                if not root_pkg or root_pkg in NODE_BUILTINS or root_pkg.startswith("node:") or self.is_local_module(root_pkg):
                    continue

                if not self.is_package_real("npm", root_pkg):
                    issues.append(Issue(
                        file_path=str(file_path),
                        line_num=line_idx,
                        category="Hallucinated Package",
                        description=f"NPM package '{root_pkg}' was not found (Slopsquatting risk).",
                        severity="CRITICAL"
                    ))

        return issues

    def scan_package_json(self, file_path: Path, code: str) -> List[Issue]:
        issues = []
        try:
            data = json.loads(code)
        except Exception:
            return issues

        deps = {}
        for key in ["dependencies", "devDependencies", "peerDependencies"]:
            if key in data and isinstance(data[key], dict):
                deps.update(data[key])

        for pkg in deps.keys():
            root_pkg = self._extract_npm_root_package(pkg)
            if not root_pkg:
                continue
            if not self.is_package_real("npm", root_pkg):
                issues.append(Issue(
                    file_path=str(file_path),
                    line_num=1,
                    category="Hallucinated Package",
                    description=f"package.json dependency '{root_pkg}' was not found on NPM.",
                    severity="CRITICAL"
                ))

        return issues

    def scan_text_patterns(self, file_path: Path, code: str) -> List[Issue]:
        issues = []
        lines = code.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            for pattern, desc in SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(Issue(
                        file_path=str(file_path),
                        line_num=line_idx,
                        category="Secret Placeholder",
                        description=f"{desc}: '{line.strip()}'",
                        severity="HIGH"
                    ))
                    break

            for pattern, desc in TRUNCATION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(Issue(
                        file_path=str(file_path),
                        line_num=line_idx,
                        category="Truncated Code",
                        description=f"{desc}: '{line.strip()}'",
                        severity="MEDIUM"
                    ))
                    break

        return issues

    def scan_file(self, file_path: Path) -> List[Issue]:
        try:
            code = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

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
        """Automatically sanitizes secrets and comments out hallucinated package imports."""
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return 0

        fixes_applied = 0
        new_lines = []

        for line in lines:
            modified_line = line
            
            # Replace secret placeholders with environment variable lookups
            for pattern, _ in SECRET_PATTERNS:
                if re.search(pattern, modified_line, re.IGNORECASE):
                    if "=" in modified_line:
                        var_name = modified_line.split("=")[0].strip()
                        if file_path.suffix == ".py":
                            modified_line = f'{var_name} = os.getenv("{var_name.upper()}", "")  # FIXED BY GUARD-AI'
                        else:
                            modified_line = f'const {var_name.replace("const ", "").replace("let ", "").replace("var ", "")} = process.env.{var_name.upper()} || ""; // FIXED BY GUARD-AI'
                        fixes_applied += 1
                        break

            # Comment out hallucinated packages
            if file_path.suffix == ".py" and ("import " in modified_line or "from " in modified_line):
                for part in re.findall(r"\b[a-zA-Z0-9_\-]+\b", modified_line):
                    if part in ["import", "from", "as"]:
                        continue
                    if not self.is_local_module(part) and part not in STDLIB_PYTHON:
                        if not self.is_package_real("pypi", part):
                            modified_line = f"# {modified_line}  # DISABLED BY GUARD-AI: Hallucinated Package"
                            fixes_applied += 1
                            break

            new_lines.append(modified_line)

        if fixes_applied > 0:
            file_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

        return fixes_applied
