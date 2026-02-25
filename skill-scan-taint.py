#!/usr/bin/env python3
"""
Skill Scanner — AST Taint Tracker
Traces data flow from sensitive sources to dangerous sinks.
Catches exfiltration that pattern matching misses.

Usage: skill-scan-taint.py <skill-path>
Exit codes: 0=clean, 1=suspicious, 2=critical, 3=error
"""

import ast
import os
import sys
import json
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional, Tuple

# ── Source/Sink Definitions ──

SENSITIVE_SOURCES = {
    # Python file reads
    "open", "read", "readlines", "readline",
    # os/env access
    "os.environ", "os.getenv", "os.environ.get",
    "dotenv.load_dotenv", "dotenv_values",
    # pathlib
    "Path.read_text", "Path.read_bytes",
}

SENSITIVE_FILE_PATTERNS = [
    r"SOUL\.md", r"MEMORY\.md", r"IDENTITY\.md", r"USER\.md",
    r"AGENTS\.md", r"TOOLS\.md", r"HEARTBEAT\.md", r"CACHE\.md",
    r"\.env", r"cache\.json", r"tools\.json", r"openclaw\.json",
    r"authorized_keys", r"id_rsa", r"id_ed25519",
    r"\.openclaw", r"\.secrets", r"\.ssh",
    r"sessions\.json", r"\.jsonl",
]

DANGEROUS_SINKS = {
    # Network — Python
    "requests.post": "network", "requests.get": "network",
    "requests.put": "network", "requests.patch": "network",
    "requests.delete": "network", "requests.request": "network",
    "urllib.request.urlopen": "network", "urllib.request.Request": "network",
    "http.client.HTTPConnection": "network", "http.client.HTTPSConnection": "network",
    "httpx.post": "network", "httpx.get": "network",
    "httpx.AsyncClient": "network", "httpx.Client": "network",
    "aiohttp.ClientSession": "network",
    "socket.connect": "network", "socket.send": "network",
    "smtplib.SMTP": "network",
    # Exec — Python
    "subprocess.run": "exec", "subprocess.Popen": "exec",
    "subprocess.call": "exec", "subprocess.check_output": "exec",
    "os.system": "exec", "os.popen": "exec",
    "exec": "exec", "eval": "exec",
    "compile": "exec",
}

EXFIL_URL_PATTERNS = [
    r"webhook\.site", r"requestbin", r"pipedream",
    r"ngrok", r"pastebin", r"discord\.com/api/webhooks",
    r"t\.me/bot", r"api\.telegram\.org",
    r"imgur\.com/upload",
]


@dataclass
class TaintedVar:
    name: str
    source: str          # what made it tainted
    file: str
    line: int
    reason: str          # human-readable


@dataclass
class TaintFlow:
    source_var: str
    source_desc: str
    source_file: str
    source_line: int
    sink_name: str
    sink_type: str       # "network" or "exec"
    sink_file: str
    sink_line: int
    severity: str        # "critical" or "high"

    def __str__(self):
        return (
            f"  [{self.severity.upper()}] {self.source_file}:{self.source_line} → "
            f"{self.sink_file}:{self.sink_line}\n"
            f"    Source: {self.source_desc}\n"
            f"    Sink: {self.sink_name} ({self.sink_type})\n"
            f"    Via: ${self.source_var}"
        )


class PythonTaintAnalyzer(ast.NodeVisitor):
    """AST-based taint tracker for Python files."""

    def __init__(self, filepath: str, all_tainted: Dict[str, TaintedVar]):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.tainted: Dict[str, TaintedVar] = dict(all_tainted)  # inherit cross-file taint
        self.flows: List[TaintFlow] = []
        self.strings_seen: List[Tuple[str, int]] = []  # (string_value, line_no)
        self.imports: Dict[str, str] = {}  # alias -> full module path
        self.from_imports: Dict[str, str] = {}  # name -> module.name

    def _resolve_attr(self, node) -> str:
        """Resolve attribute chains like os.environ.get -> 'os.environ.get'"""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            # Resolve imports
            base = parts[-1]
            if base in self.imports:
                parts[-1] = self.imports[base]
            elif base in self.from_imports:
                parts[-1] = self.from_imports[base]
        parts.reverse()
        return ".".join(parts)

    def _is_sensitive_string(self, s: str) -> Optional[str]:
        """Check if a string references sensitive files."""
        for pattern in SENSITIVE_FILE_PATTERNS:
            if re.search(pattern, s, re.IGNORECASE):
                return pattern
        return None

    def _is_exfil_url(self, s: str) -> Optional[str]:
        """Check if a string is a known exfiltration endpoint."""
        for pattern in EXFIL_URL_PATTERNS:
            if re.search(pattern, s, re.IGNORECASE):
                return pattern
        return None

    def _extract_strings(self, node) -> List[str]:
        """Extract all string literals from an expression."""
        strings = []
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append(node.value)
        elif isinstance(node, ast.JoinedStr):  # f-strings
            for val in node.values:
                strings.extend(self._extract_strings(val))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            strings.extend(self._extract_strings(node.left))
            strings.extend(self._extract_strings(node.right))
        for child in ast.iter_child_nodes(node):
            if child is not node:
                strings.extend(self._extract_strings(child))
        return strings

    def _is_tainted_expr(self, node) -> Optional[TaintedVar]:
        """Check if an expression uses a tainted variable."""
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return self.tainted[node.id]
        if isinstance(node, ast.Attribute):
            full = self._resolve_attr(node)
            if full in self.tainted:
                return self.tainted[full]
            # Check if the base object is tainted
            if isinstance(node.value, ast.Name) and node.value.id in self.tainted:
                return self.tainted[node.value.id]
        if isinstance(node, ast.Subscript):
            return self._is_tainted_expr(node.value)
        if isinstance(node, ast.BinOp):
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)
        if isinstance(node, ast.Call):
            # Check if the object the method is called on is tainted (e.g., tainted_var.encode())
            if isinstance(node.func, ast.Attribute):
                t = self._is_tainted_expr(node.func.value)
                if t:
                    return t
            for arg in node.args:
                t = self._is_tainted_expr(arg)
                if t:
                    return t
            for kw in node.keywords:
                t = self._is_tainted_expr(kw.value)
                if t:
                    return t
        if isinstance(node, ast.Dict):
            for v in node.values:
                if v:
                    t = self._is_tainted_expr(v)
                    if t:
                        return t
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                t = self._is_tainted_expr(elt)
                if t:
                    return t
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    t = self._is_tainted_expr(val.value)
                    if t:
                        return t
        return None

    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self.from_imports[name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_Assign(self, node):
        """Track taint through assignments."""
        # Check if RHS introduces taint
        taint = self._check_source(node.value, node)

        # Check if RHS uses existing tainted var
        if not taint:
            taint = self._is_tainted_expr(node.value)

        if taint:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = TaintedVar(
                        name=target.id,
                        source=taint.source if isinstance(taint, TaintedVar) else taint,
                        file=self.filepath,
                        line=node.lineno,
                        reason=f"tainted via {taint.name}" if isinstance(taint, TaintedVar) else taint
                    )
                elif isinstance(target, ast.Tuple):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted[elt.id] = TaintedVar(
                                name=elt.id,
                                source="tuple_unpack",
                                file=self.filepath,
                                line=node.lineno,
                                reason=f"tainted via tuple unpack from {taint.name if isinstance(taint, TaintedVar) else taint}"
                            )

        self.generic_visit(node)

    def _check_source(self, node, parent=None) -> Optional[str]:
        """Check if a node is a sensitive source (file read, env access, etc.)."""
        if not isinstance(node, ast.Call):
            # Check string literals for sensitive file paths
            strings = self._extract_strings(node)
            for s in strings:
                match = self._is_sensitive_string(s)
                if match:
                    return f"sensitive_path:{match}"
            return None

        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.from_imports:
                func_name = self.from_imports[func_name]
        elif isinstance(node.func, ast.Attribute):
            func_name = self._resolve_attr(node.func)

        # Check if this is a file open with sensitive path
        if func_name in ("open", "builtins.open", "io.open"):
            if node.args:
                strings = self._extract_strings(node.args[0])
                for s in strings:
                    match = self._is_sensitive_string(s)
                    if match:
                        return f"file_read:{match}"
                # Even without a sensitive path, reading any file is a source
                return "file_read:generic"

        # Check env access
        if func_name in ("os.getenv", "os.environ.get"):
            return "env_access"

        # Check pathlib reads
        if func_name.endswith((".read_text", ".read_bytes")):
            return "file_read:pathlib"

        # Check for sensitive strings in all args
        for arg in node.args:
            strings = self._extract_strings(arg)
            for s in strings:
                match = self._is_sensitive_string(s)
                if match:
                    return f"sensitive_ref:{match}"

        return None

    def visit_Expr(self, node):
        """Check standalone expressions (function calls) for sinks."""
        if isinstance(node.value, ast.Call):
            self._check_sink(node.value)
        self.generic_visit(node)

    def visit_Call(self, node):
        """Check all calls for sinks."""
        self._check_sink(node)
        self.generic_visit(node)

    def _check_sink(self, node):
        """Check if a call is a dangerous sink receiving tainted data."""
        if not isinstance(node, ast.Call):
            return

        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.from_imports:
                func_name = self.from_imports[func_name]
        elif isinstance(node.func, ast.Attribute):
            func_name = self._resolve_attr(node.func)

        # Check if this function is a known sink
        sink_type = None
        for sink_pattern, stype in DANGEROUS_SINKS.items():
            if func_name == sink_pattern or func_name.endswith(f".{sink_pattern.split('.')[-1]}"):
                sink_type = stype
                break

        if not sink_type:
            return

        # Check if any argument is tainted
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in all_args:
            taint = self._is_tainted_expr(arg)
            if taint:
                severity = "critical" if sink_type == "network" else "high"
                self.flows.append(TaintFlow(
                    source_var=taint.name,
                    source_desc=taint.reason,
                    source_file=taint.file,
                    source_line=taint.line,
                    sink_name=func_name,
                    sink_type=sink_type,
                    sink_file=self.filepath,
                    sink_line=node.lineno,
                    severity=severity,
                ))
                return  # One flow per call is enough

            # Also check for exfil URLs in args
            strings = self._extract_strings(arg)
            for s in strings:
                exfil = self._is_exfil_url(s)
                if exfil and sink_type == "network":
                    self.flows.append(TaintFlow(
                        source_var="<literal_url>",
                        source_desc=f"exfiltration endpoint: {exfil}",
                        source_file=self.filepath,
                        source_line=node.lineno,
                        sink_name=func_name,
                        sink_type="network",
                        sink_file=self.filepath,
                        sink_line=node.lineno,
                        severity="critical",
                    ))
                    return


class JSTaintAnalyzer:
    """Regex-based taint tracker for JavaScript/TypeScript files.
    Not as precise as AST, but catches common patterns."""

    SOURCES_RE = re.compile(
        r"""(?:fs\.readFile(?:Sync)?|require\s*\(\s*['"]fs['"]\)|"""
        r"""process\.env|\.env|dotenv|"""
        r"""readFileSync|readFile)\s*\(""",
        re.IGNORECASE
    )

    SENSITIVE_PATH_RE = re.compile(
        "|".join(SENSITIVE_FILE_PATTERNS),
        re.IGNORECASE
    )

    SINKS_RE = re.compile(
        r"""(?:fetch\s*\(|axios\.\w+\s*\(|"""
        r"""https?\.request\s*\(|http\.request\s*\(|"""
        r"""\.post\s*\(|\.get\s*\(|\.put\s*\(|"""
        r"""child_process|exec\s*\(|execSync|spawn\s*\(|"""
        r"""eval\s*\()""",
        re.IGNORECASE
    )

    EXFIL_RE = re.compile(
        "|".join(EXFIL_URL_PATTERNS),
        re.IGNORECASE
    )

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.flows: List[TaintFlow] = []

    def analyze(self) -> List[TaintFlow]:
        try:
            with open(self.filepath, "r", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        source_lines = []  # (line_no, line_text, reason)
        sink_lines = []    # (line_no, line_text, sink_name)
        has_sensitive_paths = []
        has_exfil_urls = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            if self.SOURCES_RE.search(line):
                source_lines.append((i, line.strip(), "file/env read"))

            if self.SENSITIVE_PATH_RE.search(line):
                has_sensitive_paths.append((i, line.strip()))

            if self.SINKS_RE.search(line):
                sink_match = self.SINKS_RE.search(line)
                sink_lines.append((i, line.strip(), sink_match.group()))

            if self.EXFIL_RE.search(line):
                has_exfil_urls.append((i, line.strip()))

        # Heuristic: if file has both sources and sinks, flag it
        # More sophisticated: check variable flow within ±20 lines
        if source_lines and sink_lines:
            for src_line, src_text, src_reason in source_lines:
                for sink_line, sink_text, sink_name in sink_lines:
                    self.flows.append(TaintFlow(
                        source_var="<js_variable>",
                        source_desc=f"{src_reason}: {src_text[:80]}",
                        source_file=self.filepath,
                        source_line=src_line,
                        sink_name=sink_name.strip(),
                        sink_type="network" if any(kw in sink_name.lower() for kw in ("fetch", "axios", "http", "post", "get", "put")) else "exec",
                        sink_file=self.filepath,
                        sink_line=sink_line,
                        severity="high",
                    ))

        # Sensitive path + exfil URL in same file = critical
        if has_sensitive_paths and has_exfil_urls:
            self.flows.append(TaintFlow(
                source_var="<sensitive_path>",
                source_desc=f"references sensitive file: {has_sensitive_paths[0][1][:80]}",
                source_file=self.filepath,
                source_line=has_sensitive_paths[0][0],
                sink_name="exfil_url",
                sink_type="network",
                sink_file=self.filepath,
                sink_line=has_exfil_urls[0][0],
                severity="critical",
            ))

        return self.flows


class ShellTaintAnalyzer:
    """Pattern-based taint tracker for shell scripts."""

    SOURCES_RE = re.compile(
        r"""(?:cat\s|head\s|tail\s|less\s|more\s|source\s|\.\s+|"""
        r"""read\s|<\s|grep\s.*(?:""" + "|".join(SENSITIVE_FILE_PATTERNS) + r"""))""",
        re.IGNORECASE
    )

    SINKS_RE = re.compile(
        r"""(?:curl\s|wget\s|nc\s|ncat\s|socat\s|"""
        r"""python[3]?\s+-c|perl\s+-e|ruby\s+-e)""",
        re.IGNORECASE
    )

    PIPE_EXFIL_RE = re.compile(
        r"""(?:cat|head|tail|read).*\|.*(?:curl|wget|nc|python|base64)""",
        re.IGNORECASE
    )

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.flows: List[TaintFlow] = []

    def analyze(self) -> List[TaintFlow]:
        try:
            with open(self.filepath, "r", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # Direct pipe from source to sink
            if self.PIPE_EXFIL_RE.search(line):
                self.flows.append(TaintFlow(
                    source_var="<pipe>",
                    source_desc=f"piped read: {stripped[:80]}",
                    source_file=self.filepath,
                    source_line=i,
                    sink_name="pipe_to_network",
                    sink_type="network",
                    sink_file=self.filepath,
                    sink_line=i,
                    severity="critical",
                ))

        return self.flows


def scan_skill(skill_path: str) -> Tuple[List[TaintFlow], Dict]:
    """Scan a skill directory for taint flows."""
    skill_path = Path(skill_path)
    all_flows: List[TaintFlow] = []
    stats = {"python_files": 0, "js_files": 0, "shell_files": 0, "total_lines": 0}

    # Collect all tainted vars across Python files (cross-file tracking)
    global_tainted: Dict[str, TaintedVar] = {}

    # Scan Python files
    for py_file in sorted(skill_path.rglob("*.py")):
        if "node_modules" in str(py_file) or "__pycache__" in str(py_file):
            continue
        stats["python_files"] += 1
        try:
            source = py_file.read_text(errors="ignore")
            stats["total_lines"] += source.count("\n")
            tree = ast.parse(source, filename=str(py_file))
            analyzer = PythonTaintAnalyzer(str(py_file), global_tainted)
            analyzer.visit(tree)
            all_flows.extend(analyzer.flows)
            global_tainted.update(analyzer.tainted)
        except SyntaxError:
            pass  # Skip unparseable files
        except Exception as e:
            print(f"  ⚠️  Error analyzing {py_file}: {e}", file=sys.stderr)

    # Scan JS/TS files
    for pattern in ("*.js", "*.ts", "*.mjs", "*.cjs"):
        for js_file in sorted(skill_path.rglob(pattern)):
            if "node_modules" in str(js_file) or "dist" in str(js_file):
                continue
            stats["js_files"] += 1
            try:
                stats["total_lines"] += js_file.read_text(errors="ignore").count("\n")
                analyzer = JSTaintAnalyzer(str(js_file))
                all_flows.extend(analyzer.analyze())
            except Exception as e:
                print(f"  ⚠️  Error analyzing {js_file}: {e}", file=sys.stderr)

    # Scan shell scripts
    for sh_file in sorted(skill_path.rglob("*.sh")):
        stats["shell_files"] += 1
        try:
            stats["total_lines"] += sh_file.read_text(errors="ignore").count("\n")
            analyzer = ShellTaintAnalyzer(str(sh_file))
            all_flows.extend(analyzer.analyze())
        except Exception as e:
            print(f"  ⚠️  Error analyzing {sh_file}: {e}", file=sys.stderr)

    # Deduplicate flows
    seen = set()
    unique_flows = []
    for flow in all_flows:
        key = (flow.source_file, flow.source_line, flow.sink_file, flow.sink_line, flow.sink_name)
        if key not in seen:
            seen.add(key)
            unique_flows.append(flow)

    return unique_flows, stats


def main():
    if len(sys.argv) < 2:
        print("Usage: skill-scan-taint.py <skill-path> [--json]")
        sys.exit(3)

    skill_path = sys.argv[1]
    json_output = "--json" in sys.argv

    if not os.path.exists(skill_path):
        print(f"❌ Path not found: {skill_path}")
        sys.exit(3)

    flows, stats = scan_skill(skill_path)

    if json_output:
        result = {
            "skill_path": skill_path,
            "stats": stats,
            "flows": [
                {
                    "severity": f.severity,
                    "source_var": f.source_var,
                    "source_desc": f.source_desc,
                    "source_file": f.source_file,
                    "source_line": f.source_line,
                    "sink_name": f.sink_name,
                    "sink_type": f.sink_type,
                    "sink_file": f.sink_file,
                    "sink_line": f.sink_line,
                }
                for f in flows
            ],
            "verdict": "critical" if any(f.severity == "critical" for f in flows)
                       else "suspicious" if flows
                       else "clean"
        }
        print(json.dumps(result, indent=2))
    else:
        total_files = stats["python_files"] + stats["js_files"] + stats["shell_files"]
        print(f"  Scanned: {total_files} files ({stats['python_files']} Python, "
              f"{stats['js_files']} JS/TS, {stats['shell_files']} Shell) — "
              f"{stats['total_lines']} lines")

        if not flows:
            print("  ✅ No taint flows detected — no data flows from sensitive sources to dangerous sinks")
        else:
            critical = [f for f in flows if f.severity == "critical"]
            high = [f for f in flows if f.severity == "high"]

            print(f"  🔴 {len(critical)} critical, 🟡 {len(high)} high severity flow(s) detected:")
            print()
            for flow in flows:
                print(str(flow))
                print()

    # Exit code
    if any(f.severity == "critical" for f in flows):
        sys.exit(2)
    elif flows:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
