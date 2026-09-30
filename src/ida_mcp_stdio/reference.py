"""Offline API discovery from installed source, without importing IDA."""

from __future__ import annotations

import ast
import importlib.util
import re
from functools import lru_cache
from pathlib import Path


class ReferenceIndex:
    """Index public functions, methods, classes and examples from Python source."""

    def __init__(self, roots: list[Path]):
        self.entries: list[dict] = []
        for root in roots:
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("*.py")):
                if "__pycache__" in path.parts:
                    continue
                try:
                    source = path.read_text(encoding="utf-8")
                    tree = ast.parse(source)
                except (OSError, SyntaxError, UnicodeError):
                    continue
                module = ".".join(path.relative_to(root).with_suffix("").parts)
                if root.name == "ida_domain":
                    module = "ida_domain." + module
                self._collect(tree.body, module, path, source)

    def _collect(self, nodes: list, prefix: str, path: Path, source: str) -> None:
        for node in nodes:
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            if node.name.startswith("_"):
                continue
            name = prefix + "." + node.name
            if isinstance(node, ast.ClassDef):
                signature = "class " + node.name
            else:
                signature = "def " + node.name + "(" + ast.unparse(node.args) + ")"
                if node.returns:
                    signature += " -> " + ast.unparse(node.returns)
            self.entries.append(
                {
                    "name": name,
                    "signature": signature,
                    "documentation": (ast.get_docstring(node) or "")[:6000],
                    "path": str(path),
                    "line": node.lineno,
                    "source": (ast.get_source_segment(source, node) or "")[:12000],
                }
            )
            if isinstance(node, ast.ClassDef):
                self._collect(node.body, name, path, source)

    def search(
        self, query: str, offset: int = 0, limit: int = 8, include_source: bool = False
    ) -> dict:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must be a nonempty string")
        if offset < 0 or not 1 <= limit <= 20:
            raise ValueError("offset must be >= 0 and limit between 1 and 20")
        tokens = re.findall(r"[\w]+", query.lower())
        ranked = []
        for entry in self.entries:
            name = entry["name"].lower()
            searchable = (name + " " + entry["documentation"]).lower()
            score = sum(5 * (token in name) + (token in searchable) for token in tokens)
            if score:
                ranked.append((score, entry))
        ranked.sort(key=lambda item: (-item[0], item[1]["name"]))
        page = []
        for _, entry in ranked[offset : offset + limit]:
            page.append(
                {k: v for k, v in entry.items() if include_source or k != "source"}
            )
        return {
            "query": query,
            "entries": page,
            "total": len(ranked),
            "next_offset": offset + limit if offset + limit < len(ranked) else None,
            "idapython_documentation": "https://python.docs.hex-rays.com/",
            "domain_documentation": "https://ida-domain.docs.hex-rays.com/",
            "note": "Signatures reflect installed source. IDAPython SDK documentation is linked, not bundled.",
        }


@lru_cache(maxsize=1)
def get_reference_index() -> ReferenceIndex:
    roots = [Path(__file__).parent / "tools"]
    spec = importlib.util.find_spec("ida_domain")
    if spec and spec.submodule_search_locations:
        roots.extend(Path(location) for location in spec.submodule_search_locations)
    return ReferenceIndex(roots)
