"""Offline API discovery from installed source, without importing IDA."""

from __future__ import annotations

import ast
import importlib.metadata
import importlib.util
import re
from functools import lru_cache
from pathlib import Path
from textwrap import dedent

_STOPWORDS = {
    "a",
    "an",
    "and",
    "do",
    "for",
    "from",
    "how",
    "i",
    "ida",
    "in",
    "of",
    "the",
    "to",
    "with",
}


def _function_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    positional = node.args.posonlyargs + node.args.args
    defaults = [None] * (len(positional) - len(node.args.defaults)) + list(
        node.args.defaults
    )

    def parameter(arg: ast.arg, default: ast.AST | None = None) -> str:
        result = arg.arg
        if arg.annotation is not None:
            result += ": " + ast.unparse(arg.annotation)
        if default is not None:
            result += " = " + ast.unparse(default)
        return result

    parts = []
    for i, (arg, default) in enumerate(zip(positional, defaults)):
        parts.append(parameter(arg, default))
        if node.args.posonlyargs and i + 1 == len(node.args.posonlyargs):
            parts.append("/")
    if node.args.vararg:
        parts.append("*" + parameter(node.args.vararg))
    elif node.args.kwonlyargs:
        parts.append("*")
    parts.extend(
        parameter(arg, default)
        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
    )
    if node.args.kwarg:
        parts.append("**" + parameter(node.args.kwarg))
    prefix = "async def " if isinstance(node, ast.AsyncFunctionDef) else "def "
    signature = prefix + node.name + "(" + ", ".join(parts) + ")"
    if node.returns is not None:
        signature += " -> " + ast.unparse(node.returns)
    return signature


class ReferenceIndex:
    """Index public functions, methods, classes and examples from Python source."""

    def __init__(self, roots: list[Path], domain_version: str | None = None):
        self.entries: list[dict] = []
        self.examples: list[dict] = []
        self.domain_version = domain_version
        seen_examples: set[Path] = set()
        for root in roots:
            if not root.is_dir():
                continue
            if root.name == "ida_domain":
                for origin, examples_root in (
                    ("packaged", root / "_examples"),
                    ("checkout", root.parent / "examples"),
                ):
                    self._collect_examples(examples_root, origin, seen_examples)
            for path in sorted(root.rglob("*.py")):
                relative = path.relative_to(root)
                if any(
                    part in {"__pycache__", "_examples", "_docs"}
                    for part in relative.parts
                ):
                    continue
                try:
                    source = path.read_text(encoding="utf-8")
                    tree = ast.parse(source, filename=str(path))
                except (OSError, SyntaxError, UnicodeError):
                    continue
                module = ".".join(relative.with_suffix("").parts)
                file = relative.as_posix()
                if root.name == "ida_domain":
                    module = "ida_domain." + module
                    file = "ida_domain/" + file
                self.entries.append(
                    {
                        "kind": "module",
                        "name": module,
                        "qualname": module,
                        "module": module,
                        "signature": "module " + module,
                        "documentation": ast.get_docstring(tree) or "",
                        "path": str(path),
                        "file": file,
                        "line": 1,
                        "visibility": (
                            "private" if path.stem.startswith("_") else "public"
                        ),
                        "source": source,
                    }
                )
                self._collect(tree.body, module, module, path, file, source)

    def _collect(
        self,
        nodes: list,
        prefix: str,
        module: str,
        path: Path,
        file: str,
        source: str,
        class_name: str | None = None,
    ) -> None:
        for node in nodes:
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            name = prefix + "." + node.name
            metadata = {
                "decorators": [ast.unparse(item) for item in node.decorator_list]
            }
            if isinstance(node, ast.ClassDef):
                bases = [ast.unparse(base) for base in node.bases]
                arguments = bases + [ast.unparse(keyword) for keyword in node.keywords]
                signature = "class " + node.name
                if arguments:
                    signature += "(" + ", ".join(arguments) + ")"
                metadata.update(kind="class", bases=bases)
            else:
                signature = _function_signature(node)
                metadata.update(
                    kind="method" if class_name is not None else "function",
                    **{"async": isinstance(node, ast.AsyncFunctionDef)},
                )
                if class_name is not None:
                    metadata["class"] = class_name
            start_line = min(
                [node.lineno] + [item.lineno for item in node.decorator_list]
            )
            node_source = dedent(
                "".join(
                    source.splitlines(keepends=True)[start_line - 1 : node.end_lineno]
                )
            )
            self.entries.append(
                {
                    **metadata,
                    "name": name,
                    "qualname": name,
                    "module": module,
                    "signature": signature,
                    "documentation": ast.get_docstring(node) or "",
                    "path": str(path),
                    "file": file,
                    "line": node.lineno,
                    "visibility": "private" if node.name.startswith("_") else "public",
                    "source": node_source,
                }
            )
            if isinstance(node, ast.ClassDef):
                nested_class = (
                    class_name + "." + node.name
                    if class_name is not None
                    else node.name
                )
                self._collect(node.body, name, module, path, file, source, nested_class)

    def _collect_examples(self, root: Path, origin: str, seen: set[Path]) -> None:
        if not root.is_dir():
            return
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.relative_to(root).parts or path.resolve() in seen:
                continue
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError, UnicodeError):
                continue
            relative = path.relative_to(root)
            self.examples.append(
                {
                    "kind": "example",
                    "name": relative.with_suffix("").as_posix(),
                    "path": relative.as_posix(),
                    "file": str(path),
                    "documentation": ast.get_docstring(tree) or "",
                    "origin": origin,
                    "source": source,
                }
            )
            seen.add(path.resolve())

    @staticmethod
    def _rank(items: list[dict], query: str, tokens: list[str]) -> list[dict]:
        ranked = []
        for entry in items:
            if entry.get("visibility", "public") != "public":
                continue
            name = entry["name"].casefold()
            body = entry["documentation"].casefold()
            if entry["kind"] == "example":
                body += " " + entry["source"].casefold()
            score = 100 if query in name or query in body else 0
            for token in tokens:
                for variant in {token, token.removesuffix("s")} - {""}:
                    score += 12 * (variant in name) + 2 * (variant in body)
                    if name.rsplit(".", 1)[-1] == variant:
                        score += 40
            if score and "property" in entry.get("decorators", []):
                score += 20
            if score:
                ranked.append((score, entry))
        ranked.sort(
            key=lambda item: (-item[0], item[1]["name"], item[1].get("origin", ""))
        )
        return [entry for _, entry in ranked]

    @staticmethod
    def _page(
        entries: list[dict], offset: int, limit: int, include_source: bool
    ) -> list[dict]:
        return [
            {
                key: value
                for key, value in entry.items()
                if include_source or key != "source"
            }
            for entry in entries[offset : offset + limit]
        ]

    def search(
        self, query: str, offset: int = 0, limit: int = 8, include_source: bool = False
    ) -> dict:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must be a nonempty string")
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 20
        ):
            raise ValueError("offset must be >= 0 and limit between 1 and 20")
        normalized = query.strip().casefold()
        tokens = [
            token for token in re.findall(r"\w+", normalized) if token not in _STOPWORDS
        ]
        tokens = tokens or [normalized]
        ranked = self._rank(self.entries, normalized, tokens)
        examples = self._rank(self.examples, normalized, tokens)
        return {
            "query": query,
            "domain_version": self.domain_version,
            "entries": self._page(ranked, offset, limit, include_source),
            "total": len(ranked),
            "next_offset": offset + limit if offset + limit < len(ranked) else None,
            "examples": self._page(examples, offset, limit, include_source),
            "examples_total": len(examples),
            "examples_next_offset": (
                offset + limit if offset + limit < len(examples) else None
            ),
            "idapython_documentation": "https://python.docs.hex-rays.com/",
            "domain_documentation": "https://ida-domain.docs.hex-rays.com/",
            "note": "Signatures reflect installed source. IDAPython SDK documentation is linked, not bundled.",
        }


@lru_cache(maxsize=1)
def get_reference_index() -> ReferenceIndex:
    roots = [Path(__file__).parent / "tools"]
    spec = importlib.util.find_spec("ida_domain")
    version = None
    if spec and spec.submodule_search_locations:
        roots.extend(Path(location) for location in spec.submodule_search_locations)
        try:
            version = importlib.metadata.version("ida-domain")
        except importlib.metadata.PackageNotFoundError:
            pass
    return ReferenceIndex(roots, domain_version=version)
