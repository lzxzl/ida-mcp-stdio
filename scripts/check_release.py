"""Check source and distribution versions before an external release upload."""

from __future__ import annotations

import argparse
import ast
import json
import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path

import tomllib


def source_version(root: Path) -> str:
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    version = project["version"]
    module = ast.parse((root / "src/ida_mcp_stdio/__init__.py").read_text())
    source = next(
        ast.literal_eval(node.value)
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in node.targets
        )
    )
    if source != version:
        raise ValueError(
            f"package source version {source} differs from project version {version}"
        )
    for path in (".claude-plugin/plugin.json", ".codex-plugin/plugin.json"):
        manifest = json.loads((root / path).read_text())
        if manifest["version"] != version:
            raise ValueError(f"{path} version differs from project version {version}")
    marketplace = json.loads((root / ".claude-plugin/marketplace.json").read_text())
    if marketplace["plugins"][0]["version"] != version:
        raise ValueError(f"marketplace version differs from project version {version}")
    return version


def check_metadata(data: bytes, version: str, kind: str) -> None:
    metadata = BytesParser().parsebytes(data)
    if metadata["Name"] != "ida-mcp-stdio":
        raise ValueError(f"{kind} name is not ida-mcp-stdio")
    if metadata["Version"] != version:
        raise ValueError(f"{kind} version {metadata['Version']} differs from {version}")
    if metadata["Requires-Python"] != ">=3.10":
        raise ValueError(f"{kind} Requires-Python must be >=3.10")


def check_dist(directory: Path, version: str) -> None:
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("dist must contain exactly one wheel and one sdist")
    with zipfile.ZipFile(wheels[0]) as wheel:
        metadata_paths = [
            path for path in wheel.namelist() if path.endswith(".dist-info/METADATA")
        ]
        if len(metadata_paths) != 1:
            raise ValueError("wheel must contain exactly one METADATA")
        check_metadata(wheel.read(metadata_paths[0]), version, "wheel")
        required = {
            "ida_mcp_stdio/__init__.py",
            "ida_mcp_stdio/__main__.py",
            "ida_mcp_stdio/benchmark.py",
            "ida_mcp_stdio/assets/opencode-session.js",
        }
        missing = sorted(required.difference(wheel.namelist()))
        if missing:
            raise ValueError("wheel is missing release assets: " + ", ".join(missing))
    with tarfile.open(sdists[0], "r:gz") as sdist:
        members = sdist.getmembers()
        roots = {Path(member.name).parts[0] for member in members}
        if len(roots) != 1:
            raise ValueError("sdist must have exactly one root directory")
        prefix = next(iter(roots)) + "/"
        required = {
            "PKG-INFO",
            "pyproject.toml",
            "README.md",
            "README.en.md",
            "LICENSE",
            "src/ida_mcp_stdio/__main__.py",
            "src/ida_mcp_stdio/benchmark.py",
            "src/ida_mcp_stdio/assets/opencode-session.js",
            ".claude-plugin/plugin.json",
            ".claude-plugin/marketplace.json",
            ".codex-plugin/plugin.json",
            ".codex-plugin/mcp.json",
            ".codex-plugin/hooks.json",
            "scripts/plugin_launcher.py",
            "scripts/check_release.py",
            "plugin-skills/ida-analysis/SKILL.md",
            "plugin-skills/ida-analysis/SKILL.en.md",
        }
        names = {member.name for member in members if member.isfile()}
        missing = sorted(path for path in required if prefix + path not in names)
        if missing:
            raise ValueError("sdist is missing release assets: " + ", ".join(missing))
        metadata = sdist.extractfile(prefix + "PKG-INFO")
        if metadata is None:
            raise ValueError("sdist PKG-INFO must be a regular file")
        check_metadata(metadata.read(), version, "sdist")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--tag", help="Git release tag, exactly v<package version>")
    parser.add_argument("--dist", type=Path, help="Built wheel and sdist directory")
    args = parser.parse_args(argv)
    try:
        version = source_version(args.root)
        if args.tag is not None and args.tag != "v" + version:
            raise ValueError(f"release tag {args.tag!r} must equal v{version}")
        if args.dist is not None:
            check_dist(args.dist, version)
    except (
        OSError,
        ValueError,
        KeyError,
        StopIteration,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"release check: {exc}", file=sys.stderr)
        return 1
    print(f"Release checks passed for {version}; no files were published.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
