# Releases

[中文](RELEASING.md)

## Local checks

Synchronize `pyproject.toml`, the package `__version__`, both plugin manifests and the marketplace catalog. The tag must be `v<version>`, such as `v0.5.0`.

Release tooling requires Python 3.11+; the native server still supports Python 3.10+.

```sh
python3 -m pip install build twine
python3 scripts/check_release.py --tag v0.5.0
python3 -m build
python3 -m twine check --strict dist/*
python3 scripts/check_release.py --dist dist
```

`python -m build` builds the wheel from the sdist. The checker validates versions, package name, Python floor and required module/client resource files. `dist` must contain exactly this release's wheel and sdist. Tests stay local and are excluded from distributions; see [validation scope](TESTING.en.md).

## GitHub / PyPI

Configure a PyPI Trusted Publisher for repository `lzxzl/ida-mcp-stdio`, workflow `release.yml`, and environment `pypi`. Create that GitHub environment and configure release review if desired.

Publishing a non-prerelease GitHub Release starts the [workflow](../.github/workflows/release.yml). It checks out the tag, validates and builds packages, checks a handshake without loading IDA, then uploads through OIDC. Failed version or package checks prevent the upload job.

Having a workflow file or a successful local build does not mean the package was published. Use the package-name command only after a successful PyPI upload:

```sh
uvx --from ida-mcp-stdio ida-mcp-server stdio
```

Release tags should identify tested commits. The installer still uses GitHub `main` by default, and installed venvs update explicitly through `update`.
