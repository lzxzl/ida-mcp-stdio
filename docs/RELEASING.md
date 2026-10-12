# 发布

[English](RELEASING.en.md)

## 本地检查

发布版本同时记录在 `pyproject.toml`、包的 `__version__`、两份插件清单和 marketplace 清单。标签必须是 `v<版本>`，例如 `v0.5.0`。

发布工具需要 Python 3.11+；native 服务本身仍支持 Python 3.10+。

```sh
python3 -m pip install build twine
python3 scripts/check_release.py --tag v0.5.0
python3 -m build
python3 -m twine check --strict dist/*
python3 scripts/check_release.py --dist dist
```

`python -m build` 从 sdist 构建 wheel。检查器验证版本、包名、Python 下限，以及必需的模块和客户端资源文件。`dist` 必须只包含这次发布的一份 wheel 和一份 sdist。测试目录不随发布包分发；本地测试与实机验证见[验证范围](TESTING.md)。

## GitHub / PyPI

配置 PyPI Trusted Publisher：仓库 `lzxzl/ida-mcp-stdio`，工作流 `release.yml`，环境 `pypi`。在 GitHub 创建同名环境，并按需要设置发布审核。

发布非 prerelease 的 GitHub Release 后，[工作流](../.github/workflows/release.yml)按标签检出源码，校验并构建包，运行不加载 IDA 的握手检查，再通过 OIDC 上传到 PyPI。版本或包检查失败时不会进入上传作业。

工作流文件和本地构建成功不代表已经发布。只有 PyPI 上传完成后，才能使用下列包名安装方式：

```sh
uvx --from ida-mcp-stdio ida-mcp-server stdio
```

每次 GitHub Release 的标签应指向已验证的提交。默认安装器目前仍从 GitHub `main` 获取源码；已安装的 venv 使用 `update` 显式更新。
