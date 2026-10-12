"""Plan and invoke the official HCLI installer for the Nexus GUI provider.

Planning only reads local files. Executing a plan may create IDA's virtualenv,
configure its login environment, install Python dependencies and write plugins.
HCLI owns those changes; a failed command does not imply they were rolled back.
The GUI's IDAPython interpreter is independent of the stdio server interpreter.
"""

from __future__ import annotations

import json
import math
import os
import plistlib
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

OFFICIAL_GUI_PLUGIN = "ida-mcp@https://github.com/HexRaysSA/ida-mcp"


@dataclass(frozen=True)
class GuiInstallPlan:
    hcli: Path
    ida_dir: Path
    ida_user_dir: Path
    ida_python: Path | None
    environment: Path | None
    create_environment: bool
    configure_environment: bool
    commands: tuple[tuple[str, ...], ...]
    timeout: float
    platform: str
    configuration_files: tuple[Path, ...] = ()
    allow_missing_hcli: bool = False


@dataclass(frozen=True)
class GuiInstallResult:
    plan: GuiInstallPlan
    dry_run: bool
    completed_commands: tuple[tuple[str, ...], ...] = ()
    doctor: dict | None = None
    environment_report: dict | None = None


class GuiInstallError(RuntimeError):
    """An external failure, including commands completed before that failure."""

    def __init__(
        self,
        message: str,
        *,
        command: tuple[str, ...],
        completed_commands: tuple[tuple[str, ...], ...],
        returncode: int | None = None,
        stdout: str = "",
        stderr: str = "",
        may_have_changes: bool = False,
    ):
        super().__init__(message)
        self.command = command
        self.completed_commands = completed_commands
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.may_have_changes = may_have_changes


def _absolute(path: str | Path) -> Path:
    # Keep venv interpreter symlinks, which select the virtual environment.
    return Path(os.path.abspath(Path(path).expanduser()))


def _executable(path: Path, label: str, platform: str) -> None:
    if platform == "win32" and path.suffix.lower() in {".bat", ".cmd"}:
        raise ValueError(f"{label} must be an executable, not a shell script: {path}")
    if not path.is_file() or (platform != "win32" and not os.access(path, os.X_OK)):
        raise ValueError(f"{label} is not an executable file: {path}")


def _mutation_directory(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            if (
                sys.platform == "darwin"
                and str(candidate) in {"/tmp", "/var"}
                and str(candidate.resolve()) == "/private" + str(candidate)
            ):
                continue
            raise ValueError(f"Refusing symlinked GUI install destination: {candidate}")
        if candidate.exists() and not candidate.is_dir():
            raise ValueError(f"GUI install destination is not a directory: {candidate}")


def _ida_directory(path: str | Path, platform: str) -> Path:
    directory = _absolute(path)
    if (
        platform == "darwin"
        and directory.name == "MacOS"
        and directory.parent.name == "Contents"
    ):
        directory = directory.parent.parent
    contents = directory / "Contents" / "MacOS"
    binaries = contents if platform == "darwin" and contents.is_dir() else directory
    if not binaries.is_dir():
        raise ValueError(f"IDA directory does not exist: {directory}")
    names = ("idat.exe", "idat64.exe") if platform == "win32" else ("idat", "idat64")
    if not any(
        (binaries / name).is_file()
        and (platform == "win32" or os.access(binaries / name, os.X_OK))
        for name in names
    ):
        raise ValueError(f"IDA directory has no idat executable: {directory}")
    version = None
    sdk = binaries / "python" / "ida_pro.py"
    if sdk.is_file():
        version = re.search(r"IDA SDK v(\d+)\.(\d+)", sdk.read_text(encoding="utf-8"))
    if version is None and platform == "darwin":
        info = directory / "Contents" / "Info.plist"
        if info.is_file():
            try:
                with info.open("rb") as handle:
                    metadata = plistlib.load(handle)
                value = metadata.get("CFBundleShortVersionString", "")
                version = re.match(r"(\d+)\.(\d+)", str(value))
            except (ValueError, plistlib.InvalidFileException) as exc:
                raise ValueError(f"Invalid IDA version metadata: {info}") from exc
    if version is None:
        raise ValueError(
            f"Cannot determine IDA version from local SDK or application metadata: {directory}"
        )
    if tuple(map(int, version.groups())) < (9, 4):
        raise ValueError(
            "The official Nexus GUI plugin requires IDA >=9.4; native supports IDA 9.2"
        )
    return directory


def _environment_python(environment: Path, platform: str) -> Path:
    return environment / ("Scripts/python.exe" if platform == "win32" else "bin/python")


def _interpreter(python: Path, platform: str) -> None:
    _executable(python, "GUI Python interpreter", platform)
    configuration = python.parent.parent / "pyvenv.cfg"
    if (
        python.parent.name.lower() != ("scripts" if platform == "win32" else "bin")
        or not configuration.is_file()
    ):
        raise ValueError(
            f"GUI Python interpreter must belong to a virtual environment: {python}"
        )
    version = re.search(
        r"(?m)^\s*version\s*=\s*(\d+)\.(\d+)", configuration.read_text(encoding="utf-8")
    )
    if version and tuple(map(int, version.groups())) < (3, 11):
        raise ValueError("The official Nexus GUI plugin requires Python >=3.11")


def _default_user_directory(platform: str) -> Path:
    if os.environ.get("HCLI_IDAUSR"):
        return _absolute(os.environ["HCLI_IDAUSR"])
    if os.environ.get("IDAUSR"):
        separator = ";" if platform == "win32" else ":"
        return _absolute(os.environ["IDAUSR"].split(separator)[0])
    if platform == "win32":
        if not os.environ.get("APPDATA"):
            raise ValueError("Pass an IDA user directory when APPDATA is unavailable")
        return _absolute(Path(os.environ["APPDATA"]) / "Hex-Rays" / "IDA Pro")
    return _absolute(Path.home() / ".idapro")


def _configuration_files(platform: str) -> tuple[Path, ...]:
    if platform == "win32":
        return ()  # HCLI uses the user environment registry via PowerShell.
    home = _absolute(Path.home())
    files = []
    if platform == "darwin":
        files.append(
            home / "Library/LaunchAgents/com.hex-rays.idapython-venv-executable.plist"
        )
    elif platform == "linux":
        files.append(
            home / ".config/environment.d/50-hexrays-idapython-venv-executable.conf"
        )
    shell = Path(os.environ.get("SHELL", "")).name
    profile = {
        "zsh": ".zprofile",
        "bash": ".bash_profile",
        "sh": ".profile",
        "fish": ".config/fish/config.fish",
    }.get(shell)
    if profile:
        files.append(home / profile)
    return tuple(files)


def _configuration_file(path: Path) -> None:
    _mutation_directory(path.parent)
    if path.is_symlink():
        raise ValueError(f"Refusing symlinked GUI login configuration: {path}")
    if path.exists() and not path.is_file():
        raise ValueError(f"GUI login configuration is not a file: {path}")


def plan_gui_install(
    *,
    ida_dir: str | Path,
    hcli: str | Path = "hcli",
    ida_user_dir: str | Path | None = None,
    ida_python: str | Path | None = None,
    create_environment: bool = False,
    environment: str | Path | None = None,
    configure_environment: bool = True,
    timeout: float = 300,
    platform: str | None = None,
    allow_missing_hcli: bool = False,
) -> GuiInstallPlan:
    """Validate local inputs and return exact HCLI argv without running it.

    ``create_environment`` explicitly permits HCLI to create and configure the
    GUI's Python environment. Set ``configure_environment=False`` to create only;
    IDA must then be launched with IDAPYTHON_VENV_EXECUTABLE selecting that venv.
    An explicit ``ida_python`` must be an existing venv; HCLI doctor checks its
    real Python version, pip availability and IDA's embedded Python compatibility.
    ``allow_missing_hcli`` permits an explicit absolute future executable while
    planning an environment install; execution still requires that executable.
    """
    platform = platform or sys.platform
    if platform not in {"darwin", "linux", "win32"}:
        raise ValueError(f"Unsupported GUI install platform: {platform}")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("GUI command timeout must be finite and positive")
    if create_environment and ida_python is not None:
        raise ValueError(
            "Choose GUI environment creation or an existing GUI Python interpreter"
        )
    if environment is not None and not create_environment:
        raise ValueError("A GUI environment path requires create_environment")
    directory = _ida_directory(ida_dir, platform)
    user_directory = (
        _absolute(ida_user_dir)
        if ida_user_dir is not None
        else _default_user_directory(platform)
    )
    _mutation_directory(user_directory / "plugins")
    hcli_value = str(hcli)
    if allow_missing_hcli and not Path(hcli_value).is_absolute():
        raise ValueError("A future HCLI executable requires an explicit absolute path")
    candidate = (
        shutil.which(hcli_value)
        if not Path(hcli_value).is_absolute() and len(Path(hcli_value).parts) == 1
        else hcli_value
    )
    if not candidate:
        raise ValueError(
            "HCLI is unavailable; install ida-hcli or pass its executable path"
        )
    hcli_path = _absolute(candidate)
    if allow_missing_hcli and not hcli_path.exists():
        if hcli_path.is_symlink():
            raise ValueError(f"Refusing symlinked future HCLI executable: {hcli_path}")
        _mutation_directory(hcli_path.parent)
        if platform == "win32" and hcli_path.suffix.lower() in {".bat", ".cmd"}:
            raise ValueError("Future HCLI must be an executable, not a shell script")
    else:
        _executable(hcli_path, "HCLI", platform)
    selected = ida_python
    if selected is None and not create_environment:
        selected = os.environ.get("IDAPYTHON_VENV_EXECUTABLE") or None
    python = _absolute(selected) if selected is not None else None
    environment_path = None
    configuration_files = ()
    prefix = (str(hcli_path), "--disable-updates")
    commands = []
    if create_environment:
        environment_path = (
            _absolute(environment)
            if environment is not None
            else user_directory / "venv"
        )
        _mutation_directory(environment_path)
        if configure_environment:
            # HCLI 0.26 renders this value directly into quoted shell exports,
            # XML and PowerShell. These characters cannot be persisted safely.
            if any(character in str(environment_path) for character in '"$`&<>\r\n'):
                raise ValueError(
                    "GUI environment path cannot be safely persisted to login configuration; use a plain path or disable configuration"
                )
            configuration_files = _configuration_files(platform)
            for configuration_file in configuration_files:
                _configuration_file(configuration_file)
        python = _environment_python(environment_path, platform)
        if environment_path.exists():
            _interpreter(python, platform)
        create = (
            *prefix,
            "ida",
            "python",
            "create-environment",
            "--path",
            str(environment_path),
            "--no-reinstall-plugins",
            "--json",
        )
        if not configure_environment:
            create = (*create, "--no-configure-env-var")
        commands.append(create)
    elif python is not None:
        _interpreter(python, platform)
    commands.extend(
        [
            (*prefix, "ida", "python", "doctor", "--json"),
            (*prefix, "plugin", "install", "--upgrade", OFFICIAL_GUI_PLUGIN),
        ]
    )
    return GuiInstallPlan(
        hcli_path,
        directory,
        user_directory,
        python,
        environment_path,
        create_environment,
        configure_environment,
        tuple(commands),
        timeout,
        platform,
        configuration_files,
        allow_missing_hcli,
    )


def _subprocess_environment(plan: GuiInstallPlan, *, creating: bool) -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "HCLI_CURRENT_IDA_VERSION",
        "HCLI_CURRENT_IDA_PLATFORM",
        "HCLI_CURRENT_IDA_PYTHON_EXE",
        "IDAPYTHON_VENV_EXECUTABLE",
        "PIP_TARGET",
        "PIP_PREFIX",
        "PIP_USER",
        "PIP_ROOT",
        "PIP_PYTHON",
        "PYTHONHOME",
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "UV_PROJECT_ENVIRONMENT",
        "UV_PYTHON",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "HCLI_DISABLE_UPDATES": "1",
            "HCLI_CURRENT_IDA_INSTALL_DIR": str(plan.ida_dir),
            "HCLI_IDAUSR": str(plan.ida_user_dir),
            "IDAUSR": str(plan.ida_user_dir),
            "PIP_CONFIG_FILE": os.devnull,
        }
    )
    if plan.ida_python is not None and not creating:
        environment["HCLI_CURRENT_IDA_PYTHON_EXE"] = str(plan.ida_python)
        environment["IDAPYTHON_VENV_EXECUTABLE"] = str(plan.ida_python)
    return environment


def _output(value: str | bytes | None) -> str:
    return (
        value.decode("utf-8", errors="replace")
        if isinstance(value, bytes)
        else value or ""
    )


def execute_gui_install(
    plan: GuiInstallPlan, *, dry_run: bool = False, runner: Callable | None = None
) -> GuiInstallResult:
    """Execute after caller validation, or return a side-effect-free dry run.

    Callers must plan and validate all client configuration before this function.
    A GuiInstallError records completed actions and possible partial HCLI writes.
    Captured HCLI output is never sent to an MCP protocol's stdout.
    """
    # Recheck local inputs in case they changed after planning.
    _ida_directory(plan.ida_dir, plan.platform)
    if not (dry_run and plan.allow_missing_hcli and not plan.hcli.exists()):
        _executable(plan.hcli, "HCLI", plan.platform)
    if plan.ida_python is not None and (
        not plan.create_environment
        or (plan.environment is not None and plan.environment.exists())
    ):
        _interpreter(plan.ida_python, plan.platform)
    _mutation_directory(plan.ida_user_dir / "plugins")
    if plan.environment is not None:
        _mutation_directory(plan.environment)
    for configuration_file in plan.configuration_files:
        _configuration_file(configuration_file)
    if dry_run:
        return GuiInstallResult(plan, True)
    completed: list[tuple[str, ...]] = []
    changed = False
    doctor = None
    environment_report = None
    execution_plan = plan
    for command in plan.commands:
        creating = "create-environment" in command
        mutating = creating or "install" in command
        try:
            process = (runner or subprocess.run)(
                list(command),
                shell=False,
                check=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=plan.timeout,
                env=_subprocess_environment(execution_plan, creating=creating),
            )
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            OSError,
        ) as exc:
            timed_out = isinstance(exc, subprocess.TimeoutExpired)
            reason = f"timed out after {plan.timeout:g}s" if timed_out else str(exc)
            raise GuiInstallError(
                (
                    f"HCLI {reason}; external changes may remain"
                    if changed or (mutating and not isinstance(exc, OSError))
                    else f"HCLI {reason}"
                ),
                command=command,
                completed_commands=tuple(completed),
                returncode=getattr(exc, "returncode", None),
                stdout=_output(getattr(exc, "stdout", None)),
                stderr=_output(getattr(exc, "stderr", None)),
                may_have_changes=changed or (mutating and not isinstance(exc, OSError)),
            ) from exc
        if process.returncode:
            raise GuiInstallError(
                f"HCLI exited with status {process.returncode}"
                + ("; external changes may remain" if changed or mutating else ""),
                command=command,
                completed_commands=tuple(completed),
                returncode=process.returncode,
                stdout=_output(process.stdout),
                stderr=_output(process.stderr),
                may_have_changes=changed or mutating,
            )
        if creating:
            try:
                environment_report = json.loads(process.stdout)
                if not isinstance(environment_report, dict):
                    raise ValueError("environment creation did not return an object")
                if (
                    plan.configure_environment
                    and environment_report.get("configured") is not True
                ):
                    raise ValueError("HCLI did not configure the GUI login environment")
                if _absolute(environment_report["venv_path"]) != plan.environment:
                    raise ValueError(
                        "HCLI created a different environment than requested"
                    )
                actual_python = _absolute(environment_report["python_exe"])
                if actual_python.parent.parent != plan.environment:
                    raise ValueError(
                        "HCLI selected an interpreter outside the requested environment"
                    )
                _mutation_directory(plan.environment)
                _interpreter(actual_python, plan.platform)
                execution_plan = replace(plan, ida_python=actual_python)
            except (ValueError, TypeError, KeyError, OSError) as exc:
                raise GuiInstallError(
                    f"Invalid HCLI environment creation report: {exc}",
                    command=command,
                    completed_commands=tuple(completed),
                    stdout=_output(process.stdout),
                    stderr=_output(process.stderr),
                    may_have_changes=True,
                ) from exc
        if "doctor" in command:
            try:
                doctor = json.loads(process.stdout)
                if not isinstance(doctor, dict) or doctor.get("ok") is not True:
                    raise ValueError("IDAPython environment check was not successful")
                for field, minimum in (
                    ("ida_version", (9, 4)),
                    ("python_version", (3, 11)),
                ):
                    version = re.match(r"(\d+)\.(\d+)", str(doctor.get(field, "")))
                    if version is None or tuple(map(int, version.groups())) < minimum:
                        raise ValueError(
                            f"HCLI reported unsupported {field}: {doctor.get(field)!r}"
                        )
            except (ValueError, TypeError) as exc:
                raise GuiInstallError(
                    f"Invalid HCLI doctor report: {exc}",
                    command=command,
                    completed_commands=tuple(completed),
                    stdout=_output(process.stdout),
                    stderr=_output(process.stderr),
                    may_have_changes=changed,
                ) from exc
        completed.append(command)
        changed = changed or mutating
    return GuiInstallResult(plan, False, tuple(completed), doctor, environment_report)
