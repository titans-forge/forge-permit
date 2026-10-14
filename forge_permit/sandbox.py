# SPDX-License-Identifier: Apache-2.0
"""macOS Seatbelt feasibility backend; no fallback to unrestricted execution."""
from pathlib import Path
import json
import platform
import sys


class BackendUnavailable(RuntimeError):
    pass


def profile_for(worker_script: Path) -> str:
    if platform.system() != "Darwin":
        raise BackendUnavailable("macOS Seatbelt is required; Linux is not qualified")
    python = Path(sys.executable).resolve()
    libraries = Path(sys.base_prefix).resolve() / "lib"
    worker = worker_script.resolve(strict=True)
    if not libraries.is_dir():
        raise BackendUnavailable("Python runtime library directory unavailable")
    q = json.dumps
    return "\n".join([
        "(version 1)", "(deny default)",
        "(allow sysctl-read)",
        "(allow file-read-metadata)",
        "(allow file-read* "
        f"(literal {q(str(python))}) (literal {q(str(worker))}) (subpath {q(str(libraries))}) "
        '(subpath "/System/Library") (subpath "/usr/lib") '
        '(subpath "/System/Volumes/Preboot/Cryptexes/OS") '
        '(literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random"))',
    ])


def command(worker_script: Path, profile: str) -> list[str]:
    return [str(Path(sys.executable).resolve()), "-I", "-S", "-B",
            str(Path(__file__).with_name("bootstrap.py").resolve()), profile, str(worker_script.resolve())]
