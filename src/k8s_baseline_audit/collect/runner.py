"""kubectl subprocess runner that refuses every non-read command."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

TIMEOUT_SECONDS = 120

# verb -> allowed first sub-argument (None = any)
_ALLOWED: dict[str, frozenset[str] | None] = {
    "get": None,
    "version": None,
    "api-resources": None,
    "auth": frozenset({"can-i"}),
    "config": frozenset({"current-context", "view"}),
}


class ForbiddenCommandError(Exception):
    """Raised before execution when a kubectl command is not read-only."""


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str


Exec = Callable[[Sequence[str]], CommandResult]


def _subprocess_exec(argv: Sequence[str]) -> CommandResult:
    try:
        proc = subprocess.run(
            list(argv), capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired:
        return CommandResult(tuple(argv), 124, "", f"timeout after {TIMEOUT_SECONDS}s")
    except FileNotFoundError:
        return CommandResult(tuple(argv), 127, "", "kubectl not found on PATH")
    return CommandResult(tuple(argv), proc.returncode, proc.stdout, proc.stderr)


def check_allowed(args: Sequence[str]) -> None:
    if not args:
        raise ForbiddenCommandError("empty kubectl command")
    verb = args[0]
    if verb not in _ALLOWED:
        raise ForbiddenCommandError(f"kubectl verb not allowed: {verb}")
    subs = _ALLOWED[verb]
    if subs is not None and (len(args) < 2 or args[1] not in subs):
        raise ForbiddenCommandError(f"kubectl {verb} subcommand not allowed: {list(args[1:2])}")


@dataclass
class KubectlRunner:
    context: str | None = None
    exec_fn: Exec = _subprocess_exec
    history: list[CommandResult] = field(default_factory=list)

    def run(self, *args: str) -> CommandResult:
        check_allowed(args)
        argv = ["kubectl"]
        if self.context:
            argv += ["--context", self.context]
        argv += list(args)
        result = self.exec_fn(argv)
        self.history.append(result)
        return result
