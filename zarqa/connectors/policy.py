"""Which connector tools Zarqa may call.

Order of checks for a tool on a connector:
  1. ``deny`` list match -> blocked (always wins)
  2. ``allow`` list set and no match -> blocked
  3. tool is a response action (isolate, quarantine, kill, delete, disable,
     revoke, ...) or the server marks it destructive -> ALWAYS blocked on this
     path. No setting enables these for investigations. Zarqa takes no response
     actions at all.
  4. tool looks like it changes state -> blocked unless ``allow_write: true``
     AND the tool is named in ``allow`` explicitly.

Pushing intel to another platform (connectors with the ``sharing`` role) goes through
``decide_share`` instead: never offered to a model, only run by the sharing module.
"Looks like it changes state" uses the MCP ``readOnlyHint``/``destructiveHint``
annotations when the server sends them, otherwise the tool name. Hints come
from the server and are not proof, so a write-like NAME is blocked even if the
server says it is read-only.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

_WRITE_WORDS = (
    "delete", "remove", "create", "update", "write", "set", "add", "put", "post", "patch",
    "isolate", "contain", "quarantine", "block", "unblock", "kill", "stop", "start", "restart",
    "disable", "enable", "reset", "revoke", "send", "execute", "exec", "run", "install",
    "uninstall", "upload", "modify", "edit", "approve", "close", "assign", "ban", "purge",
)
# Response actions and destructive operations. Blocked whatever the config says.
_NEVER_WORDS = (
    "isolate", "unisolate", "contain", "quarantine", "kill", "terminate", "delete", "remove", "purge",
    "wipe", "erase", "destroy", "drop", "truncate", "disable", "revoke", "ban", "block", "unblock",
    "uninstall", "shutdown", "reboot", "restart", "suspend", "lock", "unlock", "reset", "rollback",
    "remediate",
)
_WORD_RE = re.compile(r"[a-z]+")


def _words(name: str) -> list[str]:
    # split camelCase, snake_case, kebab-case
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    return _WORD_RE.findall(spaced.lower())


def looks_write(tool: dict[str, Any]) -> bool:
    if any(w in _WRITE_WORDS for w in _words(str(tool.get("name", "")))):
        return True
    ann = tool.get("annotations") or {}
    if ann.get("destructiveHint") is True:
        return True
    return ann.get("readOnlyHint") is False


def is_never(tool: dict[str, Any]) -> bool:
    """A response or destructive action that no configuration may allow."""
    if any(w in _NEVER_WORDS for w in _words(str(tool.get("name", "")))):
        return True
    return (tool.get("annotations") or {}).get("destructiveHint") is True


def _match(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def decide(spec, tool: dict[str, Any]) -> tuple[bool, str]:
    """Return (allowed, reason)."""
    name = str(tool.get("name", ""))
    if _match(name, spec.deny):
        return False, "denied by the connector's deny list"
    if spec.allow and not _match(name, spec.allow):
        return False, "not on the connector's allow list"
    if is_never(tool):
        return False, "response or destructive action; Zarqa never calls these, whatever the config says"
    if looks_write(tool):
        if set(getattr(spec, "roles", []) or []) & {"sharing", "ticketing"}:
            return False, "may change state; sharing and ticketing tools run only from the sharing module"
        if not spec.allow_write:
            return False, "may change state; connectors are read-only unless allow_write is set"
        if name not in spec.allow:
            return False, "may change state; write tools must be named exactly in the allow list"
    return True, "allowed"


# Destructive operations: not even an approved response action may call these.
_DESTRUCTIVE_WORDS = (
    "delete", "remove", "purge", "wipe", "erase", "destroy", "drop", "truncate", "format", "uninstall",
    "shutdown", "reboot", "rollback", "overwrite",
)


def is_destructive(tool: dict[str, Any]) -> bool:
    """Data-destroying or service-stopping operations: never allowed, approved or not."""
    return any(w in _DESTRUCTIVE_WORDS for w in _words(str(tool.get("name", ""))))


def decide_share(spec, tool: dict[str, Any]) -> tuple[bool, str]:
    """May this tool be used to PUSH intel to another platform? Needs the ``sharing`` role,
    ``allow_write: true`` and the tool named exactly in ``allow``; the deny list still wins, and
    destructive or response tools are refused whatever the config says."""
    name = str(tool.get("name", ""))
    if _match(name, spec.deny):
        return False, "denied by the connector's deny list"
    if "sharing" not in spec.roles:
        return False, "the connector does not have the sharing role"
    if is_destructive(tool) or is_never(tool):
        return False, "destructive or response operation; never run"
    if not spec.allow_write:
        return False, "sharing needs allow_write: true on the connector"
    if name not in spec.allow:
        return False, "sharing tools must be named exactly in tools.allow"
    return True, "allowed sharing tool"
