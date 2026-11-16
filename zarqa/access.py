"""Who is asking, and which data sources they may use and see.

A connector can list who may use it::

    connectors:
      - name: mail
        roles: [email]
        access: [insider-threat, "role:admin", "user:jdoe"]   # group names, role:<role>, user:<name>

No ``access`` (the default) means everyone. Admins can use every connector.

The caller is held in a context variable: the web guard sets it per request,
and jobs started from a request inherit it (the job runner copies the context),
so an investigation runs with the permissions of whoever started it. Scheduled and
command-line work has no caller and sees everything.

An investigation that called a connector with ``access`` is *restricted* to the people
who may use those connectors: other people cannot list or open it, its lead,
reports, chat or exports, and it is left out of other people's memory.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass, field

ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


@dataclass(frozen=True)
class Access:
    user: str = ""
    role: str = "viewer"
    groups: tuple[str, ...] = ()
    connectors: frozenset[str] | None = None     # None: every connector
    restricted_names: frozenset[str] = field(default_factory=frozenset)

    def to_dict(self) -> dict:
        return {"user": self.user, "role": self.role, "groups": list(self.groups),
                "connectors": None if self.connectors is None else sorted(self.connectors),
                "restricted_names": sorted(self.restricted_names)}

    @classmethod
    def from_dict(cls, d: dict) -> Access:
        c = d.get("connectors")
        return cls(user=str(d.get("user", "")), role=str(d.get("role", "viewer")), groups=tuple(d.get("groups") or ()),
                   connectors=None if c is None else frozenset(c),
                   restricted_names=frozenset(d.get("restricted_names") or ()))

    def public(self) -> dict:
        return {"user": self.user, "role": self.role, "groups": list(self.groups),
                "connectors": None if self.connectors is None else sorted(self.connectors)}


_current: contextvars.ContextVar[Access | None] = contextvars.ContextVar("zarqa_access", default=None)


def current() -> Access | None:
    return _current.get()


def set_current(a: Access | None):
    return _current.set(a)


def reset(token) -> None:
    _current.reset(token)


def matches(entry: str, user: str, role: str, groups) -> bool:
    e = str(entry).strip()
    if e.startswith("role:"):
        want = e[5:].strip().lower()
        return want in ROLE_RANK and ROLE_RANK.get(role, -1) >= ROLE_RANK[want]
    if e.startswith("user:"):
        return bool(user) and e[5:].strip().lower() == str(user).lower()
    return e in set(groups or ())


def build(specs, *, user: str, role: str, groups=()) -> Access:
    """The Access for this caller over these connector specs (an iterable of ConnectorSpec)."""
    specs = list(specs)
    restricted = frozenset(s.name for s in specs if getattr(s, "access", None))
    groups = tuple(sorted({str(g) for g in groups or () if str(g).strip()}))
    if role == "admin" or not restricted:
        return Access(user=user, role=role, groups=groups, connectors=None, restricted_names=restricted)
    allowed = frozenset(s.name for s in specs
                        if not getattr(s, "access", None) or any(matches(e, user, role, groups) for e in s.access))
    return Access(user=user, role=role, groups=groups, connectors=allowed, restricted_names=restricted)


def can_use(connector: str) -> bool:
    a = current()
    return a is None or a.connectors is None or connector in a.connectors


def can_see(restricted) -> bool:
    """May the current caller see a record that used these restricted connectors?"""
    a = current()
    if a is None or a.connectors is None or not restricted:
        return True
    return set(restricted) <= set(a.connectors)


def scheduler_access(cfg) -> Access | None:
    """The identity the scheduler's own work (feed pulls, watches, scheduled investigations) runs as.

        scheduler:
          groups: [intel-automation]     # connector access lists are matched against these
          role: operator

    Without a ``scheduler`` section it runs with no person behind it and may use every connector
    (what it reads from restricted sources is then restricted like any investigation). Saved investigations always
    run as the person who saved them."""
    s = ((getattr(cfg, "raw", None) or {}).get("scheduler") or {})
    if not s:
        return None
    from .connectors.spec import parse_connectors
    try:
        specs = parse_connectors(list(getattr(cfg, "connectors", None) or []))
    except Exception:
        specs = []
    role = str(s.get("role", "operator")).lower()
    if role not in ROLE_RANK:
        raise ValueError("scheduler.role must be viewer, operator or admin")
    groups = s.get("groups") or []
    if not isinstance(groups, list):
        raise ValueError("scheduler.groups must be a list")
    return build(specs, user=str(s.get("user", "scheduler")), role=role, groups=groups)


def run_as(a: Access | None, fn, *args, **kw):
    tok = set_current(a)
    try:
        return fn(*args, **kw)
    finally:
        reset(tok)
