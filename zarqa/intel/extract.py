"""Pull indicators and ATT&CK technique IDs out of free text (advisories, emails, notes).

Handles common defanging: hxxp, [.], (.), {.}, [:], [at]. Pattern-based, so it
can miss indicators or pick up false ones; review before trusting.
"""

from __future__ import annotations

import ipaddress
import re

TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "cve", "technique")

_FILE_EXT = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "zip", "rar", "7z", "gz", "tar", "iso", "img",
    "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "rtf", "txt", "log", "csv", "json", "xml", "html",
    "htm", "php", "asp", "aspx", "jsp", "png", "jpg", "jpeg", "gif", "svg", "lnk", "msi", "hta", "py", "sh", "bin",
    "dat", "tmp", "ini", "cfg", "conf", "yaml", "yml", "md", "so", "elf", "apk", "dmg", "pkg", "one", "local",
}

_RE = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`)\]]+", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"),
    "ipv4": re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d|\.\d)"),
    "ipv6": re.compile(r"(?<![:\w.])(?=[0-9a-fA-F:]*:[0-9a-fA-F]*:)[0-9a-fA-F:]{2,39}(?![:\w])"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "technique": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "domain": re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"),
}


def refang(text: str) -> str:
    t = re.sub(r"\bhxxp(s?)", r"http\1", text, flags=re.I)
    t = re.sub(r"\bfxp\b", "ftp", t, flags=re.I)
    t = re.sub(r"\s?[\[\(\{]\s?(?:\.|dot)\s?[\]\)\}]\s?", ".", t, flags=re.I)
    t = re.sub(r"[\[\(\{]:[\]\)\}]", ":", t)
    t = re.sub(r"\s?[\[\(\{]\s?(?:@|at)\s?[\]\)\}]\s?", "@", t, flags=re.I)
    return t.replace("[://]", "://")


def normalize(kind: str, value: str) -> str:
    v = value.strip()
    if kind in ("domain", "email", "md5", "sha1", "sha256"):
        return v.lower().rstrip(".")
    if kind == "cve":
        return v.upper()
    if kind == "ipv6":
        try:
            return str(ipaddress.IPv6Address(v))
        except ValueError:
            return v.lower()
    if kind == "url":
        return v.rstrip(".,;")
    return v


def guess_type(value: str) -> str | None:
    """Type of a single value, or None if it does not look like an indicator."""
    v = refang(value.strip())
    for kind in ("url", "email", "cve", "technique", "sha256", "sha1", "md5", "ipv4", "ipv6", "domain"):
        m = _RE[kind].fullmatch(v)
        if not m or (kind == "domain" and not _ok_domain(v)):
            continue
        if kind == "ipv6" and not _is_v6(v):
            continue
        return kind
    return None


def _is_v6(v: str) -> bool:
    try:
        return not ipaddress.IPv6Address(v).is_unspecified
    except ValueError:
        return False


def _ok_domain(d: str) -> bool:
    tld = d.rsplit(".", 1)[-1].lower()
    return tld not in _FILE_EXT and not d.replace(".", "").isdigit()


def extract(text: str) -> dict[str, list[str]]:
    """Return ``{type: [values]}`` found in ``text`` (deduplicated, in order)."""
    t = refang(text or "")
    out: dict[str, list[str]] = {k: [] for k in TYPES}
    seen: set[tuple[str, str]] = set()
    taken: list[tuple[int, int]] = []

    def add(kind: str, raw: str, span: tuple[int, int]) -> None:
        v = normalize(kind, raw)
        if (kind, v) in seen:
            return
        seen.add((kind, v))
        out[kind].append(v)
        taken.append(span)

    def inside(span):
        return any(a <= span[0] and span[1] <= b for a, b in taken)

    for kind in ("url", "email", "cve", "technique", "sha256", "sha1", "md5", "ipv4", "ipv6"):
        for m in _RE[kind].finditer(t):
            if inside(m.span()):
                continue
            if kind == "ipv6" and not _is_v6(m.group(0)):
                continue
            add(kind, m.group(0), m.span())
    for m in _RE["domain"].finditer(t):
        if not inside(m.span()) and _ok_domain(m.group(0)):
            add("domain", m.group(0), m.span())
    # the host of each URL is also worth hunting
    for u in list(out["url"]):
        host = re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split(":")[0].split("@")[-1]
        k = guess_type(host)
        if k in ("domain", "ipv4") and normalize(k, host) not in out[k]:
            out[k].append(normalize(k, host))
    # and the domain of each email address
    for e in list(out["email"]):
        d = e.split("@", 1)[1]
        if _ok_domain(d) and d not in out["domain"]:
            out["domain"].append(d)
    return {k: v for k, v in out.items() if v}


# ---- filtering and context ------------------------------------------------

_NON_ROUTABLE = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]
LINK_TYPES = ("domain", "url", "email")


def _routable(kind: str, v: str) -> bool:
    host = v
    if kind == "url":
        from urllib.parse import urlparse
        try:
            host = urlparse(v).hostname or ""
        except ValueError:          # "http://[broken": not a usable address
            return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved
                or any(ip in n for n in _NON_ROUTABLE if n.version == ip.version))


def _host(kind: str, v: str) -> str:
    from urllib.parse import urlparse
    try:
        h = (urlparse(v).hostname or "") if kind == "url" else v.split("@")[-1]
    except ValueError:
        return ""
    return h.lower().removeprefix("www.")


def indicators(text: str, *, url: str = "", strict_links: bool = False,
               ignore_domains: list[str] | None = None) -> tuple[dict[str, list[str]], list[str]]:
    """Indicators worth keeping from ``text``, and the values dropped (with the reason).

    - Private, loopback, link-local and reserved addresses are never indicators: in a write-up they are
      examples, lab addresses or a victim's internal hosts.
    - The publisher's own domain (from ``url``) and ``ignore_domains`` are never kept.
    - ``strict_links``: domains, URLs and emails are kept only if the text defanged them (hxxp, [.]),
      which is how reports mark real indicators; plain links in an article are usually references.
      IPs and hashes are unaffected.
    """
    found = extract(text)
    dropped: list[str] = []
    own = _host("url", url) if url else ""
    skip = [d.lower().removeprefix("www.") for d in ignore_domains or [] if d]
    low = (text or "").lower()

    def keep(kind: str, v: str) -> bool:
        if not _routable(kind, v):
            dropped.append(f"{v}: not a public address")
            return False
        if kind in LINK_TYPES:
            host = _host(kind, v)
            for d in ([own] if own else []) + skip:
                if host == d or host.endswith("." + d):
                    dropped.append(f"{v}: publisher or ignored domain")
                    return False
            if strict_links and v.lower() in low:
                dropped.append(f"{v}: plain link, not defanged")
                return False
        return True
    out = {k: [v for v in vals if (k in ("cve", "technique") or keep(k, v))] for k, vals in found.items()}
    return {k: v for k, v in out.items() if v}, dropped


_SENT_END = re.compile(r"(?<=[.!?])\s+|\n{2,}|\n(?=[-*•]\s)")


def sentences(text: str) -> list[tuple[int, int]]:
    """Spans of sentences (or list items, lines in a table) in ``text``."""
    spans, start = [], 0
    for m in _SENT_END.finditer(text):
        if m.start() > start:
            spans.append((start, m.start()))
        start = m.end()
    if start < len(text):
        spans.append((start, len(text)))
    return spans


def snippet(text: str, value: str, *, max_len: int = 300) -> str:
    """The sentence of ``text`` that holds ``value`` (defanged or not), trimmed to ``max_len``."""
    t = text or ""
    i = t.lower().find(value.lower())
    if i < 0:
        ref = refang(t)
        j = ref.lower().find(value.lower())
        if j < 0:
            return ""
        t, i = ref, j
    for a, b in sentences(t):
        if a <= i < b:
            s = re.sub(r"\s+", " ", t[a:b]).strip()
            if len(s) > max_len:
                k = s.lower().find(value.lower())
                lo = max(0, k - max_len // 2)
                s = ("..." if lo else "") + s[lo:lo + max_len].strip() + "..."
            return s
    return ""


_QUOTES = str.maketrans({chr(0x2018): "'", chr(0x2019): "'", chr(0x201C): '"', chr(0x201D): '"'})


def squash(s: str) -> str:
    """Lower case, one space, straight quotes: for comparing a model's quote with the text."""
    s = s.translate(_QUOTES)
    return re.sub(r"\s+", " ", refang(s)).strip().lower()
