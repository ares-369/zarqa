"""Fetch text from a URL (HTML, plain text or PDF) or a local PDF file, safely.

URL safety: only http(s); every redirect hop is checked; hosts that resolve to
private, loopback, link-local or reserved addresses are refused unless
``collect.allow_private_urls`` is true, and the validated IP is pinned for the
request to prevent DNS rebinding.
PDF text extraction needs the optional ``pdf`` extra (pypdf).
"""

from __future__ import annotations

import io
import ipaddress
import re
import socket
from contextlib import contextmanager
from contextvars import ContextVar
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

MAX_BYTES = 15_000_000
MAX_TEXT = 200_000


class FetchError(ValueError):
    pass


class _Text(HTMLParser):
    # Page furniture, not the article: menus, sidebars ("trending", "related"), cookie and share boxes.
    SKIP = {"script", "style", "noscript", "svg", "nav", "footer", "header", "form", "aside", "iframe", "button",
            "template", "dialog"}
    BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "section", "article", "td"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        if tag == "title":
            self._in_title = True
        if tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self.skip:
            self.parts.append(data)


def html_to_text(html: str) -> tuple[str, str]:
    p = _Text()
    p.feed(html)
    text = re.sub(r"[ \t]+", " ", "".join(p.parts))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return p.title.strip(), text


def pdf_to_text(data: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise FetchError("PDF import needs the pdf extra: pip install 'zarqa[pdf]'") from exc
    try:
        reader = PdfReader(io.BytesIO(data))
        pages = [(pg.extract_text() or "") for pg in reader.pages[:200]]
    except Exception as exc:
        raise FetchError(f"could not read the PDF: {exc}") from exc
    text = "\n".join(pages).strip()
    if not text:
        raise FetchError("the PDF has no extractable text (it may be scanned images)")
    return text


_PINNED_DNS: ContextVar[tuple[str, str] | None] = ContextVar("_PINNED_DNS", default=None)
_ORIG_GETADDRINFO = socket.getaddrinfo


def _pinned_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    pin = _PINNED_DNS.get()
    if pin and host == pin[0]:
        return _ORIG_GETADDRINFO(pin[1], port, family, type, proto, flags)
    return _ORIG_GETADDRINFO(host, port, family, type, proto, flags)


socket.getaddrinfo = _pinned_getaddrinfo


@contextmanager
def _pin_host(hostname: str | None, pinned_ip: str | None):
    if not hostname or not pinned_ip:
        yield
        return
    tok = _PINNED_DNS.set((hostname, pinned_ip))
    try:
        yield
    finally:
        _PINNED_DNS.reset(tok)


def _check_host(url: str, allow_private: bool) -> str | None:
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise FetchError("only http(s) URLs are allowed")
    if allow_private:
        return None
    try:
        infos = _ORIG_GETADDRINFO(u.hostname, u.port or (443 if u.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise FetchError(f"cannot resolve {u.hostname}") from exc
    first_ip: str | None = None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise FetchError(f"{u.hostname} resolves to a non-public address; set collect.allow_private_urls to allow it")
        if first_ip is None:
            first_ip = str(ip)
    return first_ip


def fetch_url(url: str, *, allow_private: bool = False, session=None, timeout: float = 30,
              headers: dict | None = None, want_raw: bool = False) -> dict:
    """Fetch a URL safely. ``want_raw``: also return the undecoded-to-text body (for lists and JSON);
    ``headers``: extra request headers (for example a feed's API key). Headers are not sent again to a
    different host after a redirect."""
    s = session or requests.Session()
    first_host = urlparse(url).hostname
    for _ in range(6):
        pinned_ip = _check_host(url, allow_private)
        with _pin_host(urlparse(url).hostname, pinned_ip):
            hdrs = {"User-Agent": "zarqa"}
            if headers and urlparse(url).hostname == first_host:
                hdrs.update(headers)
            r = s.get(url, timeout=timeout, allow_redirects=False, stream=True, headers=hdrs)
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
            url = urljoin(url, r.headers["Location"])
            r.close()
            continue
        break
    else:
        raise FetchError("too many redirects")
    if r.status_code >= 400:
        raise FetchError(f"HTTP {r.status_code}")
    data = b""
    for chunk in r.iter_content(65536):
        data += chunk
        if len(data) > MAX_BYTES:
            raise FetchError("document is larger than 15 MB")
    ctype = r.headers.get("Content-Type", "").lower()
    # without a declared charset the HTTP library assumes Latin-1; the web is mostly UTF-8
    enc = (r.encoding if "charset=" in ctype else None) or "utf-8"
    raw = data.decode(enc, "replace") if "pdf" not in ctype and data[:5] != b"%PDF-" else ""
    if want_raw and raw:
        return {"url": url, "title": "", "text": raw[:MAX_TEXT], "raw": raw, "content_type": ctype}
    if raw.lstrip()[:200].lower().startswith(("<?xml", "<rss", "<feed")):
        return {"url": url, "title": "", "text": raw[:MAX_TEXT], "raw": raw[:MAX_BYTES]}
    if "pdf" in ctype or data[:5] == b"%PDF-":
        title, text = Path(urlparse(url).path).name, pdf_to_text(data)
    elif "html" in ctype or b"<html" in data[:2000].lower():
        title, text = html_to_text(data.decode(enc, "replace"))
    else:
        title, text = "", data.decode(enc, "replace")
    return {"url": url, "title": title[:300], "text": text[:MAX_TEXT]}


def read_file(path: str) -> dict:
    p = Path(path).expanduser()
    data = p.read_bytes()[:MAX_BYTES]
    if data[:5] == b"%PDF-":
        return {"title": p.stem, "text": pdf_to_text(data)[:MAX_TEXT]}
    if p.suffix.lower() in (".html", ".htm"):
        title, text = html_to_text(data.decode("utf-8", "replace"))
        return {"title": title or p.stem, "text": text[:MAX_TEXT]}
    return {"title": p.stem, "text": data.decode("utf-8", "replace")[:MAX_TEXT]}
