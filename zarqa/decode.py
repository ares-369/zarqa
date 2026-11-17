"""Decode obfuscated command lines and scripts without running them.

Handles, recursively (up to 4 layers): PowerShell -EncodedCommand (base64 of
UTF-16LE), base64 blobs, gzip/deflate inside base64, hex, [char] code lists,
URL encoding, string concatenation and reversed strings, and backtick and caret
escapes. Pure string work: nothing is executed. It finds common layers, not all.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
import zlib

MAX_INPUT = 200_000
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_ENC = re.compile(r"(?i)(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+([A-Za-z0-9+/=]{8,})")
_HEX = re.compile(r"(?:0x)?((?:[0-9a-fA-F]{2}){12,})")
_CHARS = re.compile(r"(?i)(?:\[char\]\s*\d{2,3}\s*[+,]?\s*){4,}")
_CHARLIST = re.compile(r"(?i)\[char\[\]\]\s*\(?\s*((?:\d{2,3}\s*,\s*){3,}\d{2,3})\s*\)?")
_FROMCC = re.compile(r"(?i)String\.fromCharCode\(\s*((?:\d{2,3}\s*,\s*){3,}\d{2,3})\s*\)")
_CONCAT = re.compile(r"""(?:(['"])[^'"]{0,200}\1\s*\+\s*){2,}(['"])[^'"]{0,200}\2""")
_KEYWORDS = re.compile(r"(?i)\b(iex|invoke-expression|downloadstring|downloadfile|invoke-webrequest|iwr|net\.webclient|"
                       r"frombase64string|start-process|new-object|bitsadmin|certutil|rundll32|regsvr32|mshta|wscript|"
                       r"cscript|curl|wget|bash\s+-c|/dev/tcp|nc\s+-e|powershell|cmd\s*/c|eval|atob|"
                       r"add-mppreference|set-mppreference|-exclusionpath|amsi|virtualalloc|reflection\.assembly)\b")
_URL = re.compile(r"\bhttps?://[^\s'\"<>)]+", re.I)
_IP = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d|\.\d)")


def _printable(s: str, ratio: float = 0.85) -> bool:
    if not s:
        return False
    good = sum(ch.isprintable() or ch in "\r\n\t" for ch in s)
    return good / len(s) >= ratio


def _bytes_to_text(b: bytes) -> tuple[str, str] | None:
    if b.startswith(b"\x1f\x8b"):
        try:
            t = _bytes_to_text(zlib.decompress(b, 16 + zlib.MAX_WBITS))
            if t:
                return t[0], "gzip"
        except zlib.error:
            pass
    for wbits, how in ((-15, "deflate"), (15, "zlib")):
        try:
            d = zlib.decompress(b, wbits)
            t = _bytes_to_text(d)
            if t:
                return t[0], how
        except zlib.error:
            pass
    if len(b) >= 4 and b[1::2].count(0) >= len(b[1::2]) * 0.8:
        try:
            s = b.decode("utf-16-le")
            if _printable(s):
                return s, "utf-16le"
        except UnicodeDecodeError:
            pass
    try:
        s = b.decode("utf-8")
        if _printable(s):
            return s, "utf-8"
    except UnicodeDecodeError:
        pass
    return None


def _b64(s: str) -> tuple[str, str] | None:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s + pad, validate=True)
    except (binascii.Error, ValueError):
        return None
    t = _bytes_to_text(raw)
    return (t[0], "base64+" + t[1]) if t else None


def _step(text: str) -> list[tuple[str, str]]:
    """One decoding pass; returns [(method, decoded)]."""
    out: list[tuple[str, str]] = []
    for m in _ENC.finditer(text):
        r = _b64(m.group(1))
        if r:
            out.append(("powershell -EncodedCommand " + r[1], r[0]))
    if not out:
        for m in _B64.finditer(text):
            r = _b64(m.group(0))
            if r and len(r[0]) >= 6:
                out.append((r[1], r[0]))
    for m in _CHARS.finditer(text):
        codes = re.findall(r"\d{2,3}", m.group(0))
        out.append(("[char] codes", "".join(chr(int(c)) for c in codes if int(c) < 0x110000)))
    for rx, name in ((_CHARLIST, "[char[]] list"), (_FROMCC, "String.fromCharCode")):
        for m in rx.finditer(text):
            out.append((name, "".join(chr(int(c)) for c in re.findall(r"\d+", m.group(1)))))
    for m in _HEX.finditer(text):
        try:
            t = _bytes_to_text(bytes.fromhex(m.group(1)))
        except ValueError:
            t = None
        if t:
            out.append(("hex+" + t[1], t[0]))
    if "%" in text and re.search(r"%[0-9a-fA-F]{2}", text):
        u = urllib.parse.unquote(text)
        if u != text:
            out.append(("url encoding", u))
    for m in _CONCAT.finditer(text):
        joined = "".join(p[1] for p in re.findall(r"""(['"])(.*?)\1""", m.group(0)))
        out.append(("string concatenation", joined))
    cleaned = re.sub(r"`(?=[A-Za-z])", "", text)
    cleaned = re.sub(r"\^(?=[A-Za-z])", "", cleaned)
    if cleaned != text:
        out.append(("backtick/caret escapes removed", cleaned))
    if re.search(r"(?i)\[-1\.\.|-join\s*\(\s*\[array\]::reverse|\.reverse\(\)", text):
        for lit in re.findall(r"""['"]([^'"]{12,})['"]""", text):
            out.append(("reversed string", lit[::-1]))
    return out


def decode(text: str, max_depth: int = 4) -> dict:
    text = (text or "")[:MAX_INPUT]
    layers = []
    seen = {text}
    frontier = [text]
    for depth in range(1, max_depth + 1):
        nxt = []
        for t in frontier:
            for method, dec in _step(t):
                if dec in seen or not dec.strip():
                    continue
                seen.add(dec)
                layers.append({"depth": depth, "method": method, "decoded": dec[:20_000]})
                nxt.append(dec)
        if not nxt:
            break
        frontier = nxt[:10]
    allt = "\n".join([text] + [la["decoded"] for la in layers])
    return {
        "layers": layers,
        "final": layers[-1]["decoded"] if layers else text,
        "keywords": sorted({k.lower() for k in _KEYWORDS.findall(allt)}),
        "urls": sorted(set(_URL.findall(allt)))[:50],
        "ips": sorted(set(_IP.findall(allt)))[:50],
        "note": "decoded by pattern; nothing was executed. Layers it does not know are left as they are.",
    }
