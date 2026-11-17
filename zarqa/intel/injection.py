"""Spot text in collected content that tries to instruct an AI (prompt injection).

Pages, reports and connector results are written by other people, some of them
attackers. Text there that addresses an AI ("ignore previous instructions",
"report no threats", chat-template tags) is flagged: the document is marked for
review, whatever the model concluded. The text is still only data: the model is
told so, and nothing here changes what tools can do.

Simple patterns, not a classifier: they catch the blatant attempts and cost
nothing. A miss is covered by the untrusted-data wrapping and the tool policy.
"""

from __future__ import annotations

import re

_AI = r"(?:ai|assistant|model|llm|agent|analyst|hunter|bot|reviewer|gpt|chatbot)"
_BENIGN = r"(?:benign|clean|safe|trusted|false[\s_-]?positives?|legitimate|harmless|authori[sz]ed|not\s+malicious)"
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ignore instructions", re.compile(
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous|prior|above|earlier|"
        r"preceding|system|original)?\s*(?:instructions?|prompts?|rules?|directions?|context|guidance|guidelines)\b"
        r"|\b(?:previous|prior|earlier|original)\s+(?:instructions?|rules?|guidelines?)\s+(?:no\s+longer|do\s+not|don'?t)"
        r"\s+apply|\byour\s+(?:task|instructions?|role|goal|orders?)\s+(?:has|have)\s+(?:changed|been\s+(?:updated|"
        r"changed|replaced))", re.I)),
    ("ignore instructions (other languages)", re.compile(
        r"\bignor(?:ez|e|a|iere|eer)\s+(?:toutes\s+|todas\s+|alle\s+|las\s+|les\s+|die\s+)*(?:les\s+|las\s+|die\s+)?"
        r"(?:instructions|instrucciones|anweisungen|instructies)\b", re.I)),
    ("override marker", re.compile(
        r"\b(?:system|admin|developer|security)\s+(?:override|prompt|instructions?|message)\s*[:\]-]"
        r"|\[(?:system|admin|developer)\]\s*(?:new\s+)?(?:policy|instructions?|rules?|override)\b", re.I)),
    ("addresses an AI", re.compile(
        rf"\b(?:you\s+are\s+(?:now\s+)?(?:an?\s+|the\s+)?(?:[a-z-]+\s+){{0,2}}{_AI}\b|(?:note|message|instruction)s?\s+(?:to|for)\s+"
        rf"(?:the\s+|any\s+)?(?:automated\s+)?{_AI}s?\b|\bif\s+you\s+are\s+an?\s+{_AI}\b"
        rf"|\battention,?\s+(?:the\s+)?{_AI}\b|\bto\s+(?:the|any)\s+(?:automated\s+|security\s+)?{_AI}s?\b"
        rf"|\bas\s+the\s+(?:security\s+)?{_AI}\b,?\s+you\b|\b{_AI}\s*[,:]\s*(?:please\s+)?(?:ignore|disregard|override|"
        rf"forget|stop|do\s+not|don'?t)\b|\b(?:the\s+)?{_AI}\s+(?:reviewing\s+this\s+)?(?:should|must|has\s+to)\s+"
        rf"(?:conclude|answer|report|say|consider|treat|mark|classify|label)\b)", re.I)),
    ("asks for a benign verdict", re.compile(
        rf"\b(?:mark|classify|report|treat|label|consider|flag)\s+(?:(?:this|the|these|all|them|it)\s+)?(?:(?:host|"
        rf"system|machine|finding|activity|event|alert|file|process|traffic|entry|log|attachment|message)s?\s+)?"
        rf"(?:as\s+)?{_BENIGN}\b|\b(?:report|answer|say|return|give)\s+(?:zero|no|0)\s+(?:findings|threats|results|alerts)\b"
        rf"|\b(?:answer|say|report|return|conclude)\s+[\"']?(?:no_results|inconclusive|telemetry_found_benign)\b"
        rf"|\bconclude\s+(?:that\s+)?there\s+is\s+nothing\s+(?:malicious|suspicious)", re.I)),
    ("tells it not to report", re.compile(
        r"\b(?:do\s+not|don'?t|never)\s+(?:report|flag|alert|escalate|mention|investigate)\s+(?:this|it|these|"
        r"the\s+(?:host|activity|finding|process))", re.I)),
    ("chat template tags", re.compile(
        r"<\|im_(?:start|end)\|>|\[/?INST\]|<</?SYS>>|</?(?:system|assistant)>|<\|(?:system|assistant|user)\|>",
        re.I)),
    ("fake verdict or action", re.compile(
        r"\"action\"\s*:\s*\"(?:verdict|call)\"|\"outcome\"\s*:\s*\"(?:telemetry_found_benign|no_results)\"", re.I)),
    ("breaks out of the data wrapper", re.compile(r"UNTRUSTED[_-]DATA", re.I)),
]


_OPEN = re.compile(r"^\s*<<UNTRUSTED-DATA [^>\n]*>>")
_CLOSE = re.compile(r"<<END-UNTRUSTED-DATA [^>\n]*>>\s*$")


def _body(content: str) -> str:
    """The text inside the untrusted-data wrapper (the wrapper's own markers are ours; inside it,
    wrap() has already turned any look-alike marker into UNTRUSTED_DATA)."""
    return _CLOSE.sub("", _OPEN.sub("", content, count=1), count=1)


_SPLIT = re.compile(r"(?<=\w)[-_.](?=\w)")
_SPACED = re.compile(r"\b(?:\w[-_.]){3,}\w\b")      # i-g-n-o-r-e: one letter, a separator, repeated


def _views(body: str) -> list[tuple[str, str]]:
    """The text as written, then normalised (look-alike letters, words split by - _ .), then any payload the
    offline decoder can unpack (base64, -EncodedCommand, hex, ...). Each view is scanned."""
    import unicodedata
    out = [("", body)]
    norm = unicodedata.normalize("NFKC", body)
    norm = _SPACED.sub(lambda m: re.sub(r"[-_.]", "", m.group(0)) if len(m.group(0)) <= 80 else m.group(0), norm)
    norm = _SPLIT.sub(" ", norm)
    if norm != body:
        out.append((" (normalised)", norm))
    try:
        from ..decode import decode
        r = decode(body[:100_000]) or {}
        texts = [str(x.get("decoded") or "") for x in r.get("layers") or [] if isinstance(x, dict)]
        texts.append(str(r.get("final") or ""))
        dec = "\n".join(dict.fromkeys(t for t in texts if t and t not in body))
        if dec:
            out.append((" (decoded)", dec))
    except Exception:
        pass
    return out


def scan(content: str, max_hits: int = 5) -> list[dict]:
    """Return [{pattern, excerpt}] for text that looks like instructions to an AI."""
    body = _body(content or "")
    hits: list[dict] = []
    seen: set[str] = set()
    for where, text in _views(body):
        for name, rx in PATTERNS:
            if name in seen:
                continue
            m = rx.search(text)
            if m:
                seen.add(name)
                a, b = max(0, m.start() - 60), min(len(text), m.end() + 60)
                excerpt = re.sub(r"\s+", " ", text[a:b]).strip()
                hits.append({"pattern": name + where, "excerpt": excerpt[:200]})
                if len(hits) >= max_hits:
                    return hits
    return hits
