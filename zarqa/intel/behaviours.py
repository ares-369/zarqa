"""ATT&CK techniques found by wording, with no model: technique names written out, and plain behaviour phrases.

Reports often describe a technique without its ID: "dumped LSASS memory", "deleted volume shadow copies",
"created a scheduled task", "side-loaded a malicious DLL". Two deterministic passes find them:

1. **Technique names** from the bundled ATT&CK data, written out in the text ("Process Hollowing", "Password
   Spraying", "Ingress Tool Transfer"). Names of one ordinary word ("DNS", "Python", "Cron") and a few
   multi-word names that are everyday phrases are skipped: they appear in reports without meaning the technique.
2. **Behaviour phrases**: a short curated list of wordings that almost always mean one technique.

Each hit keeps the matched passage as its evidence, like any other mention. IDs in the list are resolved
through the ATT&CK data, so a renumbered technique maps to its current ID and an unknown one is skipped.
These are word matches, not understanding: "the actor did not use PowerShell" still matches PowerShell. The
benchmark in docs/benchmarks.md measures what that costs.
"""

from __future__ import annotations

import re
from functools import lru_cache

from . import attack

# wording -> technique (IDs resolved through the ATT&CK data at load)
PHRASES: list[tuple[str, str]] = [
    (r"lsass(?:\.exe)?(?:\s+process)?\s+(?:memory|dump)|dump(?:ed|ing|s)?\s+(?:the\s+)?lsass", "T1003.001"),
    (r"(?:ntds\.dit|ntdsutil)", "T1003.003"),
    (r"dcsync", "T1003.006"),
    (r"(?:sam|security)\s+(?:registry\s+)?hive|reg(?:\.exe)?\s+save\s+hklm\\\\sam", "T1003.002"),
    (r"(?:delet\w+|remov\w+|wip\w+)\s+(?:the\s+|all\s+)?(?:volume\s+)?shadow\s+cop(?:y|ies)|vssadmin(?:\.exe)?\s+delete",
     "T1490"),
    (r"encrypt\w*\s+(?:the\s+|victims?'?\s+)?(?:files|systems|drives|virtual\s+machines|vms)|ransom\s+notes?", "T1486"),
    (r"scheduled\s+tasks?|schtasks(?:\.exe)?", "T1053.005"),
    (r"(?:registry\s+)?run\s+keys?|currentversion\\\\run\b", "T1547.001"),
    (r"rundll32(?:\.exe)?", "T1218.011"),
    (r"regsvr32(?:\.exe)?", "T1218.010"),
    (r"mshta(?:\.exe)?", "T1218.005"),
    (r"msiexec(?:\.exe)?\s+/", "T1218.007"),
    (r"password\s+spray(?:ing|ed)?", "T1110.003"),
    (r"credential\s+stuffing", "T1110.004"),
    (r"brute[\s-]?forc(?:e|ed|ing)", "T1110"),
    (r"keylog(?:ger|ging|s)?", "T1056.001"),
    (r"(?:takes?|took|capture[sd]?|grab\w*)\s+screenshots?", "T1113"),
    (r"web\s?shells?", "T1505.003"),
    (r"dll\s+(?:side[\s-]?loading|search\s+order\s+hijack\w*)|side[\s-]?load(?:s|ed|ing)?\s+(?:a\s+)?(?:malicious\s+)?dll",
     "T1574.002"),
    (r"exfiltrat\w+\s+(?:\w+\s+){0,3}over\s+(?:the\s+)?(?:c2|command[\s-]and[\s-]control)", "T1041"),
    (r"exfiltrat\w+\s+(?:\w+\s+){0,4}to\s+(?:cloud\s+storage|mega|dropbox|google\s+drive|onedrive)", "T1567.002"),
    (r"dns\s+tunnel(?:ing|s)?", "T1071.004"),
    (r"spear[\s-]?phishing\s+(?:e-?mails?\s+)?(?:with\s+)?(?:an?\s+)?(?:malicious\s+)?attachments?", "T1566.001"),
    (r"spear[\s-]?phishing\s+links?|phishing\s+(?:e-?mails?|messages?)\s+(?:with|containing)\s+(?:a\s+)?(?:malicious\s+)?links?",
     "T1566.002"),
    (r"process\s+hollowing", "T1055.012"),
    (r"(?:reflective(?:ly)?\s+(?:dll\s+)?(?:load|inject)\w*)", "T1620"),
    (r"powershell(?:\.exe)?", "T1059.001"),
    (r"cmd\.exe|windows\s+command\s+shell", "T1059.003"),
    (r"\bwmic?(?:\.exe)?\b|windows\s+management\s+instrumentation", "T1047"),
    (r"remote\s+desktop\s+protocol|\brdp\b", "T1021.001"),
    (r"(?:admin\$|c\$|ipc\$)|smb/windows\s+admin\s+shares", "T1021.002"),
    (r"pass[\s-]the[\s-]hash", "T1550.002"),
    (r"pass[\s-]the[\s-]ticket", "T1550.003"),
    (r"kerberoast(?:ing|ed)?", "T1558.003"),
    (r"golden\s+tickets?", "T1558.001"),
    (r"as-?rep\s+roast(?:ing)?", "T1558.004"),
    (r"(?:disabl\w+|tamper\w*\s+with|turn\w*\s+off|kill\w*)\s+(?:the\s+)?(?:antivirus|anti-virus|av|edr|endpoint\s+"
     r"(?:protection|detection)|security\s+(?:tools|software|products)|microsoft\s+defender|windows\s+defender)", "T1562.001"),
    (r"clear\w*\s+(?:the\s+)?(?:windows\s+)?event\s+logs?|wevtutil(?:\.exe)?\s+cl", "T1070.001"),
    (r"timestomp\w*", "T1070.006"),
    (r"exploit\w*\s+(?:a\s+|the\s+)?(?:\w+\s+){0,3}(?:in|on)\s+(?:an?\s+)?(?:internet|public)[\s-](?:facing|exposed)",
     "T1190"),
    (r"(?:public|internet)[\s-](?:facing|exposed)\s+(?:\w+\s+){0,2}(?:application|server|appliance|device|service)s?\s+"
     r"(?:\w+\s+){0,3}exploit\w*", "T1190"),
    (r"supply[\s-]chain\s+(?:attack|compromise)", "T1195"),
    (r"watering[\s-]hole|drive[\s-]by\s+(?:download|compromise)", "T1189"),
    (r"\btor\b\s+(?:network|nodes?|hidden\s+service|onion)|over\s+tor\b", "T1090.003"),
    (r"domain\s+fronting", "T1090.004"),
    (r"steganograph\w+", "T1027.003"),
    (r"uac\s+bypass|bypass\w*\s+(?:the\s+)?user\s+account\s+control", "T1548.002"),
    (r"token\s+(?:impersonation|theft|manipulation)", "T1134.001"),
    (r"(?:network|port)\s+scan(?:ning|ner|s)?|scann\w+\s+(?:the\s+)?(?:internal\s+)?network", "T1046"),
    (r"remote\s+(?:access|monitoring\s+and\s+management|management)\s+(?:software|tools?)|\brmm\s+tools?", "T1219"),
    (r"seo\s+poisoning", "T1608.006"),
    (r"(?:fake|bogus)\s+captcha|clickfix|filefix|paste\s+(?:\w+\s+){0,3}into\s+(?:the\s+)?(?:run\s+dialog|terminal|powershell)",
     "T1204.004"),
    (r"(?:user|victim)s?\s+(?:\w+\s+){0,2}(?:open\w*|launch\w*|run\w*|execut\w*|double[\s-]click\w*)\s+(?:\w+\s+){0,3}"
     r"(?:malicious\s+)?(?:attachment|file|document|executable|lnk|shortcut)", "T1204.002"),
    (r"(?:download\w*|fetch\w*|retriev\w*|pull\w*)\s+(?:\w+\s+){0,3}(?:additional\s+|next[\s-]stage\s+|second[\s-]stage\s+)?"
     r"(?:payloads?|tools?|malware|binar(?:y|ies)|stagers?)\s+from", "T1105"),
    (r"masquerad\w+\s+as|disguis\w+\s+as\s+(?:a\s+)?(?:legitimate|benign)", "T1036"),
    (r"(?:creat\w+|install\w+|regist\w+)\s+(?:a\s+)?(?:new\s+|malicious\s+)?(?:windows\s+)?services?\b", "T1543.003"),
    (r"psexec", "T1569.002"),
    (r"nltest|domain\s+trust\s+discovery", "T1482"),
    (r"adfind|bloodhound|sharphound", "T1087.002"),
    (r"(?:archiv|compress)\w*\s+(?:the\s+)?(?:collected\s+|stolen\s+)?(?:data|files)|\b(?:7-?zip|winrar|rar\.exe)\b",
     "T1560.001"),
    (r"(?:tunnel\w*|ngrok|chisel|plink)\b", "T1572"),
    (r"privilege\s+escalation\s+(?:vulnerability|exploit|flaw)|exploit\w*\s+(?:\w+\s+){0,3}to\s+(?:gain|escalate)\s+"
     r"(?:system|root|admin\w*)\s+privileges", "T1068"),
    (r"(?:sandbox|virtual\s+machine|vm)\s+evasion|anti[\s-](?:vm|sandbox)|check\w*\s+(?:whether|if)\s+it\s+(?:is|was)\s+"
     r"running\s+(?:in|inside)\s+(?:a\s+)?(?:sandbox|virtual\s+machine|vm)", "T1497"),
    (r"anti[\s-]debug\w*", "T1622"),
    (r"(?:base64|xor)[\s-](?:encoded|obfuscated|encrypted)", "T1027"),
    (r"(?:decod|decrypt|deobfuscat)\w+\s+(?:the\s+)?(?:payload|shellcode|strings|configuration|config)", "T1140"),
    (r"(?:mfa|multi[\s-]factor)\s+(?:fatigue|bombing|push\s+spam)", "T1621"),
    (r"(?:session|authentication)\s+cookies?\s+(?:theft|stealing|stolen)|steal\w*\s+(?:browser\s+|session\s+)?cookies",
     "T1539"),
    (r"(?:aitm|adversary[\s-]in[\s-]the[\s-]middle|man[\s-]in[\s-]the[\s-]middle)", "T1557"),
    (r"(?:delet\w+|wip\w+|destroy\w+)\s+(?:\w+\s+){0,2}(?:data|files|backups)|\bwiper\b", "T1485"),
    (r"defac\w+", "T1491"),
    (r"(?:ingress\s+tool\s+transfer)", "T1105"),
]

# technique names that are ordinary words or phrases in a report, not the technique
_SKIP_NAMES = {"dns", "python", "javascript", "cron", "at", "tool", "code", "malware", "dll", "exploits", "services",
               "launchctl", "systemd", "pubprn", "odbcconf", "lua", "autohotkey", "sharepoint", "msbuild", "linux",
               "cloud accounts", "local accounts", "domain accounts", "default accounts", "web protocols",
               "mail protocols", "file transfer protocols", "email accounts", "social media accounts",
               "domains", "server", "botnet", "web services", "digital certificates", "vulnerabilities", "upload malware",
               "install digital certificate", "link target", "user execution", "modify registry",
               "additional cloud credentials", "data staged", "local data staging", "spearphishing via service",
               "valid accounts", "phishing", "obfuscated files or information", "command and scripting interpreter",
               "application layer protocol", "data encoding", "standard encoding", "non-standard encoding",
               "encrypted channel", "symmetric cryptography", "asymmetric cryptography", "credentials in files",
               "unsecured credentials", "file deletion", "network sniffing", "content injection", "screen capture",
               "audio capture", "video capture", "email collection", "rootkit", "software packing", "binary padding",
               "social media", "ip addresses", "cloud services", "social engineering", "malicious link",
               "multi-factor authentication", "financial theft", "remote desktop software", "email spoofing",
               "delay execution", "email addresses", "employee names", "network topology", "dns server",
               "domain properties", "network trust dependencies", "business relationships", "identify roles",
               "determine physical locations", "client configurations", "hardware", "software", "firmware",
               "credentials", "threat intel vendors", "purchase technical data", "scan databases",
               "search engines", "code repositories", "open websites/domains", "search victim-owned websites",
               "cloud storage object discovery", "cloud service discovery", "account manipulation"}


@lru_cache(maxsize=1)
def _phrases() -> list[tuple[re.Pattern, str]]:
    out = []
    for rx, tid in PHRASES:
        t = attack.technique(tid)
        if t:
            out.append((re.compile(r"(?<![\w-])(?:" + rx + r")(?![\w-])", re.I), t["id"]))
    return out


@lru_cache(maxsize=1)
def _names_re() -> tuple[re.Pattern | None, dict[str, str]]:
    names: dict[str, str] = {}
    for tid, t in attack.data()["techniques"].items():
        n = t["n"].strip()
        low = n.lower()
        if low in _SKIP_NAMES or (" " not in n and not re.search(r"[A-Z].*[A-Z]|\d", n[1:])):
            continue                       # one ordinary word ("Masquerading" is kept by the phrase list instead)
        if len(low) < 6:
            continue
        names.setdefault(low, tid)
    if not names:
        return None, {}
    alt = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
    return re.compile(r"(?<![\w-])(?:" + alt + r")(?![\w-])", re.I), names


def find_techniques(text: str) -> list[dict]:
    """[{id, matched, how}] for techniques named or described in ``text`` (each ID once)."""
    seen: set[str] = set()
    out = []
    rx, names = _names_re()
    if rx is not None:
        for m in rx.finditer(text or ""):
            tid = names.get(m.group(0).lower())
            t = attack.technique(tid) if tid else None
            if t and t["id"] not in seen:
                seen.add(t["id"])
                out.append({"id": t["id"], "matched": m.group(0), "how": "name"})
    for prx, tid in _phrases():
        if tid in seen:
            continue
        m = prx.search(text or "")
        if m:
            seen.add(tid)
            out.append({"id": tid, "matched": m.group(0), "how": "phrase"})
    return out
