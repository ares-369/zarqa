"""What runs in your organization, from an asset inventory, so relevance can say which hosts a report is about.

An inventory is a list of rows ``host, name, version, vendor``: the software each host has installed. It comes
from a file (CSV with a header, or JSON) or from a read-only connector tool (``inventory.from`` in config), and
each import replaces the rows from that source, so the store always holds the latest snapshot.

Package names are turned into product names (``openssh-server`` -> ``OpenSSH``, ``libssl3`` -> ``OpenSSL``);
libraries, fonts, documentation and other packages nobody writes advisories about are left out. What is left is
offered as *suggestions* for the organization profile. Nothing is added to the profile by itself: one-word
package names (``less``, ``file``, ``patch``) would match half the news, so a person picks.

Once a product is in the profile, relevance says which hosts run it: "names your product OpenSSH (on 3 hosts:
web1, web2, db1)", and a product that is actually installed weighs a little more than one only listed.

Formats read without any mapping:

* rows with ``host``/``hostname``/``agent``, ``name``/``product``/``package``, ``version``, ``vendor``;
* search results ``{"hits": {"hits": [{"_source": ...}]}}`` with ``agent.name`` and ``package.name``/
  ``package.version``/``package.vendor`` (a Wazuh-style inventory index);
* API results ``{"data": {"affected_items": [...]}}`` with ``agent_id`` or ``agent.name``.

Anything else: ``inventory.fields`` maps each column to a dotted path, and ``inventory.rows`` names where the
list is.

A scheduled export elsewhere can push the inventory with ``POST /api/inventory/import`` and a bearer token set in
``inventory.token_env``; that token can do nothing else.
"""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from .store import KnowledgeStore, now

FIELDS = ("host", "name", "version", "vendor")
_GUESS = {"host": ("host", "hostname", "host.name", "agent.name", "agent_name", "agent", "computer", "agent_id",
                   "agent.id"),
          "name": ("name", "product", "package", "package.name", "software", "program"),
          "version": ("version", "package.version", "ver"),
          "vendor": ("vendor", "package.vendor", "publisher", "manufacturer")}
MAX_ROWS = 200_000

# package name -> product name people write in advisories
ALIASES = {
    "openssh-server": "OpenSSH", "openssh-client": "OpenSSH", "openssh-sftp-server": "OpenSSH", "openssh": "OpenSSH",
    "openssl": "OpenSSL", "libssl3": "OpenSSL", "libssl3t64": "OpenSSL", "libssl1.1": "OpenSSL",
    "libc6": "glibc", "libc-bin": "glibc", "glibc": "glibc", "liblzma5": "xz", "xz-utils": "xz",
    "pve-manager": "Proxmox VE", "proxmox-ve": "Proxmox VE", "proxmox-backup-server": "Proxmox Backup Server",
    "apache2": "Apache HTTP Server", "httpd": "Apache HTTP Server", "nginx": "nginx", "openresty": "OpenResty",
    "docker-ce": "Docker", "docker.io": "Docker", "containerd.io": "containerd", "containerd": "containerd",
    "mariadb-server": "MariaDB", "mysql-server": "MySQL", "redis-server": "Redis", "redis": "Redis",
    "postgresql": "PostgreSQL", "samba": "Samba", "bind9": "BIND", "unbound": "Unbound", "dnsmasq-base": "dnsmasq",
    "dnsmasq": "dnsmasq", "exim4-daemon-light": "Exim", "postfix": "Postfix", "dovecot-core": "Dovecot",
    "systemd": "systemd", "sudo": "sudo", "bash": "Bash", "curl": "curl", "libcurl4": "curl", "wget": "wget",
    "git": "Git", "vim": "Vim", "rsync": "rsync", "polkitd": "polkit", "policykit-1": "polkit", "cups": "CUPS",
    "cups-daemon": "CUPS", "openvpn": "OpenVPN", "wireguard-tools": "WireGuard", "tailscale": "Tailscale",
    "zfsutils-linux": "OpenZFS", "qemu-server": "QEMU", "pve-qemu-kvm": "QEMU", "qemu-system-x86": "QEMU",
    "lxc-pve": "LXC", "lxc": "LXC", "nodejs": "Node.js", "python3": "Python", "php": "PHP", "openjdk": "Java",
    "grafana": "Grafana", "elasticsearch": "Elasticsearch", "opensearch": "OpenSearch",
    "wazuh-manager": "Wazuh", "wazuh-indexer": "Wazuh", "wazuh-dashboard": "Wazuh", "wazuh-agent": "Wazuh agent",
    "jenkins": "Jenkins", "gitlab-ce": "GitLab", "forgejo": "Forgejo", "gitea": "Gitea",
    "google-chrome-stable": "Google Chrome", "chromium": "Chromium", "firefox": "Firefox", "firefox-esr": "Firefox",
    "thunderbird": "Thunderbird", "linux-image": "Linux kernel", "pve-kernel": "Linux kernel",
    "proxmox-kernel": "Linux kernel", "gpg": "GnuPG", "gnupg2": "GnuPG", "gpg-agent": "GnuPG", "gpgsm": "GnuPG",
    "dirmngr": "GnuPG", "gpgconf": "GnuPG", "bind9-host": "BIND", "bind9-dnsutils": "BIND", "bind9-libs": "BIND",
    "samba-libs": "Samba", "smbclient": "Samba", "dbus-daemon": "D-Bus", "ssh": "OpenSSH", "vim-tiny": "Vim",
    "git-man": "Git", "nmap": "Nmap", "tcpdump": "tcpdump", "iptables": "iptables", "nftables": "nftables",
    "apparmor": "AppArmor", "busybox": "BusyBox", "sqlite3": "SQLite", "zlib1g": "zlib", "perl": "Perl",
    "rpcbind": "rpcbind", "nfs-common": "NFS", "nfs-kernel-server": "NFS", "criu": "CRIU",
    "squid": "Squid", "haproxy": "HAProxy", "keepalived": "keepalived", "fail2ban": "Fail2ban",
    "suricata": "Suricata", "zeek": "Zeek", "snort": "Snort", "clamav": "ClamAV", "mosquitto": "Mosquitto",
    "nextcloud": "Nextcloud", "jellyfin": "Jellyfin", "plexmediaserver": "Plex", "openvswitch-switch": "Open vSwitch",
    "ceph-common": "Ceph", "ceph": "Ceph", "corosync": "Corosync", "frr": "FRRouting", "isc-dhcp-client": "ISC DHCP",
    "isc-dhcp-server": "ISC DHCP", "kea-dhcp4-server": "Kea DHCP", "cups-browsed": "CUPS", "avahi-daemon": "Avahi",
    "exim4": "Exim", "dovecot-imapd": "Dovecot", "screen": "GNU Screen", "tmux": "tmux", "sudo-ldap": "sudo",
    "set": "Social-Engineer Toolkit", "john": "John the Ripper", "responder": "Responder",
    "netexec": "NetExec", "bloodhound": "BloodHound", "mimikatz": "Mimikatz", "anydesk": "AnyDesk",
    "rclone": "rclone", "powershell": "PowerShell", "ntfs-3g": "NTFS-3G",
    "nodejs-doc": "Node.js", "npm": "npm", "pip": "pip", "python3-pip": "pip", "ruby": "Ruby", "golang": "Go",
}
_PREFIX_ALIASES = (("postgresql-", "PostgreSQL"), ("openjdk-", "Java"), ("php8", "PHP"), ("php7", "PHP"),
                   ("python3.", "Python"), ("linux-image-", "Linux kernel"), ("pve-kernel-", "Linux kernel"),
                   ("proxmox-kernel-", "Linux kernel"), ("mozilla firefox", "Firefox"), ("google chrome", "Google Chrome"),
                   ("microsoft edge", "Microsoft Edge"), ("7-zip", "7-Zip"), ("notepad++", "Notepad++"),
                   ("putty", "PuTTY"), ("winrar", "WinRAR"), ("vlc media player", "VLC"),
                   ("microsoft office", "Microsoft Office"), ("microsoft 365", "Microsoft Office"),
                   ("adobe acrobat", "Adobe Acrobat"), ("zoom", "Zoom"), ("openvpn", "OpenVPN"),
                   ("wireshark", "Wireshark"), ("node.js", "Node.js"), ("python 3", "Python"),
                   ("java ", "Java"), ("oracle virtualbox", "VirtualBox"), ("vmware", "VMware"))
# packages nobody writes advisories about by that name
_NOISE = re.compile(r"^(lib(?!reoffice)|fonts?-|gir1\.2-|python3?-|ruby-|node-|golang-|perl-|r-cran-|texlive|"
                    r"debian-|doc-|wamerican|wbritish|dictionaries|iso-codes|.*\.ids$|.*-keyring$|.*-x86-64-linux-gnu$|"
                    r".*-(locales|config|conf|schemas|icon-theme|helpers?|defaults|extra|setup|faq)$|cpp|g\+\+|gcc|"
                    r"binutils|build-essential|fakeroot|pkg-?conf|login\.defs|usrmerge|init-system|systemd-sysv|"
                    r"x11-|xserver-|xfonts|ttf-|firmware-|linux-(headers|modules|libc|tools|base)|"
                    r"language-pack|hunspell|myspell|aspell|manpages|man-db|info$|install-info|tzdata|locales|"
                    r"debconf|dpkg|apt|ucf|base-|lsb-|sensible-utils|ca-certificates|"
                    r"kb\d|update for |security update for |hotfix for |microsoft visual c\+\+|"
                    r"microsoft \.net|windows sdk|vs_|vcredist)", re.I)
_NOISE_SUFFIX = re.compile(r"(-dev|-doc|-docs|-common|-data|-dbg|-dbgsym|-l10n|-locale|-perl|-headers|-examples|"
                           r"-bin|-utils|-tools|-core|-base|-runtime|-plugins?(-\w+)?)$", re.I)
# words too common to be a match term on their own
GENERIC = {"less", "file", "patch", "make", "time", "screen", "tree", "tar", "gzip", "bzip2", "zip", "unzip",
           "nano", "man", "info", "which", "grep", "sed", "gawk", "mawk", "findutils", "diffutils", "coreutils",
           "procps", "psmisc", "hostname", "login", "passwd", "mount", "util-linux", "bsdutils", "kmod", "init",
           "cron", "logrotate", "rsyslog", "netbase", "iproute2", "iputils-ping", "ifupdown", "net-tools",
           "readline-common", "ncurses-base", "ncurses-bin", "sysvinit-utils", "e2fsprogs", "dash", "debianutils",
           "adduser", "gpgv", "gnupg", "pinentry-curses", "openssl-provider-legacy", "media-types", "mime-support",
           "shared-mime-info", "dbus", "udev", "bc", "dc", "ed", "jq", "htop", "lsof", "strace", "ltrace",
           "pciutils", "usbutils", "dmidecode", "ethtool", "bridge-utils", "vlan", "spike", "click", "expect", "rich",
           "foundation", "office", "fuse", "fuse3", "ftp", "whois", "steam", "eject", "kbd", "parted", "cpio",
           "logsave", "fdisk", "traceroute", "whiptail", "mailcap", "reportbug", "tasksel", "console", "keyboard",
           "sysstat", "zstd", "xauth", "hdparm", "dosfstools", "gdisk", "wtmpdb", "sqv", "corepack", "dracut-install",
           "command-not-found", "dmsetup", "xdg-user-dirs", "ssl-cert", "rpcsvc-proto", "inetutils-telnet",
           "netcat-traditional", "isc-dhcp-common", "bash-completion", "ncurses-term", "runit-helper"}


def product_name(name: str) -> str | None:
    """The product an installed package belongs to, or None for packages that are not worth matching."""
    n = (name or "").strip()
    if not n or len(n) > 200:
        return None
    low = n.lower()
    if low in ALIASES:
        return ALIASES[low]
    for pre, prod in _PREFIX_ALIASES:
        if low.startswith(pre):
            return prod
    if _NOISE.match(low) or low in GENERIC:
        return None
    base = re.sub(r"\s*\([^()]*\)", " ", n).strip()               # "(x64 en-US)", "(version 2.1)"
    base = re.sub(r"[\s_-]+v?\d+(\.\d+)*([a-z]\d*)?(\s.*)?$", "", base).strip()     # trailing version numbers
    if _NOISE_SUFFIX.search(base):
        stem = _NOISE_SUFFIX.sub("", base)
        if stem.lower() in ALIASES:
            return ALIASES[stem.lower()]
        return None
    if len(base) < 3 or base.lower() in GENERIC:
        return None
    return base


def _dig(obj: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


def _rows_of(data: Any, rows_path: str = "") -> list:
    if rows_path:
        got = _dig(data, rows_path)
        if not isinstance(got, list):
            raise ValueError(f"inventory.rows: nothing is a list at {rows_path!r}")
        return got
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        hits = _dig(data, "hits.hits")
        if isinstance(hits, list):
            return [h.get("_source", h) if isinstance(h, dict) else h for h in hits]
        for path in ("data.affected_items", "items", "rows", "results", "data", "packages", "software"):
            got = _dig(data, path)
            if isinstance(got, list):
                return got
    raise ValueError("no list of inventory rows found (set inventory.rows to where the list is)")


def parse(content: str | bytes | list | dict, *, fields: dict | None = None, rows: str = "") -> list[dict]:
    """Inventory rows ``{host, name, version, vendor}`` from CSV or JSON. Rows with no host or name are skipped."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", "replace")
    if isinstance(content, str):
        text = content.lstrip("﻿").strip()
        if not text:
            return []
        if text[0] in "[{":
            data: Any = json.loads(text)
        else:
            data = list(csv.DictReader(io.StringIO(text)))
    else:
        data = content
    items = _rows_of(data, rows)
    fields = {k: v for k, v in (fields or {}).items() if k in FIELDS and v}
    out = []
    for it in items[:MAX_ROWS]:
        if not isinstance(it, dict):
            continue
        low = {str(k).strip().lower(): v for k, v in it.items()}
        row = {}
        for f in FIELDS:
            v = _dig(it, fields[f]) if f in fields else next(
                (x for x in (_dig(low, p) if "." in p else low.get(p) for p in _GUESS[f]) if x not in (None, "")), None)
            if isinstance(v, dict):
                v = v.get("name") or v.get("id")
            row[f] = str(v).strip()[:200] if v not in (None, "") else ""
        if row["host"] and row["name"]:
            out.append(row)
    return out


class Inventory:
    """Installed software per host, kept in the knowledge store's database. One snapshot per source."""

    def __init__(self, store: KnowledgeStore):
        self.store = store
        with store._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, "
                      "host TEXT NOT NULL, name TEXT NOT NULL, product TEXT DEFAULT '', version TEXT DEFAULT '', "
                      "vendor TEXT DEFAULT '', seen TEXT NOT NULL)")
            c.execute("CREATE INDEX IF NOT EXISTS assets_product ON assets(product)")
            c.execute("CREATE TABLE IF NOT EXISTS inventory_state (source TEXT PRIMARY KEY, imported TEXT, rows INTEGER, "
                      "hosts INTEGER, error TEXT DEFAULT '', tried TEXT DEFAULT '')")
            c.commit()

    def replace(self, source: str, rows: list[dict]) -> dict:
        source = (source or "file").strip()[:60]
        ts = now()
        seen = set()
        data = []
        for r in rows:
            key = (r["host"].lower(), r["name"].lower(), r.get("version", ""))
            if key in seen:
                continue
            seen.add(key)
            data.append((source, r["host"], r["name"], product_name(r["name"]) or "", r.get("version", ""),
                         r.get("vendor", ""), ts))
        hosts = len({d[1].lower() for d in data})
        with self.store._lock, self.store._conn() as c:
            c.execute("DELETE FROM assets WHERE source=?", (source,))
            for row in data:            # one by one: the PostgreSQL adapter has no executemany
                c.execute("INSERT INTO assets (source, host, name, product, version, vendor, seen) VALUES "
                          "(?,?,?,?,?,?,?)", row)
            c.execute("INSERT INTO inventory_state (source, imported, rows, hosts, error, tried) VALUES (?,?,?,?,'',?) "
                      "ON CONFLICT(source) DO UPDATE SET imported=excluded.imported, rows=excluded.rows, "
                      "hosts=excluded.hosts, error='', tried=excluded.tried", (source, ts, len(data), hosts, ts))
            c.commit()
        return {"source": source, "rows": len(data), "hosts": hosts,
                "products": len({d[3] for d in data if d[3]})}

    def record_error(self, source: str, error: str) -> None:
        with self.store._lock, self.store._conn() as c:
            c.execute("INSERT INTO inventory_state (source, imported, rows, hosts, error, tried) VALUES (?,'',0,0,?,?) "
                      "ON CONFLICT(source) DO UPDATE SET error=excluded.error, tried=excluded.tried",
                      (source, error[:300], now()))
            c.commit()

    def clear(self, source: str | None = None) -> int:
        with self.store._lock, self.store._conn() as c:
            if source:
                n = c.execute("DELETE FROM assets WHERE source=?", (source,)).rowcount
                c.execute("DELETE FROM inventory_state WHERE source=?", (source,))
            else:
                n = c.execute("DELETE FROM assets").rowcount
                c.execute("DELETE FROM inventory_state")
            c.commit()
        return n

    def sources(self) -> list[dict]:
        with self.store._conn() as c:
            rows = c.execute("SELECT source, imported, rows, hosts, error, tried FROM inventory_state "
                             "ORDER BY source").fetchall()
        return [dict(zip(("source", "imported", "rows", "hosts", "error", "tried"), r, strict=True)) for r in rows]

    def products(self) -> list[dict]:
        """Every product found, with the hosts and versions, most hosts first."""
        with self.store._conn() as c:
            rows = c.execute("SELECT product, host, version, name FROM assets WHERE product != ''").fetchall()
        by: dict[str, dict] = {}
        for prod, host, ver, name in rows:
            p = by.setdefault(prod.lower(), {"product": prod, "hosts": set(), "versions": set(), "packages": set()})
            p["hosts"].add(host)
            if ver:
                p["versions"].add(ver)
            p["packages"].add(name)
        out = [{"product": p["product"], "hosts": sorted(p["hosts"], key=str.lower), "versions": sorted(p["versions"])[:20],
                "packages": sorted(p["packages"])[:20]} for p in by.values()]
        return sorted(out, key=lambda x: (-len(x["hosts"]), x["product"].lower()))

    def hosts_by_product(self) -> dict[str, list[str]]:
        return {p["product"].lower(): p["hosts"] for p in self.products()}

    def versions_by_product(self) -> dict[str, list[tuple[str, str]]]:
        """(host, installed version) per product; one row per host and version."""
        with self.store._conn() as c:
            rows = c.execute("SELECT DISTINCT product, host, version FROM assets WHERE product != ''").fetchall()
        out: dict[str, list[tuple[str, str]]] = {}
        for prod, host, ver in rows:
            out.setdefault(prod.lower(), []).append((host, ver or ""))
        return out

    def count(self) -> int:
        with self.store._conn() as c:
            return int(c.execute("SELECT COUNT(*) FROM assets").fetchone()[0])


def matches(product: str, hosts_by_product: dict[str, list[str]]) -> list[str]:
    """The hosts running a profile product. A profile name matches an inventory product case-insensitively, or
    when the product is the profile name with words added before or after ("Proxmox" matches "Proxmox VE",
    "Outlook" matches "Microsoft Outlook"; "Nginx Proxy Manager" does not match "nginx")."""
    key = product.strip().lower()
    if not key:
        return []
    if key in hosts_by_product:
        return hosts_by_product[key]
    found: set[str] = set()
    for prod, hosts in hosts_by_product.items():
        # only a broader profile name covers a longer product name ("Proxmox" covers "Proxmox VE"), never the
        # reverse: "Nginx Proxy Manager" in the profile is not plain nginx on a host
        if len(key) >= 3 and (prod.startswith(key + " ") or prod.endswith(" " + key)):
            found.update(hosts)
    return sorted(found, key=str.lower)


_TOKEN = re.compile(r"[a-z0-9][a-z0-9.+#_-]*[a-z0-9+#]|[a-z0-9]")


def _grams(text: str, n: int = 3) -> set[str]:
    words = _TOKEN.findall(text.lower())
    out = set(words)
    for k in range(2, n + 1):
        out.update(" ".join(words[i:i + k]) for i in range(len(words) - k + 1))
    return out


def named_in_reports(store: KnowledgeStore, names: list[str], *, documents: int = 1000) -> dict[str, int]:
    """How many of the latest collected reports name each product (whole words, case-insensitive)."""
    want = {" ".join(_TOKEN.findall(n.lower())): n for n in names}
    want.pop("", None)
    counts = dict.fromkeys(want.values(), 0)
    with store._conn() as c:
        rows = c.execute("SELECT title, text FROM documents WHERE kind NOT IN ('list', 'stix') ORDER BY id DESC LIMIT ?",
                         (int(documents),)).fetchall()
    for title, text in rows:
        for g in _grams(f"{title}\n{(text or '')[:100_000]}") & want.keys():
            counts[want[g]] += 1
    return counts


KNOWN = set(ALIASES.values()) | {p for _, p in _PREFIX_ALIASES}


def suggest(inv: Inventory, profile_products: list[str], limit: int = 100, *, everything: bool = False) -> list[dict]:
    """Inventory products not yet in the profile that are worth adding: well-known products, and any product
    named in the reports collected so far. Ranked by how many reports name it, then by hosts.
    ``everything``: every product found, also the ones no report names."""
    have = {p.strip().lower() for p in profile_products}
    cands = [p for p in inv.products()
             if p["product"].lower() not in have
             and not any(matches(h, {p["product"].lower(): ["x"]}) for h in have)]
    named = named_in_reports(inv.store, [p["product"] for p in cands])
    out = []
    for p in cands:
        n = named.get(p["product"], 0)
        if not everything and not n and p["product"] not in KNOWN:
            continue
        out.append({"product": p["product"], "hosts": len(p["hosts"]), "examples": p["hosts"][:5],
                    "packages": p["packages"][:5], "reports": n, "known": p["product"] in KNOWN})
    out.sort(key=lambda x: (-x["reports"], -x["hosts"], x["product"].lower()))
    return out[:limit]


def token_ok(cfg, header: str) -> bool:
    """A bearer token for ``POST /api/inventory/import`` only (``inventory.token_env``): lets a scheduled export
    elsewhere replace the inventory without any other access."""
    import hmac
    import os
    env = str((((cfg.raw or {}).get("inventory") or {}).get("token_env") or "")) if cfg is not None else ""
    tok = os.getenv(env, "") if env else ""
    return bool(tok) and header.startswith("Bearer ") and hmac.compare_digest(header[7:].strip(), tok)


def settings(cfg) -> dict:
    raw = ((cfg.raw or {}).get("inventory") or {}) if cfg is not None else {}
    src = raw.get("from") or {}
    return {"from": src if isinstance(src, dict) and src.get("connector") else None,
            "fields": raw.get("fields") or {}, "rows": str(raw.get("rows") or ""),
            "every_hours": int(raw.get("every_hours", 24) or 0), "source": str(raw.get("source") or "connector")[:60]}


def validate(raw: dict) -> None:
    inv = raw.get("inventory")
    if inv is None:
        return
    if not isinstance(inv, dict):
        raise ValueError("inventory: a mapping (from, fields, rows, every_hours)")
    src = inv.get("from")
    if src is not None and (not isinstance(src, dict) or not src.get("connector") or not src.get("tool")):
        raise ValueError("inventory.from: needs connector and tool (and optional arguments)")
    if src and not isinstance(src.get("arguments", {}), dict):
        raise ValueError("inventory.from.arguments: a mapping")
    if inv.get("token_env") is not None and not re.fullmatch(r"[A-Z_][A-Z0-9_]*", str(inv.get("token_env") or "_")):
        raise ValueError("inventory.token_env: the name of an environment variable holding the import token")
    f = inv.get("fields")
    if f is not None and (not isinstance(f, dict) or set(f) - set(FIELDS)):
        raise ValueError(f"inventory.fields: map some of {', '.join(FIELDS)} to dotted paths")
    try:
        if int(inv.get("every_hours", 24) or 0) < 0:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("inventory.every_hours: hours between pulls (0 = only by hand)") from None


def pull(cfg, store: KnowledgeStore, *, hub=None, actor: str = "") -> dict:
    """Read the inventory from the configured connector tool and replace that source's snapshot."""
    s = settings(cfg)
    if not s["from"]:
        raise ValueError("no inventory.from connector configured")
    if hub is None:
        from ..connectors import get_hub
        hub = get_hub(cfg)
    from ..collect.collector import _unwrap
    inv = Inventory(store)
    src = s["from"]
    try:
        r = hub.call(src["connector"], src["tool"], dict(src.get("arguments") or {}), actor=actor or "inventory",
                     ref="inventory", max_bytes=50_000_000)
        if r.get("is_error"):
            raise ValueError(_unwrap(r["content"]).strip()[:300] or "the tool reported an error")
        rows = parse(_unwrap(r["content"]).strip(), fields=s["fields"], rows=s["rows"])
    except Exception as exc:
        inv.record_error(s["source"], str(exc))
        raise
    return inv.replace(s["source"], rows)


def due(cfg, store: KnowledgeStore) -> bool:
    s = settings(cfg)
    if not s["from"] or not s["every_hours"]:
        return False
    from datetime import datetime, timedelta, timezone
    st = {x["source"]: x for x in Inventory(store).sources()}.get(s["source"])
    if not st or not st.get("tried"):
        return True
    try:
        last = datetime.fromisoformat(st["tried"])        # a failed pull waits as long as a good one
    except ValueError:
        return True
    return datetime.now(timezone.utc) - last >= timedelta(hours=s["every_hours"])
