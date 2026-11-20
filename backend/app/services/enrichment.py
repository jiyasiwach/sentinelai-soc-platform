"""IOC extraction and threat-intelligence enrichment (local TI feed, no network calls)."""

from __future__ import annotations

import ipaddress
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
MAX_IOCS = 200

INTERNAL_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",  # RFC1918
        "100.64.0.0/10",  # CGNAT
        "169.254.0.0/16",  # link-local
        "127.0.0.0/8",  # loopback
    )
]

RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
RE_URL = re.compile(r"\b(?:https?|hxxps?|ftp)://[^\s\"'<>`{}|\\^]+", re.I)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_DOMAIN = re.compile(
    r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-]|\.[a-z0-9])", re.I
)

GENERIC_TLDS = {
    "com",
    "net",
    "org",
    "info",
    "biz",
    "io",
    "co",
    "app",
    "dev",
    "xyz",
    "top",
    "online",
    "site",
    "club",
    "shop",
    "store",
    "live",
    "tech",
    "cloud",
    "link",
    "click",
    "win",
    "bid",
    "loan",
    "work",
    "zip",
    "mov",
    "onion",
    "example",
    "test",
    "gov",
    "edu",
    "mil",
    "int",
    "pro",
    "mobi",
    "asia",
    "tel",
    "lol",
    "icu",
    "buzz",
    "rest",
    "fun",
    "space",
    "website",
    "host",
    "network",
    "services",
    "support",
    "email",
    "invalid",
}
# File extensions that collide with 2-letter ccTLDs (or are common in logs) - never treat as domains.
FILE_EXTENSIONS = {
    "exe",
    "dll",
    "sys",
    "ps",
    "ps1",
    "psm1",
    "bat",
    "cmd",
    "vbs",
    "js",
    "jse",
    "hta",
    "scr",
    "msi",
    "lnk",
    "py",
    "sh",
    "pl",
    "rb",
    "cs",
    "md",
    "so",
    "db",
    "gz",
    "bz",
    "xz",
    "ts",
    "rs",
    "go",
    "kt",
    "hs",
    "jar",
    "doc",
    "docx",
    "docm",
    "xls",
    "xlsx",
    "xlsm",
    "ppt",
    "pptx",
    "pdf",
    "txt",
    "log",
    "csv",
    "json",
    "xml",
    "html",
    "htm",
    "php",
    "asp",
    "aspx",
    "jsp",
    "cfg",
    "conf",
    "ini",
    "tmp",
    "dat",
    "bin",
    "iso",
    "img",
    "jpg",
    "jpeg",
    "png",
    "gif",
    "bmp",
    "svg",
    "rar",
    "tar",
    "tgz",
    "7z",
    "locked",
    "enc",
    "bak",
    "old",
}
INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".corp", ".localdomain", ".home.arpa", ".intranet")


def is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in INTERNAL_NETS)


def _valid_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not (ip.is_unspecified or ip == ipaddress.IPv4Address("255.255.255.255"))


def _tld_ok(tld: str) -> bool:
    tld = tld.lower()
    if tld in FILE_EXTENSIONS:
        return False
    return len(tld) == 2 or tld in GENERIC_TLDS


def _string_values(obj: Any, out: list[str], depth: int = 0) -> None:
    """Collect string values (not keys) so field names like `host.name` or `rule.id` never become IOCs."""
    if depth > 12 or len(out) > 5000:
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _string_values(v, out, depth + 1)
    elif isinstance(obj, list | tuple):
        for v in obj:
            _string_values(v, out, depth + 1)
    elif isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, int | float) and not isinstance(obj, bool):
        out.append(str(obj))


def extract_iocs(*sources: Any) -> list[dict]:
    """Extract IOCs from any mix of strings/dicts/lists. Returns [{type, value}] de-duplicated."""
    texts: list[str] = []
    for src in sources:
        _string_values(src, texts)
    text = "\n".join(texts)

    found: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        key = (kind, value.lower())
        if key not in seen and len(found) < MAX_IOCS:
            seen.add(key)
            found.append({"type": kind, "value": value})

    urls = [u.rstrip(".,;:)]'\"") for u in RE_URL.findall(text)]
    for u in urls:
        add("url", u)
    emails = RE_EMAIL.findall(text)
    for e in emails:
        add("email", e.lower())
    for h in RE_SHA256.findall(text):
        add("sha256", h.lower())
    for h in RE_SHA1.findall(text):
        add("sha1", h.lower())
    for h in RE_MD5.findall(text):
        add("md5", h.lower())
    for c in RE_CVE.findall(text):
        add("cve", c.upper())

    # Remove emails and hashes before IP/domain scanning so their parts are not re-extracted.
    scrub = RE_EMAIL.sub(" ", text)
    for ip in RE_IPV4.findall(scrub):
        if _valid_ipv4(ip):
            add("ip", ip)
    for u in urls:  # URL hosts are domains/IPs worth enriching
        host = (urlparse(u.replace("hxxp", "http")).hostname or "").lower()
        if (
            host
            and not _valid_ipv4(host)
            and "." in host
            and _tld_ok(host.rsplit(".", 1)[1])
            and not host.endswith(INTERNAL_SUFFIXES)
        ):
            add("domain", host)
    for m in RE_DOMAIN.finditer(scrub):
        domain, tld = m.group(1).lower(), m.group(2)
        if not _tld_ok(tld) or domain.endswith(INTERNAL_SUFFIXES):
            continue
        labels = domain.split(".")
        if any(label.isdigit() for label in labels):
            continue
        add("domain", domain)
    return found


@lru_cache
def load_threat_intel() -> dict:
    with open(DATA_DIR / "threat_intel.json", encoding="utf-8") as fh:
        data = json.load(fh)
    # Normalise keys to lower case for lookups
    return {
        section: {k.lower(): v for k, v in entries.items()}
        for section, entries in data.items()
        if isinstance(entries, dict)
    }


_SECTION = {
    "ip": "ips",
    "domain": "domains",
    "url": "urls",
    "email": "emails",
    "md5": "hashes",
    "sha1": "hashes",
    "sha256": "hashes",
}


def _lookup(kind: str, value: str) -> dict | None:
    ti = load_threat_intel()
    section = ti.get(_SECTION.get(kind, ""), {})
    hit = section.get(value.lower())
    if hit:
        return hit
    if kind == "url":
        host = (urlparse(value).hostname or "").lower()
        return ti.get("domains", {}).get(host) or ti.get("ips", {}).get(host)
    if kind == "email":
        return ti.get("domains", {}).get(value.split("@")[-1].lower())
    if kind == "domain":
        parts = value.lower().split(".")
        for i in range(1, len(parts) - 1):  # parent domain match
            parent = ".".join(parts[i:])
            if parent in ti.get("domains", {}):
                return ti["domains"][parent]
    return None


def enrich_ioc(ioc: dict) -> dict:
    kind, value = ioc["type"], ioc["value"]
    out = {
        "type": kind,
        "value": value,
        "reputation": "unknown",
        "score": 0,
        "tags": [],
        "country": "",
        "asn": "",
        "malware_family": "",
        "source": "local-ti",
    }
    if kind == "ip":
        out["internal"] = is_internal_ip(value)
        if out["internal"]:
            out["tags"] = ["internal"]
    if kind == "cve":
        out["source"] = "nvd-link"
        return out
    hit = _lookup(kind, value)
    if hit:
        out.update(
            {
                "reputation": hit.get("reputation", "unknown"),
                "score": int(hit.get("score", 0)),
                "tags": list(hit.get("tags", [])),
                "country": hit.get("country", ""),
                "asn": hit.get("asn", ""),
                "malware_family": hit.get("malware_family", ""),
                "description": hit.get("description", ""),
            }
        )
    return out


def enrich_iocs(iocs: list[dict]) -> list[dict]:
    return [enrich_ioc(i) for i in iocs]


def summarize_ti(enriched: list[dict]) -> dict:
    counts = {"malicious": 0, "suspicious": 0, "benign": 0, "unknown": 0}
    for e in enriched:
        counts[e.get("reputation", "unknown") if e.get("reputation") in counts else "unknown"] += 1
    return counts
