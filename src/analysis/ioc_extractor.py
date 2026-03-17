import re

# Compiled regex patterns for common IOC types
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_URL = re.compile(r"https?://[^\s\"'<>]+")
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Private/reserved IP ranges to exclude from IOC results
_PRIVATE_RANGES = re.compile(
    r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0|255\.)"
)


def extract_iocs(text: str) -> dict[str, list[str]]:
    """
    Extract indicators of compromise from raw text.
    Returns a dict with categorised IOCs — useful for threat intel feeds.
    """
    ips = [
        ip for ip in _IPV4.findall(text)
        if not _PRIVATE_RANGES.match(ip)
    ]
    domains = _DOMAIN.findall(text)
    urls = _URL.findall(text)
    emails = _EMAIL.findall(text)
    md5s = _MD5.findall(text)
    sha256s = _SHA256.findall(text)
    cves = _CVE.findall(text)

    return {
        "ips": list(set(ips)),
        "domains": list(set(domains)),
        "urls": list(set(urls)),
        "emails": list(set(emails)),
        "md5s": list(set(md5s)),
        "sha256s": list(set(sha256s)),
        "cves": list(set(cves)),
    }


def flatten_iocs(ioc_dict: dict[str, list[str]]) -> list[str]:
    """Flatten categorised IOCs into a single list for storage."""
    result = []
    for category, values in ioc_dict.items():
        for value in values:
            result.append(f"{category[:-1]}:{value}")  # e.g. "ip:1.2.3.4"
    return result