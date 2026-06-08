"""Core engine for WAYBACKRECON.

Parses Wayback/CDX exports (or plain URL lists), extracts the historical
attack surface, and flags interesting/risky URLs for defensive review.

Supported input formats (auto-detected per line):
  * CDX server output (whitespace-separated columns), e.g.
      com,example)/login?user=foo 20190101000000 https://example.com/login?user=foo text/html 200 ...
  * Plain URL lists (one URL per line), e.g. waybackurls / gau output.

Everything is standard-library only and fully offline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator
from urllib.parse import urlsplit, parse_qsl, unquote

# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return 0


# Categories of historically-interesting endpoints. Each rule is
# (category, severity, compiled-regex tested against the URL path/query).
_PATH_RULES = [
    ("backup-file", "high", r"\.(bak|old|orig|backup|swp|save|tmp|~)(\?|$)"),
    ("archive-file", "medium", r"\.(zip|tar|gz|tgz|rar|7z|sql|dump)(\?|$)"),
    ("config-file", "high", r"(^|/)(\.env|\.git|web\.config|config\.(php|json|ya?ml)|settings\.py|wp-config\.php)(\?|$|/)"),
    ("secret-file", "critical", r"(^|/)(\.htpasswd|id_rsa|\.pem|\.key|credentials|secrets?\.(json|ya?ml|txt))(\?|$)"),
    ("admin-panel", "medium", r"(^|/)(admin|administrator|wp-admin|phpmyadmin|manage|console|dashboard)(/|\?|$)"),
    ("api-endpoint", "low", r"(^|/)(api|v[0-9]+|graphql|rest|rpc)(/|\?|$)"),
    ("auth-endpoint", "medium", r"(^|/)(login|signin|signup|register|oauth|sso|token|logout|reset)(/|\?|$|\.)"),
    ("debug-endpoint", "high", r"(^|/)(debug|trace|test|phpinfo|status|actuator|server-status)(/|\?|$|\.)"),
    ("upload-endpoint", "medium", r"(^|/)(upload|uploads|fileupload|import)(/|\?|$)"),
    ("doc-file", "low", r"\.(pdf|docx?|xlsx?|csv)(\?|$)"),
]
_COMPILED_PATH_RULES = [(cat, sev, re.compile(pat, re.IGNORECASE)) for cat, sev, pat in _PATH_RULES]

# Query parameters that commonly map to a vuln class when reflected. Used to
# surface candidate parameters for *authorized* testing -- never auto-exploited.
_PARAM_HINTS = {
    "open-redirect": {"url", "redirect", "redir", "next", "return", "returnurl", "returnto", "dest", "destination", "continue", "goto", "rurl", "out"},
    "lfi-path": {"file", "path", "page", "document", "folder", "root", "pg", "template", "include", "dir"},
    "ssrf": {"uri", "host", "server", "port", "to", "target", "site", "callback", "webhook", "feed", "proxy"},
    "sqli": {"id", "uid", "user", "userid", "item", "order", "sort", "category", "cat", "product", "query", "q", "search"},
    "idor": {"id", "uid", "account", "user_id", "order_id", "invoice", "doc", "key", "number", "no"},
}
_PARAM_SEVERITY = {
    "open-redirect": "medium",
    "lfi-path": "high",
    "ssrf": "high",
    "sqli": "medium",
    "idor": "medium",
}

# Tokens that look like secrets leaked directly in query strings.
_SECRET_PARAM_RE = re.compile(
    r"(?:^|[?&])((?:api[_-]?key|apikey|access[_-]?token|auth|password|passwd|pwd|secret|client[_-]?secret|session|sessid|token|key)=[^&\s]+)",
    re.IGNORECASE,
)


@dataclass
class Finding:
    category: str
    severity: str
    url: str
    detail: str = ""
    param: str = ""
    timestamp: str = ""
    status: str = ""

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "url": self.url,
            "detail": self.detail,
            "param": self.param,
            "timestamp": self.timestamp,
            "status": self.status,
        }


@dataclass
class ReconResult:
    findings: list[Finding] = field(default_factory=list)
    total_urls: int = 0
    unique_urls: int = 0
    hosts: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    extensions: dict[str, int] = field(default_factory=dict)
    status_codes: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def as_dict(self) -> dict:
        return {
            "summary": {
                "total_urls": self.total_urls,
                "unique_urls": self.unique_urls,
                "hosts": self.hosts,
                "params": self.params,
                "extensions": self.extensions,
                "status_codes": self.status_codes,
                "severity_counts": self.severity_counts(),
                "finding_count": len(self.findings),
            },
            "findings": [f.as_dict() for f in self.findings],
            "errors": self.errors,
        }


@dataclass
class _Record:
    url: str
    timestamp: str = ""
    status: str = ""
    mimetype: str = ""


_URL_RE = re.compile(r"https?://", re.IGNORECASE)


def parse_cdx_lines(lines: Iterable[str]) -> Iterator[_Record]:
    """Yield records from CDX rows or plain URL lists. Robust to mixed input."""
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        # Plain URL on its own line.
        if len(parts) == 1 and _URL_RE.match(parts[0]):
            yield _Record(url=parts[0])
            continue
        # CDX-style: find the column that is an actual URL.
        url = next((p for p in parts if _URL_RE.match(p)), "")
        if not url:
            continue
        ts = parts[1] if len(parts) > 1 and parts[1].isdigit() else ""
        mimetype = parts[3] if len(parts) > 3 else ""
        status = parts[4] if len(parts) > 4 and parts[4].isdigit() else ""
        yield _Record(url=url, timestamp=ts, status=status, mimetype=mimetype)


def _extension_of(path: str) -> str:
    seg = path.rsplit("/", 1)[-1]
    if "." in seg:
        ext = seg.rsplit(".", 1)[-1].lower()
        if 1 <= len(ext) <= 6 and ext.isalnum():
            return ext
    return ""


def analyze(lines: Iterable[str], min_severity: str = "info") -> ReconResult:
    """Run the full recon analysis over an iterable of input lines."""
    result = ReconResult()
    seen: set[str] = set()
    hosts: set[str] = set()
    params: set[str] = set()
    threshold = severity_rank(min_severity)

    def add(f: Finding) -> None:
        if severity_rank(f.severity) >= threshold:
            result.findings.append(f)

    for rec in parse_cdx_lines(lines):
        result.total_urls += 1
        url = rec.url
        try:
            split = urlsplit(url)
        except ValueError as exc:  # malformed URL
            result.errors.append(f"unparseable url: {url[:80]} ({exc})")
            continue

        if split.hostname:
            hosts.add(split.hostname)
        if rec.status:
            result.status_codes[rec.status] = result.status_codes.get(rec.status, 0) + 1

        # Normalize for dedup (host + path + sorted query keys).
        qpairs = parse_qsl(split.query, keep_blank_values=True)
        qkeys = sorted(k for k, _ in qpairs)
        norm = f"{split.scheme}://{split.netloc}{split.path}?{'&'.join(qkeys)}"
        is_new = norm not in seen
        seen.add(norm)

        ext = _extension_of(split.path)
        if ext:
            result.extensions[ext] = result.extensions.get(ext, 0) + 1

        path_and_query = split.path + ("?" + split.query if split.query else "")

        # Only run rule evaluation once per normalized URL to avoid dupes.
        if not is_new:
            continue

        # --- path / extension rules ---
        for cat, sev, rgx in _COMPILED_PATH_RULES:
            if rgx.search(path_and_query):
                add(Finding(category=cat, severity=sev, url=url,
                            detail=f"path matches {cat} pattern",
                            timestamp=rec.timestamp, status=rec.status))

        # --- secrets leaked in query string ---
        for m in _SECRET_PARAM_RE.finditer("?" + split.query):
            leaked = unquote(m.group(1))
            key = leaked.split("=", 1)[0]
            add(Finding(category="secret-in-url", severity="critical", url=url,
                        detail=f"possible secret in query: {key}=***",
                        param=key, timestamp=rec.timestamp, status=rec.status))

        # --- parameter vuln hints ---
        for k, _v in qpairs:
            params.add(k)
            lk = k.lower()
            for vuln, names in _PARAM_HINTS.items():
                if lk in names:
                    add(Finding(category=f"param:{vuln}", severity=_PARAM_SEVERITY[vuln], url=url,
                                detail=f"param '{k}' commonly tested for {vuln}",
                                param=k, timestamp=rec.timestamp, status=rec.status))

    result.unique_urls = len(seen)
    result.hosts = sorted(hosts)
    result.params = sorted(params)
    result.extensions = dict(sorted(result.extensions.items(), key=lambda kv: (-kv[1], kv[0])))
    result.status_codes = dict(sorted(result.status_codes.items()))
    # Stable, severity-first ordering for output.
    result.findings.sort(key=lambda f: (-severity_rank(f.severity), f.category, f.url))
    return result
