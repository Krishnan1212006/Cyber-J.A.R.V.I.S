"""
Security and sanitization utilities for untrusted web content.

All scraped web content (HTML, text, RSS feeds, JSON) is treated as UNTRUSTED DATA.
Articles must never be evaluated, executed, or allowed to alter JARVIS instructions,
API keys, system configuration, or user memory.
"""

from __future__ import annotations
import hashlib
import re
import unicodedata
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode


# Query parameters commonly used for tracking that should be stripped for canonicalization
_TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "fbclid",
    "gclid",
    "gclsrc",
    "dclid",
    "msclkid",
    "ref",
    "ref_src",
    "source",
    "m",  # Blogger mobile switcher (?m=1)
}

# Regex to strip non-printable ASCII control characters except newline (\n), carriage return (\r), and tab (\t)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(text: str) -> str:
    """
    Sanitize untrusted text.
    - Strips NULL bytes and dangerous non-printable ASCII control characters.
    - Normalizes Unicode to NFKC.
    - Preserves normal punctuation and readable formatting.
    """
    if not text:
        return ""

    # Normalize Unicode form
    clean = unicodedata.normalize("NFKC", text)

    # Strip control characters
    clean = _CONTROL_CHAR_RE.sub("", clean)

    # Normalize carriage returns
    clean = clean.replace("\r\n", "\n").replace("\r", "\n")

    return clean.strip()


def normalize_url(url: str) -> str:
    """
    Produce a canonical normalized URL for deduplication.
    - Forces HTTPS scheme.
    - Lowercases scheme and netloc/domain.
    - Strips tracking query parameters (utm_*, fbclid, m=1, etc.).
    - Removes URL fragments (#...).
    - Removes trailing slash from path (unless path is empty or single slash).
    """
    if not url or not isinstance(url, str):
        return ""

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception:
        return url.strip()

    scheme = "https"  # Always canonicalize to https for THN
    netloc = parsed.netloc.lower()

    # If port 443 is explicitly specified, strip it
    if netloc.endswith(":443"):
        netloc = netloc[:-4]

    # Normalize path: remove trailing slash if length > 1
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Strip tracking query parameters
    query_items = parse_qsl(parsed.query, keep_blank_values=False)
    filtered_query = [(k, v) for k, v in query_items if k.lower() not in _TRACKING_PARAMS]
    # Sort remaining parameters for deterministic hashing
    filtered_query.sort(key=lambda x: x[0])
    query = urlencode(filtered_query)

    # Construct canonical URL (fragment is omitted)
    canonical = urlunparse((scheme, netloc, path, "", query, ""))
    return canonical


def compute_content_hash(text: str) -> str:
    """
    Compute deterministic SHA-256 hash of normalized article content.
    Whitespace is collapsed and text is case-folded to make the hash robust
    against cosmetic whitespace or markup jitter.
    """
    if not text:
        return hashlib.sha256(b"").hexdigest()

    # Normalize whitespace and case-fold
    normalized = " ".join(text.casefold().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def wrap_untrusted(text: str, source: str = "thehackernews") -> str:
    """
    Wrap untrusted article content in strict boundaries.
    When this content is later passed to an AI model for analysis or RAG,
    the model will treat the enclosed data strictly as passive input.
    """
    sanitized = sanitize_text(text)
    return (
        f'<untrusted_cyber_article source="{source}">\n'
        f"{sanitized}\n"
        f"</untrusted_cyber_article>"
    )
