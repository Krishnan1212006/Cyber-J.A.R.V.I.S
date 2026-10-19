"""
The Hacker News Data Provider Abstraction.
Implements resilient, zero-browser data ingestion using THN's Blogger JSON feed
and lightweight HTML parsing for full article bodies.
"""

from __future__ import annotations
import abc
import json
import logging
import random
import time
from typing import Any, Generator, Optional
from urllib.parse import urlencode

import bs4
import dateutil.parser
import requests

from .config import load_cyber_config
from .models import Article, utc_now_iso
from .security import (
    sanitize_text,
    normalize_url,
    compute_content_hash,
)

logger = logging.getLogger("intel.thn_provider")


class BaseDataProvider(abc.ABC):
    """Abstract interface for cybersecurity news data providers."""

    @abc.abstractmethod
    def collect_latest(self, limit: int = 20) -> list[dict[str, Any]]:
        """Fetch metadata for the latest published articles."""
        pass

    @abc.abstractmethod
    def collect_historical(
        self,
        start_date: str,
        end_date: str,
        max_articles: Optional[int] = None,
        start_offset: int = 1,
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Yield historical article batches within the given date bounds."""
        pass

    @abc.abstractmethod
    def fetch_article(self, url: str) -> dict[str, Any]:
        """Fetch and extract full article body and metadata from the given URL."""
        pass

    @abc.abstractmethod
    def normalize_article(self, raw_data: dict[str, Any]) -> Optional[Article]:
        """Convert raw entry data into a validated, normalized Article instance."""
        pass


class THNDataProvider(BaseDataProvider):
    """
    Data provider for The Hacker News (https://thehackernews.com/).
    Combines the fast Blogger JSON feed for feed metadata with clean HTML extraction
    for article full-text content.
    """

    FEED_BASE_URL = "https://thehackernews.com/feeds/posts/default"

    def __init__(self, config: Optional[dict[str, Any]] = None):
        self.config = config or load_cyber_config()
        self.rate_delay = float(self.config.get("rate_limit_delay_seconds", 1.0))
        self.timeout = int(self.config.get("request_timeout_seconds", 15))
        self.max_retries = int(self.config.get("max_retries", 3))
        self.user_agent = self.config.get("user_agent", "JARVIS Cyber-Intel/1.0")

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": self.user_agent,
                "Accept": "application/json, text/html, application/xhtml+xml, */*",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )

    def _polite_sleep(self) -> None:
        """Enforce polite request delay with subtle jitter."""
        jitter = random.uniform(0.1, 0.4)
        time.sleep(self.rate_delay + jitter)

    def _http_get(self, url: str, params: Optional[dict] = None) -> requests.Response:
        """Execute HTTP GET with automatic retries and exponential backoff."""
        for attempt in range(1, self.max_retries + 1):
            try:
                self._polite_sleep()
                resp = self.session.get(url, params=params, timeout=self.timeout)
                if resp.status_code == 200:
                    return resp
                if resp.status_code in (429, 500, 502, 503, 504):
                    wait = (2 ** attempt) + random.uniform(0.5, 1.5)
                    logger.warning(
                        f"HTTP {resp.status_code} for {url}. Backing off {wait:.1f}s (attempt {attempt}/{self.max_retries})"
                    )
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
            except (requests.RequestException, TimeoutError) as exc:
                if attempt == self.max_retries:
                    raise
                wait = (2 ** attempt) + random.uniform(0.5, 1.5)
                logger.warning(
                    f"Request failed: {exc}. Retrying in {wait:.1f}s (attempt {attempt}/{self.max_retries})"
                )
                time.sleep(wait)

        raise requests.RequestException(f"Failed to fetch {url} after {self.max_retries} attempts.")

    # ── Latest Ingestion ───────────────────────────────────────────────────────

    def collect_latest(self, limit: int = 20) -> list[dict[str, Any]]:
        """
        Fetch latest articles from THN Blogger JSON feed.
        """
        # Maximum allowed per request on Blogger is typically 150
        batch_limit = min(max(1, limit), 150)
        params = {
            "alt": "json",
            "max-results": str(batch_limit),
            "start-index": "1",
        }

        resp = self._http_get(self.FEED_BASE_URL, params=params)
        data = resp.json()
        entries = data.get("feed", {}).get("entry", [])
        return entries[:limit]

    # ── Historical Ingestion ───────────────────────────────────────────────────

    def collect_historical(
        self,
        start_date: str,
        end_date: str,
        max_articles: Optional[int] = None,
        start_offset: int = 1,
    ) -> Generator[list[dict[str, Any]], None, None]:
        """
        Yield batches of historical articles published between start_date and end_date.
        Dates are parsed to ISO 8601 UTC.
        Paginates using start-index in chunks of up to 100.
        """
        # Parse boundary dates
        try:
            start_dt = dateutil.parser.parse(start_date)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=dateutil.tz.tzutc())
        except Exception as e:
            raise ValueError(f"Invalid start_date '{start_date}': {e}")

        try:
            end_dt = dateutil.parser.parse(end_date)
            if end_dt.tzinfo is None:
                # End of the specified day
                end_dt = end_dt.replace(hour=23, minute=59, second=59, tzinfo=dateutil.tz.tzutc())
        except Exception as e:
            raise ValueError(f"Invalid end_date '{end_date}': {e}")

        batch_size = 50
        current_offset = max(1, start_offset)
        collected_total = 0
        reached_end = False

        while not reached_end:
            if max_articles is not None and collected_total >= max_articles:
                break

            params = {
                "alt": "json",
                "max-results": str(batch_size),
                "start-index": str(current_offset),
            }

            try:
                resp = self._http_get(self.FEED_BASE_URL, params=params)
                data = resp.json()
            except Exception as e:
                logger.error(f"Error fetching batch at offset {current_offset}: {e}")
                break

            entries = data.get("feed", {}).get("entry", [])
            if not entries:
                # No more entries available
                break

            matching_batch = []
            for entry in entries:
                pub_raw = entry.get("published", {}).get("$t")
                if not pub_raw:
                    continue

                try:
                    pub_dt = dateutil.parser.parse(pub_raw)
                    if pub_dt.tzinfo is None:
                        pub_dt = pub_dt.replace(tzinfo=dateutil.tz.tzutc())
                except Exception:
                    continue

                # If entry is newer than end_date, skip and continue walking back
                if pub_dt > end_dt:
                    continue

                # If entry is older than start_date, we have reached past our lower bound
                if pub_dt < start_dt:
                    reached_end = True
                    break

                matching_batch.append(entry)
                collected_total += 1
                if max_articles is not None and collected_total >= max_articles:
                    reached_end = True
                    break

            if matching_batch:
                yield matching_batch

            current_offset += len(entries)
            # If the server returned fewer than requested, we reached the end of the feed
            if len(entries) < batch_size:
                break

    # ── Fetch Full Article HTML ────────────────────────────────────────────────

    def fetch_article(self, url: str) -> dict[str, Any]:
        """
        Fetch HTML page and parse clean article body and metadata.
        """
        canonical = normalize_url(url)
        resp = self._http_get(canonical)
        soup = bs4.BeautifulSoup(resp.text, "html.parser")

        # Find main article content container
        body_el = (
            soup.find("div", {"id": "articlebody"})
            or soup.find("div", {"class": "articlebody"})
            or soup.find("div", {"class": "post-body"})
            or soup.find("article")
        )

        content = ""
        if body_el:
            # Strip unwanted tags (scripts, styles, ads, social shares)
            for unwanted in body_el(["script", "style", "noscript", "iframe", "svg", "form"]):
                unwanted.decompose()

            for ad_box in body_el.find_all(class_=lambda c: c and any(w in c.lower() for w in ("ad", "banner", "social", "related"))):
                ad_box.decompose()

            # Extract clean paragraphs and headings
            paragraphs = []
            for p in body_el.find_all(["p", "h2", "h3", "h4", "li"]):
                txt = p.get_text().strip()
                if txt and len(txt) > 20:
                    paragraphs.append(txt)

            content = "\n\n".join(paragraphs) if paragraphs else body_el.get_text(separator="\n\n").strip()

        # Extract title if not in feed
        title = ""
        title_el = soup.find("h1", {"class": "story-title"}) or soup.find("h1")
        if title_el:
            title = title_el.get_text().strip()

        # Extract tags
        tags = []
        tag_container = soup.find("div", {"class": "tags"}) or soup.find("span", {"class": "tag"})
        if tag_container:
            tags = [t.get_text().strip() for t in tag_container.find_all("a") if t.get_text().strip()]

        return {
            "url": canonical,
            "title": title,
            "content": sanitize_text(content),
            "tags": tags,
        }

    # ── Article Normalization ──────────────────────────────────────────────────

    def normalize_article(self, raw_data: dict[str, Any]) -> Optional[Article]:
        """
        Convert raw feed entry dictionary (or hybrid entry + page dict) into a validated Article.
        Returns None if essential fields (title, url, published_at) are missing.
        """
        if not isinstance(raw_data, dict):
            return None

        # 1. Extract Post ID
        raw_id = raw_data.get("id", {})
        article_id_str = raw_id.get("$t", "") if isinstance(raw_id, dict) else str(raw_data.get("article_id", ""))
        # If blogger tag format: tag:blogger.com,1999:blog-ID.post-POSTID
        if "post-" in article_id_str:
            article_id = "thn_" + article_id_str.split("post-")[-1]
        elif article_id_str:
            article_id = article_id_str
        else:
            article_id = ""

        # 2. Extract Title
        title_val = raw_data.get("title", {})
        title = title_val.get("$t", "") if isinstance(title_val, dict) else str(raw_data.get("title", ""))
        title = sanitize_text(title)
        if not title:
            return None

        # 3. Extract Canonical URL
        url = ""
        links = raw_data.get("link", [])
        if isinstance(links, list):
            for link in links:
                if isinstance(link, dict) and link.get("rel") == "alternate":
                    url = link.get("href", "")
                    break
            # Fallback to first link href
            if not url and links and isinstance(links[0], dict):
                url = links[0].get("href", "")
        if not url:
            url = str(raw_data.get("url", ""))

        canonical_url = normalize_url(url)
        if not canonical_url:
            return None

        # If article_id was empty, derive deterministically from canonical URL
        if not article_id:
            import hashlib
            url_hash = hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()[:16]
            article_id = f"thn_{url_hash}"

        # 4. Extract Author
        author = "The Hacker News"
        authors = raw_data.get("author", [])
        if isinstance(authors, list) and authors:
            name = authors[0].get("name", {}).get("$t") if isinstance(authors[0], dict) else None
            if name:
                author = sanitize_text(name)
        elif "author" in raw_data and isinstance(raw_data["author"], str):
            author = sanitize_text(raw_data["author"])

        # 5. Extract Timestamps
        pub_raw = raw_data.get("published", {})
        pub_str = pub_raw.get("$t") if isinstance(pub_raw, dict) else raw_data.get("published_at")
        if not pub_str:
            return None

        try:
            pub_dt = dateutil.parser.parse(str(pub_str))
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=dateutil.tz.tzutc())
            published_at = pub_dt.astimezone(dateutil.tz.tzutc()).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return None

        upd_raw = raw_data.get("updated", {})
        upd_str = upd_raw.get("$t") if isinstance(upd_raw, dict) else raw_data.get("updated_at")
        updated_at = ""
        if upd_str:
            try:
                upd_dt = dateutil.parser.parse(str(upd_str))
                if upd_dt.tzinfo is None:
                    upd_dt = upd_dt.replace(tzinfo=dateutil.tz.tzutc())
                updated_at = upd_dt.astimezone(dateutil.tz.tzutc()).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                updated_at = published_at
        else:
            updated_at = published_at

        # 6. Extract Summary
        sum_val = raw_data.get("summary", {})
        summary = sum_val.get("$t", "") if isinstance(sum_val, dict) else str(raw_data.get("summary", ""))
        # Strip HTML if present in summary
        if "<" in summary and ">" in summary:
            summary = bs4.BeautifulSoup(summary, "html.parser").get_text(separator=" ").strip()
        summary = sanitize_text(summary)

        # 7. Extract Content
        content = str(raw_data.get("content", "")).strip()
        if not content:
            # Fall back to summary if full body hasn't been fetched yet
            content = summary
        content = sanitize_text(content)

        # 8. Extract Tags & Category
        tags: list[str] = []
        raw_categories = raw_data.get("category", [])
        if isinstance(raw_categories, list):
            for cat in raw_categories:
                if isinstance(cat, dict):
                    term = cat.get("term", "")
                    if term:
                        tags.append(sanitize_text(term))
        if "tags" in raw_data and isinstance(raw_data["tags"], list):
            tags.extend([sanitize_text(str(t)) for t in raw_data["tags"]])
        # Deduplicate tags
        tags = sorted(list({t for t in tags if t and len(t) <= 64}))

        # Feature name / category
        category = "Cybersecurity"
        feature = raw_data.get("georss$featurename", {})
        if isinstance(feature, dict) and feature.get("$t"):
            category = sanitize_text(feature["$t"])

        # 9. Compute Content Hash
        content_hash = compute_content_hash(content or summary or title)

        return Article(
            article_id=article_id,
            source="thehackernews",
            title=title,
            url=canonical_url,
            author=author,
            published_at=published_at,
            collected_at=utc_now_iso(),
            category=category,
            tags=tags,
            summary=summary,
            content=content,
            content_hash=content_hash,
            updated_at=updated_at,
            raw_html_path=raw_data.get("raw_html_path"),
            analysis_status="pending",
        )
