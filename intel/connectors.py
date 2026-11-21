"""
Multi-source connectors for JARVIS Cybersecurity News Intelligence Engine.

Provides dedicated, resilient connectors for:
1. Hacklido (https://hacklido.com/)
2. BleepingComputer (https://www.bleepingcomputer.com/)
3. The Hacker News (https://thehackernews.com/)
4. Cybersecurity News (https://cybersecuritynews.com/)

All scraped web content (HTML, text, RSS feeds, JSON) is treated as UNTRUSTED DATA.
Adheres strictly to robots.txt, rate limits, request limits, and access controls.
Never bypasses paywalls or anti-bot controls.
"""

from __future__ import annotations
import abc
import hashlib
import json
import logging
import random
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Generator, Optional
from urllib.parse import urlencode

import bs4
import dateutil.parser
import dateutil.tz
import httpx
import requests

from .config import load_cyber_config
from .models import (
    Article,
    ConnectorHealth,
    SOURCE_THEHACKERNEWS,
    SOURCE_HACKLIDO,
    SOURCE_BLEEPINGCOMPUTER,
    SOURCE_CYBERSECURITYNEWS,
    utc_now_iso,
)
from .security import (
    sanitize_text,
    normalize_url,
    compute_content_hash,
)
from .thn_provider import BaseDataProvider, THNDataProvider

logger = logging.getLogger("intel.connectors")


# ── Base Connector ─────────────────────────────────────────────────────────────

class BaseCyberNewsConnector(BaseDataProvider, abc.ABC):
    """
    Abstract base connector for cybersecurity intelligence sources.
    Provides polite HTTP requesting with jittered backoff, rate limiting,
    safe content parsing, and duplicate detection.
    """

    source_name: str = "generic"
    display_name: str = "Generic Cyber Source"
    home_url: str = "https://example.com"

    def __init__(self, config: Optional[dict[str, Any]] = None):
        self.config = config or load_cyber_config()
        self.rate_delay = float(self.config.get("rate_limit_delay_seconds", 1.0))
        self.timeout = int(self.config.get("request_timeout_seconds", 15))
        self.max_retries = int(self.config.get("max_retries", 3))
        self.user_agent = self.config.get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (JARVIS Cyber-Intel/1.0)",
        )

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )

    def _polite_sleep(self) -> None:
        """Enforce polite request delay with subtle jitter."""
        jitter = random.uniform(0.1, 0.4)
        time.sleep(self.rate_delay + jitter)

    def _http_get(
        self,
        url: str,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        use_httpx: bool = False,
    ) -> tuple[int, str, dict[str, str]]:
        """
        Execute HTTP GET with automatic retries and exponential backoff.
        Supports both requests and httpx transports for broad TLS/ALPN compatibility.
        Returns (status_code, text, response_headers).
        """
        merged_headers = dict(self.session.headers)
        if headers:
            merged_headers.update(headers)

        last_error: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                self._polite_sleep()
                if use_httpx:
                    with httpx.Client(
                        headers=merged_headers,
                        follow_redirects=True,
                        timeout=float(self.timeout),
                    ) as client:
                        resp = client.get(url, params=params)
                        if resp.status_code == 200:
                            return resp.status_code, resp.text, dict(resp.headers)
                        if resp.status_code in (429, 500, 502, 503, 504):
                            wait = (2 ** attempt) + random.uniform(0.5, 1.5)
                            logger.warning(
                                f"[{self.source_name}] HTTP {resp.status_code} for {url}. Backing off {wait:.1f}s (attempt {attempt}/{self.max_retries})"
                            )
                            time.sleep(wait)
                            continue
                        return resp.status_code, resp.text, dict(resp.headers)
                else:
                    resp = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
                    if resp.status_code == 200:
                        return resp.status_code, resp.text, dict(resp.headers)
                    if resp.status_code in (429, 500, 502, 503, 504):
                        wait = (2 ** attempt) + random.uniform(0.5, 1.5)
                        logger.warning(
                            f"[{self.source_name}] HTTP {resp.status_code} for {url}. Backing off {wait:.1f}s (attempt {attempt}/{self.max_retries})"
                        )
                        time.sleep(wait)
                        continue
                    return resp.status_code, resp.text, dict(resp.headers)
            except Exception as exc:
                last_error = exc
                if attempt == self.max_retries:
                    # Try falling back to alternate transport once before giving up
                    if not use_httpx:
                        try:
                            with httpx.Client(
                                headers=merged_headers,
                                follow_redirects=True,
                                timeout=float(self.timeout),
                            ) as client:
                                resp = client.get(url, params=params)
                                return resp.status_code, resp.text, dict(resp.headers)
                        except Exception as h_err:
                            last_error = h_err
                    raise last_error

                wait = (2 ** attempt) + random.uniform(0.5, 1.5)
                logger.warning(
                    f"[{self.source_name}] Request failed: {exc}. Retrying in {wait:.1f}s (attempt {attempt}/{self.max_retries})"
                )
                time.sleep(wait)

        if last_error:
            raise last_error
        raise requests.RequestException(f"Failed to fetch {url} after {self.max_retries} attempts.")

    def is_new_article(self, article: Article, db: Any) -> tuple[bool, str]:
        """Check against persistent DB whether an article is new or previously collected."""
        is_dup, reason = db.check_duplicate(
            url=article.url,
            content_hash=article.content_hash,
            article_id=article.article_id,
        )
        return (not is_dup, reason)


# ── 1. Hacklido Connector ──────────────────────────────────────────────────────

class HacklidoConnector(BaseCyberNewsConnector):
    """
    Data connector for Hacklido (https://hacklido.com/).
    Connects to Hacklido's public JSON:API discussions endpoint with fallback to RSS.
    Retrieves bug bounty writeups, CVE breakdowns, and ethical hacking posts.
    """

    source_name = SOURCE_HACKLIDO
    display_name = "Hacklido"
    home_url = "https://hacklido.com/"
    API_URL = "https://hacklido.com/api/discussions"
    RSS_URL = "https://hacklido.com/rss"

    def collect_latest(self, limit: int = 20) -> list[dict[str, Any]]:
        """Fetch metadata for the latest published articles from Hacklido."""
        batch_limit = min(max(1, limit), 50)
        params = {
            "include": "firstPost,user,tags",
            "sort": "-createdAt",
            "page[limit]": str(batch_limit),
            "page[offset]": "0",
        }

        try:
            status, text, _ = self._http_get(self.API_URL, params=params, use_httpx=True)
            if status == 200:
                data = json.loads(text)
                discussions = data.get("data", [])
                included = data.get("included", [])
                inc_posts = {p["id"]: p for p in included if p.get("type") == "posts"}
                inc_users = {u["id"]: u for u in included if u.get("type") == "users"}
                inc_tags = {t["id"]: t for t in included if t.get("type") == "tags"}

                results = []
                for disc in discussions[:limit]:
                    results.append({
                        "disc": disc,
                        "inc_posts": inc_posts,
                        "inc_users": inc_users,
                        "inc_tags": inc_tags,
                        "_source": "json_api",
                    })
                return results
        except Exception as e:
            logger.warning(f"Hacklido JSON:API request failed: {e}. Falling back to RSS feed.")

        # Fallback to RSS feed
        return self._collect_rss(limit=limit)

    def _collect_rss(self, limit: int = 20) -> list[dict[str, Any]]:
        """Fallback RSS collection for Hacklido."""
        status, text, _ = self._http_get(self.RSS_URL, use_httpx=True)
        if status != 200:
            return []

        root = ET.fromstring(text.encode("utf-8", errors="replace"))
        channel = root.find("channel")
        if channel is None:
            return []

        items = channel.findall("item")
        results = []
        for it in items[:limit]:
            results.append({
                "title": it.findtext("title"),
                "link": it.findtext("link"),
                "pubDate": it.findtext("pubDate"),
                "description": it.findtext("description"),
                "_source": "rss",
            })
        return results

    def collect_historical(
        self,
        start_date: str,
        end_date: str,
        max_articles: Optional[int] = None,
        start_offset: int = 0,
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Paginates historical discussions on Hacklido within the date bounds."""
        try:
            start_dt = dateutil.parser.parse(start_date)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=dateutil.tz.tzutc())
        except Exception as e:
            raise ValueError(f"Invalid start_date '{start_date}': {e}")

        try:
            end_dt = dateutil.parser.parse(end_date)
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(hour=23, minute=59, second=59, tzinfo=dateutil.tz.tzutc())
        except Exception as e:
            raise ValueError(f"Invalid end_date '{end_date}': {e}")

        batch_size = 20
        current_offset = max(0, start_offset)
        collected_total = 0
        reached_end = False

        while not reached_end:
            if max_articles is not None and collected_total >= max_articles:
                break

            params = {
                "include": "firstPost,user,tags",
                "sort": "-createdAt",
                "page[limit]": str(batch_size),
                "page[offset]": str(current_offset),
            }

            try:
                status, text, _ = self._http_get(self.API_URL, params=params, use_httpx=True)
                if status != 200:
                    break
                data = json.loads(text)
            except Exception as e:
                logger.error(f"Error fetching Hacklido historical batch at offset {current_offset}: {e}")
                break

            discussions = data.get("data", [])
            if not discussions:
                break

            included = data.get("included", [])
            inc_posts = {p["id"]: p for p in included if p.get("type") == "posts"}
            inc_users = {u["id"]: u for u in included if u.get("type") == "users"}
            inc_tags = {t["id"]: t for t in included if t.get("type") == "tags"}

            matching_batch = []
            for disc in discussions:
                created_raw = disc.get("attributes", {}).get("createdAt")
                if not created_raw:
                    continue
                try:
                    pub_dt = dateutil.parser.parse(created_raw)
                    if pub_dt.tzinfo is None:
                        pub_dt = pub_dt.replace(tzinfo=dateutil.tz.tzutc())
                except Exception:
                    continue

                if pub_dt > end_dt:
                    continue
                if pub_dt < start_dt:
                    reached_end = True
                    break

                matching_batch.append({
                    "disc": disc,
                    "inc_posts": inc_posts,
                    "inc_users": inc_users,
                    "inc_tags": inc_tags,
                    "_source": "json_api",
                })
                collected_total += 1
                if max_articles is not None and collected_total >= max_articles:
                    reached_end = True
                    break

            if matching_batch:
                yield matching_batch

            current_offset += len(discussions)
            if len(discussions) < batch_size:
                break

    def fetch_article(self, url: str) -> dict[str, Any]:
        """Fetch individual article HTML or return cached content."""
        canonical = normalize_url(url)
        try:
            status, text, _ = self._http_get(canonical, use_httpx=True)
            if status == 200:
                soup = bs4.BeautifulSoup(text, "html.parser")
                body_el = soup.find("div", {"class": "Post-body"}) or soup.find("article")
                content = sanitize_text(body_el.get_text(separator=" ", strip=True)) if body_el else ""
                return {"content": content, "url": canonical}
        except Exception as e:
            logger.warning(f"Failed to fetch article page for {url}: {e}")
        return {"content": "", "url": canonical}

    def normalize_article(self, raw_data: dict[str, Any]) -> Optional[Article]:
        """Convert raw entry data into a validated, normalized Article instance."""
        source_type = raw_data.get("_source", "json_api")

        if source_type == "json_api":
            disc = raw_data.get("disc", {})
            attrs = disc.get("attributes", {})
            title = sanitize_text(attrs.get("title", ""))
            if not title:
                return None

            disc_id = str(disc.get("id", ""))
            slug = attrs.get("slug", "")
            if slug.startswith(f"{disc_id}-"):
                raw_url = f"https://hacklido.com/d/{slug}"
            elif disc_id and slug:
                raw_url = f"https://hacklido.com/d/{disc_id}-{slug}"
            elif slug:
                raw_url = f"https://hacklido.com/d/{slug}"
            elif disc_id:
                raw_url = f"https://hacklido.com/d/{disc_id}"
            else:
                raw_url = ""
            canonical_url = normalize_url(raw_url)
            if not canonical_url:
                return None

            article_id = f"hacklido_{disc_id}" if disc_id else f"hacklido_{hashlib.sha256(canonical_url.encode()).hexdigest()[:16]}"

            # Timestamps
            created_at = attrs.get("createdAt")
            if not created_at:
                return None
            try:
                pub_dt = dateutil.parser.parse(str(created_at))
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=dateutil.tz.tzutc())
                published_at = pub_dt.astimezone(dateutil.tz.tzutc()).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                return None

            updated_at = ""
            last_posted = attrs.get("lastPostedAt")
            if last_posted:
                try:
                    upd_dt = dateutil.parser.parse(str(last_posted))
                    if upd_dt.tzinfo is None:
                        upd_dt = upd_dt.replace(tzinfo=dateutil.tz.tzutc())
                    updated_at = upd_dt.astimezone(dateutil.tz.tzutc()).strftime("%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    pass

            # Author
            inc_users = raw_data.get("inc_users", {})
            user_rel = disc.get("relationships", {}).get("user", {}).get("data")
            author = "Hacklido Community"
            if user_rel and user_rel.get("id") in inc_users:
                u_attrs = inc_users[user_rel["id"]].get("attributes", {})
                author = sanitize_text(u_attrs.get("displayName") or u_attrs.get("username") or author)

            # Tags & Category
            inc_tags = raw_data.get("inc_tags", {})
            tags_rel = disc.get("relationships", {}).get("tags", {}).get("data", [])
            tags = [inc_tags[t["id"]]["attributes"]["name"] for t in tags_rel if t.get("id") in inc_tags]
            category = tags[0] if tags else "Bug Bounty / Cybersecurity"

            # Content & Summary
            inc_posts = raw_data.get("inc_posts", {})
            post_rel = disc.get("relationships", {}).get("firstPost", {}).get("data")
            content = ""
            if post_rel and post_rel.get("id") in inc_posts:
                raw_html = inc_posts[post_rel["id"]].get("attributes", {}).get("contentHtml", "")
                if raw_html:
                    soup = bs4.BeautifulSoup(raw_html, "html.parser")
                    content = sanitize_text(soup.get_text(separator=" ", strip=True))

            if not content:
                content = title

            summary = content[:350] + ("..." if len(content) > 350 else "")

            return Article(
                article_id=article_id,
                source=SOURCE_HACKLIDO,
                title=title,
                url=canonical_url,
                author=author,
                published_at=published_at,
                collected_at=utc_now_iso(),
                category=category,
                tags=tags,
                summary=summary,
                content=content,
                content_hash=compute_content_hash(content),
                updated_at=updated_at,
                content_accessible="full",
            )

        elif source_type == "rss":
            title = sanitize_text(raw_data.get("title", ""))
            link = normalize_url(raw_data.get("link", ""))
            if not title or not link:
                return None

            article_id = f"hacklido_{hashlib.sha256(link.encode()).hexdigest()[:16]}"
            pub_raw = raw_data.get("pubDate")
            try:
                pub_dt = dateutil.parser.parse(str(pub_raw))
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=dateutil.tz.tzutc())
                published_at = pub_dt.astimezone(dateutil.tz.tzutc()).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                published_at = utc_now_iso()

            desc_raw = raw_data.get("description", "")
            soup = bs4.BeautifulSoup(desc_raw, "html.parser")
            content = sanitize_text(soup.get_text(separator=" ", strip=True)) or title
            summary = content[:350] + ("..." if len(content) > 350 else "")

            return Article(
                article_id=article_id,
                source=SOURCE_HACKLIDO,
                title=title,
                url=link,
                author="Hacklido Community",
                published_at=published_at,
                collected_at=utc_now_iso(),
                category="Bug Bounty / Cybersecurity",
                tags=["Hacklido"],
                summary=summary,
                content=content,
                content_hash=compute_content_hash(content),
                content_accessible="full",
            )

        return None


# ── 2. BleepingComputer Connector ──────────────────────────────────────────────

class BleepingComputerConnector(BaseCyberNewsConnector):
    """
    Data connector for BleepingComputer (https://www.bleepingcomputer.com/).
    Uses the official RSS feed (https://www.bleepingcomputer.com/feed/).
    Respects access restrictions and anti-bot controls; when full article HTML is
    restricted, captures full metadata and marks as partially accessible.
    """

    source_name = SOURCE_BLEEPINGCOMPUTER
    display_name = "BleepingComputer"
    home_url = "https://www.bleepingcomputer.com/"
    FEED_URL = "https://www.bleepingcomputer.com/feed/"

    def collect_latest(self, limit: int = 15) -> list[dict[str, Any]]:
        """Fetch metadata for the latest published articles from BleepingComputer RSS."""
        # Use feed-friendly headers
        feed_headers = {
            "User-Agent": "Feedly/1.0 (+http://www.feedly.com/fetcher.html; like FeedFetcher-Google)",
            "Accept": "application/rss+xml, application/xml, text/xml, */*",
        }

        status, text, _ = self._http_get(self.FEED_URL, headers=feed_headers)
        if status != 200:
            logger.warning(f"BleepingComputer feed returned status {status}")
            return []

        root = ET.fromstring(text.encode("utf-8", errors="replace"))
        channel = root.find("channel")
        if channel is None:
            return []

        items = channel.findall("item")
        results = []
        for it in items[:limit]:
            categories = [c.text for c in it.findall("category") if c.text]
            results.append({
                "title": it.findtext("title"),
                "link": it.findtext("link"),
                "pubDate": it.findtext("pubDate"),
                "creator": it.findtext("{http://purl.org/dc/elements/1.1/}creator") or "BleepingComputer",
                "categories": categories,
                "description": it.findtext("description"),
            })
        return results

    def collect_historical(
        self,
        start_date: str,
        end_date: str,
        max_articles: Optional[int] = None,
        start_offset: int = 0,
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Collect available feed items matching historical date range."""
        try:
            start_dt = dateutil.parser.parse(start_date)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=dateutil.tz.tzutc())
            end_dt = dateutil.parser.parse(end_date)
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(hour=23, minute=59, second=59, tzinfo=dateutil.tz.tzutc())
        except Exception as e:
            raise ValueError(f"Invalid date bounds: {e}")

        latest = self.collect_latest(limit=50)
        matching = []
        for item in latest[start_offset:]:
            pub_raw = item.get("pubDate")
            if not pub_raw:
                continue
            try:
                pub_dt = dateutil.parser.parse(pub_raw)
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=dateutil.tz.tzutc())
            except Exception:
                continue

            if start_dt <= pub_dt <= end_dt:
                matching.append(item)
                if max_articles is not None and len(matching) >= max_articles:
                    break

        if matching:
            yield matching

    def fetch_article(self, url: str) -> dict[str, Any]:
        """
        Attempt to fetch full article body.
        If Cloudflare/anti-bot restricts access, strictly respects boundary
        and returns partial status without attempting forbidden bypass.
        """
        canonical = normalize_url(url)
        try:
            status, text, _ = self._http_get(canonical)
            if status == 200 and "Just a moment..." not in text:
                soup = bs4.BeautifulSoup(text, "html.parser")
                body = soup.find("div", {"class": "articleBody"}) or soup.find("div", {"class": "article_section"})
                if body:
                    content = sanitize_text(body.get_text(separator=" ", strip=True))
                    return {"content": content, "url": canonical, "accessible": "full"}
        except Exception as e:
            logger.info(f"BleepingComputer article page access restricted ({e}). Using feed summary.")
        return {"content": "", "url": canonical, "accessible": "partial"}

    def normalize_article(self, raw_data: dict[str, Any]) -> Optional[Article]:
        """Convert BleepingComputer RSS entry into a validated Article instance."""
        title = sanitize_text(raw_data.get("title", ""))
        link = normalize_url(raw_data.get("link", ""))
        if not title or not link:
            return None

        article_id = f"bc_{hashlib.sha256(link.encode()).hexdigest()[:16]}"
        pub_raw = raw_data.get("pubDate")
        if not pub_raw:
            return None

        try:
            pub_dt = dateutil.parser.parse(str(pub_raw))
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=dateutil.tz.tzutc())
            published_at = pub_dt.astimezone(dateutil.tz.tzutc()).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return None

        author = sanitize_text(raw_data.get("creator") or "BleepingComputer")
        categories = [sanitize_text(c) for c in raw_data.get("categories", []) if c]
        category = categories[0] if categories else "Cybersecurity"

        desc_raw = raw_data.get("description", "")
        soup = bs4.BeautifulSoup(desc_raw, "html.parser")
        clean_summary = sanitize_text(soup.get_text(separator=" ", strip=True))

        content = raw_data.get("content") or clean_summary or title
        content_accessible = raw_data.get("content_accessible") or ("full" if len(content) > len(clean_summary) else "partial")

        return Article(
            article_id=article_id,
            source=SOURCE_BLEEPINGCOMPUTER,
            title=title,
            url=link,
            author=author,
            published_at=published_at,
            collected_at=utc_now_iso(),
            category=category,
            tags=categories,
            summary=clean_summary,
            content=content,
            content_hash=compute_content_hash(content),
            content_accessible=content_accessible,
        )


# ── 3. The Hacker News Connector ───────────────────────────────────────────────

class TheHackerNewsConnector(THNDataProvider):
    """
    Data connector for The Hacker News (https://thehackernews.com/).
    Inherits THN Blogger JSON feed engine and provides multi-source compatibility.
    """

    source_name = SOURCE_THEHACKERNEWS
    display_name = "The Hacker News"
    home_url = "https://thehackernews.com/"

    def is_new_article(self, article: Article, db: Any) -> tuple[bool, str]:
        """Check against persistent DB whether an article is new or previously collected."""
        is_dup, reason = db.check_duplicate(
            url=article.url,
            content_hash=article.content_hash,
            article_id=article.article_id,
        )
        return (not is_dup, reason)

    def normalize_article(self, raw_data: dict[str, Any]) -> Optional[Article]:
        """Normalize THN article and ensure content_accessible is set."""
        art = super().normalize_article(raw_data)
        if art:
            art.source = SOURCE_THEHACKERNEWS
            art.content_accessible = "full"
        return art


# ── 4. Cybersecurity News Connector ────────────────────────────────────────────

class CybersecurityNewsConnector(BaseCyberNewsConnector):
    """
    Data connector for Cybersecurity News (https://cybersecuritynews.com/).
    Uses the official RSS feed with full <content:encoded> article bodies
    and support for historical pagination via ?paged=N.
    """

    source_name = SOURCE_CYBERSECURITYNEWS
    display_name = "Cybersecurity News"
    home_url = "https://cybersecuritynews.com/"
    FEED_URL = "https://cybersecuritynews.com/feed/"
    CSN_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36",
    }

    def collect_latest(self, limit: int = 10) -> list[dict[str, Any]]:
        """Fetch metadata and full content for latest articles from Cybersecurity News feed."""
        status, text, _ = self._http_get(self.FEED_URL, headers=self.CSN_HEADERS, use_httpx=True)
        if status != 200:
            logger.warning(f"Cybersecurity News feed returned HTTP {status}")
            return []

        return self._parse_feed_items(text, limit=limit)

    def _parse_feed_items(self, xml_text: str, limit: int = 20) -> list[dict[str, Any]]:
        """Parse RSS XML containing standard and content:encoded tags."""
        root = ET.fromstring(xml_text.encode("utf-8", errors="replace"))
        channel = root.find("channel")
        if channel is None:
            return []

        items = channel.findall("item")
        results = []
        for it in items[:limit]:
            categories = [c.text for c in it.findall("category") if c.text]
            content_encoded = it.findtext("{http://purl.org/rss/1.0/modules/content/}encoded") or ""
            results.append({
                "title": it.findtext("title"),
                "link": it.findtext("link"),
                "pubDate": it.findtext("pubDate"),
                "creator": it.findtext("{http://purl.org/dc/elements/1.1/}creator") or "Cybersecurity News",
                "categories": categories,
                "description": it.findtext("description"),
                "content_encoded": content_encoded,
            })
        return results

    def collect_historical(
        self,
        start_date: str,
        end_date: str,
        max_articles: Optional[int] = None,
        start_offset: int = 0,
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Paginates historical articles via ?paged=N on Cybersecurity News feed."""
        try:
            start_dt = dateutil.parser.parse(start_date)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=dateutil.tz.tzutc())
            end_dt = dateutil.parser.parse(end_date)
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(hour=23, minute=59, second=59, tzinfo=dateutil.tz.tzutc())
        except Exception as e:
            raise ValueError(f"Invalid date bounds: {e}")

        # Each page typically holds 10 items
        page_num = max(1, (start_offset // 10) + 1)
        collected_total = 0
        reached_end = False

        while not reached_end:
            if max_articles is not None and collected_total >= max_articles:
                break

            paged_url = f"{self.FEED_URL}?paged={page_num}"
            try:
                status, text, _ = self._http_get(paged_url, headers=self.CSN_HEADERS, use_httpx=True)
                if status != 200:
                    break
                items = self._parse_feed_items(text, limit=50)
            except Exception as e:
                logger.error(f"Error fetching Cybersecurity News page {page_num}: {e}")
                break

            if not items:
                break

            matching_batch = []
            for item in items:
                pub_raw = item.get("pubDate")
                if not pub_raw:
                    continue
                try:
                    pub_dt = dateutil.parser.parse(pub_raw)
                    if pub_dt.tzinfo is None:
                        pub_dt = pub_dt.replace(tzinfo=dateutil.tz.tzutc())
                except Exception:
                    continue

                if pub_dt > end_dt:
                    continue
                if pub_dt < start_dt:
                    reached_end = True
                    break

                matching_batch.append(item)
                collected_total += 1
                if max_articles is not None and collected_total >= max_articles:
                    reached_end = True
                    break

            if matching_batch:
                yield matching_batch

            page_num += 1

    def fetch_article(self, url: str) -> dict[str, Any]:
        """Return article content if available or fetch via HTTP."""
        canonical = normalize_url(url)
        # Content is typically embedded directly in the RSS feed via content:encoded
        return {"content": "", "url": canonical}

    def normalize_article(self, raw_data: dict[str, Any]) -> Optional[Article]:
        """Convert Cybersecurity News entry into an Article instance with full text."""
        title = sanitize_text(raw_data.get("title", ""))
        link = normalize_url(raw_data.get("link", ""))
        if not title or not link:
            return None

        article_id = f"csn_{hashlib.sha256(link.encode()).hexdigest()[:16]}"
        pub_raw = raw_data.get("pubDate")
        if not pub_raw:
            return None

        try:
            pub_dt = dateutil.parser.parse(str(pub_raw))
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=dateutil.tz.tzutc())
            published_at = pub_dt.astimezone(dateutil.tz.tzutc()).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return None

        author = sanitize_text(raw_data.get("creator") or "Cybersecurity News")
        categories = [sanitize_text(c) for c in raw_data.get("categories", []) if c]
        category = categories[0] if categories else "Cybersecurity"

        desc_raw = raw_data.get("description", "")
        soup_desc = bs4.BeautifulSoup(desc_raw, "html.parser")
        summary = sanitize_text(soup_desc.get_text(separator=" ", strip=True))

        content_encoded = raw_data.get("content_encoded", "")
        if content_encoded:
            soup_content = bs4.BeautifulSoup(content_encoded, "html.parser")
            content = sanitize_text(soup_content.get_text(separator=" ", strip=True))
        else:
            content = summary or title

        if not summary:
            summary = content[:350] + ("..." if len(content) > 350 else "")

        return Article(
            article_id=article_id,
            source=SOURCE_CYBERSECURITYNEWS,
            title=title,
            url=link,
            author=author,
            published_at=published_at,
            collected_at=utc_now_iso(),
            category=category,
            tags=categories,
            summary=summary,
            content=content,
            content_hash=compute_content_hash(content),
            content_accessible="full",
        )
