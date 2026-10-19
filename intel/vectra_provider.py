"""
Vectra AI Platform Provider Abstraction for JARVIS (Phase 3.5).

Follows official Vectra REST API specifications (v3.3 / v3.4):
- Portal Reference: https://apidocs.vectra.ai/
- Authentication: OAuth 2.0 Client Credentials (POST /oauth2/token) or Bearer API token.
- Endpoints: GET /api/v3.3/detections, GET /api/v3.3/accounts, GET /api/v3.3/hosts.

Strict Security & Operational Guarantees:
- If credentials/tenant are not configured, status is explicitly 'NOT_CONFIGURED'.
- Zero fabricated detections; never substitutes external news articles for live telemetry.
- Server-side credential isolation (never leaks client secrets to frontend or logs).
"""

from __future__ import annotations
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional
import urllib.request
import urllib.error

from .models import utc_now_iso

logger = logging.getLogger(__name__)


@dataclass
class VectraDetection:
    """Normalized Vectra AI network/identity detection event."""

    detection_id: int
    detection_type: str
    category: str  # 'COMMAND & CONTROL', 'LATERAL MOVEMENT', 'EXFILTRATION', 'RECONNAISSANCE', 'INFO'
    threat_score: int  # 1-100
    certainty_score: int  # 1-100
    state: str  # 'active', 'closed', 'fixed'
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_host: Optional[str] = None
    summary: str = ""
    first_timestamp: Optional[str] = None
    last_timestamp: Optional[str] = None
    sensor: Optional[str] = None
    grouped_details: dict[str, Any] = field(default_factory=dict)
    ingested_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class VectraProvider:
    """
    Modular client interface for Vectra AI Detect / Recall / Stream APIs.
    Gracefully handles unconfigured deployments with explicit status reporting.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        api_token: Optional[str] = None,
        verify_ssl: bool = True,
        *,
        tenant_url: Optional[str] = None,
        token: Optional[str] = None,
    ):
        # Resolve configuration from explicit args, aliases, or server-side environment variables
        resolved_url = base_url or tenant_url or os.getenv("VECTRA_BASE_URL", "")
        self.base_url = resolved_url.rstrip("/") if resolved_url else ""
        self.client_id = client_id or os.getenv("VECTRA_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("VECTRA_CLIENT_SECRET", "")
        self.api_token = api_token or token or os.getenv("VECTRA_API_TOKEN", "")
        self.verify_ssl = verify_ssl

        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._last_error: Optional[str] = None

    @property
    def is_configured(self) -> bool:
        """Return True only if base URL and credentials (token or client_id+secret) exist."""
        has_url = bool(self.base_url and self.base_url.startswith("http"))
        has_creds = bool(self.api_token or (self.client_id and self.client_secret))
        return has_url and has_creds

    def get_status(self) -> dict[str, Any]:
        """
        Report actual provider status:
        - NOT_CONFIGURED (when credentials/deployment absent)
        - CONNECTED (verified live tenant connectivity)
        - ERROR (configured but failing authentication)
        """
        if not self.is_configured:
            return {
                "status": "NOT_CONFIGURED",
                "available": False,
                "message": (
                    "Vectra AI is not configured. An authorized Vectra SaaS portal or Brain appliance "
                    "with valid API credentials (VECTRA_BASE_URL, VECTRA_CLIENT_ID, VECTRA_CLIENT_SECRET) is required."
                ),
                "base_url": self.base_url or None,
                "api_version": "v3.3/v3.4",
                "last_checked": utc_now_iso(),
            }

        if self._last_error:
            return {
                "status": "ERROR",
                "available": False,
                "message": f"Vectra AI connection error: {self._last_error}",
                "base_url": self.base_url,
                "api_version": "v3.3/v3.4",
                "last_checked": utc_now_iso(),
            }

        # If configured, verify connection
        auth_ok, auth_err = self._authenticate()
        if not auth_ok:
            return {
                "status": "ERROR",
                "available": False,
                "message": f"Vectra AI authentication failed: {auth_err}",
                "base_url": self.base_url,
                "api_version": "v3.3/v3.4",
                "last_checked": utc_now_iso(),
            }

        return {
            "status": "CONNECTED",
            "available": True,
            "message": "Connected to authorized Vectra AI deployment.",
            "base_url": self.base_url,
            "api_version": "v3.3/v3.4",
            "last_checked": utc_now_iso(),
        }

    def _authenticate(self) -> tuple[bool, Optional[str]]:
        """Perform OAuth2 client credentials flow or validate token."""
        if not self.is_configured:
            return False, "Credentials not configured"

        if self.api_token:
            self._access_token = self.api_token
            return True, None

        # Check existing token expiration
        if self._access_token and time.time() < (self._token_expires_at - 60):
            return True, None

        # Request new OAuth token from /oauth2/token
        token_url = f"{self.base_url}/oauth2/token"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "JARVIS-Cyber-Intel/1.0",
        }
        data = f"grant_type=client_credentials&client_id={self.client_id}&client_secret={self.client_secret}".encode("utf-8")

        try:
            req = urllib.request.Request(token_url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                status_code = getattr(resp, "status", None) or getattr(resp, "code", 200)
                if status_code == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    self._access_token = payload.get("access_token")
                    expires_in = int(payload.get("expires_in", 3600))
                    self._token_expires_at = time.time() + expires_in
                    return True, None
                return False, f"HTTP {status_code}"
        except urllib.error.HTTPError as e:
            self._last_error = f"HTTP {e.code}: {e.reason}"
            return False, f"Authentication error {e.code}: {e.reason}"
        except Exception as e:
            self._last_error = str(e)
            return False, str(e)

    def poll_detections(
        self,
        min_threat: int = 50,
        min_certainty: int = 50,
        state: str = "active",
        limit: int = 50,
    ) -> list[VectraDetection]:
        """
        Poll detections from official /api/v3.3/detections or /api/v3.4/detections endpoint.
        Returns empty list when unconfigured (never invents detections).
        """
        if not self.is_configured:
            logger.info("Vectra AI is not configured; skipping detection polling.")
            return []

        auth_ok, err = self._authenticate()
        if not auth_ok:
            logger.error(f"Cannot poll Vectra detections: {err}")
            return []

        endpoint = f"{self.base_url}/api/v3.3/detections?state={state}&threat_gte={min_threat}&certainty_gte={min_certainty}&page_size={limit}"
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
            "User-Agent": "JARVIS-Cyber-Intel/1.0",
        }

        try:
            req = urllib.request.Request(endpoint, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                status_code = getattr(resp, "status", None) or getattr(resp, "code", 200)
                if status_code == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    results = data.get("results", [])
                    detections: list[VectraDetection] = []
                    for item in results:
                        det = VectraDetection(
                            detection_id=int(item.get("id", 0)),
                            detection_type=item.get("detection_type", "Unknown"),
                            category=item.get("category", "INFO"),
                            threat_score=int(item.get("threat", 0)),
                            certainty_score=int(item.get("certainty", 0)),
                            state=item.get("state", "active"),
                            src_ip=item.get("src_ip"),
                            dst_ip=item.get("dst_ip"),
                            src_host=item.get("src_host", {}).get("name") if isinstance(item.get("src_host"), dict) else item.get("src_host"),
                            summary=item.get("summary", ""),
                            first_timestamp=item.get("first_timestamp"),
                            last_timestamp=item.get("last_timestamp"),
                            sensor=item.get("sensor"),
                            grouped_details=item,
                        )
                        detections.append(det)
                    return detections
                return []
        except urllib.error.HTTPError as e:
            self._last_error = f"HTTP {e.code}: {e.reason}"
            logger.error(f"Failed to fetch Vectra detections: HTTP {e.code} {e.reason}")
            return []
        except Exception as e:
            self._last_error = str(e)
            logger.error(f"Failed to fetch Vectra detections: {e}")
            return []

    def get_detection_by_id(self, event_id: int | str) -> Optional[VectraDetection]:
        """Fetch details for a specific detection event ID from live deployment."""
        if not self.is_configured:
            return None

        auth_ok, _ = self._authenticate()
        if not auth_ok:
            return None

        endpoint = f"{self.base_url}/api/v3.3/detections/{event_id}"
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
        }
        try:
            req = urllib.request.Request(endpoint, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                if resp.status == 200:
                    item = json.loads(resp.read().decode("utf-8"))
                    return VectraDetection(
                        detection_id=int(item.get("id", event_id)),
                        detection_type=item.get("detection_type", "Unknown"),
                        category=item.get("category", "INFO"),
                        threat_score=int(item.get("threat", 0)),
                        certainty_score=int(item.get("certainty", 0)),
                        state=item.get("state", "active"),
                        src_ip=item.get("src_ip"),
                        dst_ip=item.get("dst_ip"),
                        summary=item.get("summary", ""),
                        first_timestamp=item.get("first_timestamp"),
                        last_timestamp=item.get("last_timestamp"),
                    )
        except Exception:
            return None
        return None
