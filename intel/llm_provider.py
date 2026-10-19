"""
LLM Provider Abstraction for JARVIS Cybersecurity Intelligence Subsystem.

Supports:
- Gemini (via google.genai, using gemini-3.8-flash or custom model)
- Ollama (local server via native /api/chat)
- OpenAI-compatible (LM Studio, LocalAI, Nebius, vLLM via /v1/chat/completions)
- Mock (deterministic offline testing without API consumption)
"""

from __future__ import annotations
import abc
import json
import logging
from typing import Any, Optional

import requests

from .config import load_cyber_config

logger = logging.getLogger(__name__)


class BaseLLMProvider(abc.ABC):
    """Abstract interface for intelligence LLM backends."""

    @abc.abstractmethod
    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        timeout: int = 120,
        temperature: float = 0.1,
    ) -> str:
        """Generate text completion from prompt and optional system message."""
        pass

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check if provider and model endpoint are reachable."""
        pass

    @abc.abstractmethod
    def get_model_name(self) -> str:
        """Return active model name."""
        pass

    @abc.abstractmethod
    def get_provider_name(self) -> str:
        """Return provider identifier ('gemini', 'ollama', 'openai', 'mock')."""
        pass


class GeminiLLMProvider(BaseLLMProvider):
    """Google Gemini AI Provider utilizing official google.genai client."""

    def __init__(self, api_key: str, model: str = "gemini-3.8-flash"):
        self.api_key = api_key
        self.model = model
        self._client: Any = None
        if api_key:
            try:
                from google import genai
                self._client = genai.Client(api_key=api_key)
            except Exception as e:
                logger.warning("Failed to initialize genai.Client: %s", e)

    def is_available(self) -> bool:
        return bool(self._client and self.api_key)

    def get_model_name(self) -> str:
        return self.model

    def get_provider_name(self) -> str:
        return "gemini"

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        timeout: int = 120,
        temperature: float = 0.1,
    ) -> str:
        if not self._client:
            raise RuntimeError("Gemini client not initialized. Check gemini_api_key configuration.")

        full_prompt = prompt
        config_dict: dict[str, Any] = {
            "temperature": temperature,
            "max_output_tokens": 4096,
        }
        if system:
            config_dict["system_instruction"] = system

        try:
            response = self._client.models.generate_content(
                model=self.model,
                contents=full_prompt,
                config=config_dict,
            )
            return response.text or ""
        except Exception as e:
            logger.error("Gemini generation failed: %s", e)
            raise RuntimeError(f"Gemini API error: {e}") from e


class OllamaLLMProvider(BaseLLMProvider):
    """Ollama Local Server Provider."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self.base_url = base_url.rstrip("/")
        self.model = model

    def is_available(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def get_model_name(self) -> str:
        return self.model

    def get_provider_name(self) -> str:
        return "ollama"

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        timeout: int = 120,
        temperature: float = 0.1,
    ) -> str:
        endpoint = f"{self.base_url}/api/chat"
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": 4096,
            },
        }

        try:
            resp = requests.post(endpoint, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get("content", "").strip()
        except Exception as e:
            logger.error("Ollama generation failed: %s", e)
            raise RuntimeError(f"Ollama request error: {e}") from e


class OpenAILLMProvider(BaseLLMProvider):
    """OpenAI-compatible server provider (LM Studio, LocalAI, Nebius Token Factory, vLLM)."""

    def __init__(
        self,
        base_url: str = "http://localhost:1234",
        model: str = "default",
        api_key: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key or "not-needed"

    def is_available(self) -> bool:
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            r = requests.get(f"{self.base_url}/v1/models", headers=headers, timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def get_model_name(self) -> str:
        return self.model

    def get_provider_name(self) -> str:
        return "openai"

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        timeout: int = 120,
        temperature: float = 0.1,
    ) -> str:
        endpoint = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 4096,
        }

        try:
            resp = requests.post(endpoint, json=payload, headers=headers, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            logger.error("OpenAI-compatible generation failed: %s", e)
            raise RuntimeError(f"OpenAI endpoint error: {e}") from e


class MockLLMProvider(BaseLLMProvider):
    """Mock Provider for deterministic unit testing without API costs or external network."""

    def __init__(
        self,
        mock_response: Optional[str] = None,
        mock_handler: Optional[Any] = None,
        model: str = "mock-cyber-analyst-v1",
    ):
        self.mock_response = mock_response
        self.mock_handler = mock_handler
        self.model = model
        self.calls: list[dict[str, Any]] = []

    def is_available(self) -> bool:
        return True

    def get_model_name(self) -> str:
        return self.model

    def get_provider_name(self) -> str:
        return "mock"

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        timeout: int = 120,
        temperature: float = 0.1,
    ) -> str:
        self.calls.append({"prompt": prompt, "system": system, "temperature": temperature})
        if self.mock_handler:
            return self.mock_handler(prompt, system)
        if self.mock_response is not None:
            return self.mock_response

        # Default valid structured mock response
        return json.dumps({
            "summary": "Threat actor targeted critical systems exploiting CVE-2026-12345 in WidgetApp.",
            "threat_types": ["Vulnerability Exploitation", "Ransomware"],
            "attack_types": ["Remote Code Execution"],
            "attack_vectors": ["Network / Public Facing Application"],
            "threat_actors": ["APT-Phantom"],
            "threat_groups": ["Phantom Group"],
            "malware": ["LockData"],
            "ransomware": ["LockData Ransomware"],
            "vulnerabilities": ["WidgetApp Buffer Overflow"],
            "cves": ["CVE-2026-12345"],
            "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "severity": "CRITICAL"},
            "affected_products": ["WidgetApp"],
            "affected_vendors": ["WidgetCorp"],
            "affected_versions": ["< 2.4.1"],
            "target_sectors": ["Healthcare", "Financial Services"],
            "target_countries": ["United States", "United Kingdom"],
            "target_organizations": [],
            "technical_explanation": {
                "what_happened": "Adversary exploited an unauthenticated buffer overflow in WidgetApp to execute arbitrary commands.",
                "initial_access": "Exploitation of public facing application on port 8443.",
                "execution": "Shellcode execution via memory corruption.",
                "impact": "Data encrypted and systems held for ransom."
            },
            "mitre_attack": [
                {
                    "tactic": "Initial Access",
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application",
                    "evidence": "Exploited CVE-2026-12345 on internet exposed portal",
                    "confidence": "HIGH"
                }
            ],
            "iocs": [
                {
                    "type": "ip",
                    "value": "198.51.100.25",
                    "context": "Command and control IP",
                    "confidence": "HIGH"
                }
            ],
            "tools": ["Cobalt Strike"],
            "technologies": ["OpenSSL", "Nginx"],
            "impact": {
                "confidentiality": "HIGH",
                "integrity": "HIGH",
                "availability": "HIGH",
                "business": "Disruption of clinical hospital operations and data theft"
            },
            "detection_methods": ["Monitor for unexpected child processes spawned by WidgetApp service"],
            "mitigation": ["Apply vendor security patch version 2.4.1 immediately"],
            "remediation": ["Isolate affected hosts, rotate service credentials"],
            "security_recommendations": [
                "Restrict exposed administration ports to internal VPN",
                "Deploy endpoint detection and response (EDR)"
            ],
            "severity": "CRITICAL",
            "severity_reason": "Active exploitation of unauthenticated remote code execution vulnerability (CVSS 9.8) resulting in ransomware deployment",
            "confidence": "HIGH",
            "facts": [
                "Vendor WidgetCorp released security advisory for CVE-2026-12345",
                "LockData ransomware group is actively scanning for vulnerable endpoints"
            ],
            "inferences": [
                "The campaign is likely financially motivated based on observed ransom demands"
            ]
        })


def get_llm_provider(config: Optional[dict[str, Any]] = None) -> BaseLLMProvider:
    """
    Factory function to construct and return the configured LLMProvider.
    Ensures safe configuration, no hardcoded API keys, and graceful fallback.
    """
    cfg = config or load_cyber_config()
    provider_type = (cfg.get("llm_provider") or "gemini").strip().lower()

    if provider_type == "mock":
        return MockLLMProvider()

    if provider_type == "gemini":
        api_key = cfg.get("llm_api_key", "")
        model = cfg.get("llm_model") or "gemini-3.8-flash"
        if api_key:
            provider = GeminiLLMProvider(api_key=api_key, model=model)
            if provider.is_available():
                return provider

        # If Gemini key not available, fallback to Ollama
        logger.warning("Gemini API key not configured or invalid. Checking Ollama fallback...")
        provider_type = "ollama"

    if provider_type == "ollama":
        url = cfg.get("llm_url") or "http://localhost:11434"
        model = cfg.get("llm_model") or "llama3.2"
        return OllamaLLMProvider(base_url=url, model=model)

    if provider_type in ("openai", "lmstudio", "localai", "nebius"):
        url = cfg.get("llm_url") or "http://localhost:1234"
        model = cfg.get("llm_model") or "default"
        api_key = cfg.get("llm_api_key")
        return OpenAILLMProvider(base_url=url, model=model, api_key=api_key)

    # Fallback default
    return OllamaLLMProvider()
