"""
agents/autonomy.py — Autonomy levels (1-4) and safety/approval policy engine.

Autonomy NEVER bypasses safety, scope, or authorization controls.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .models import AutonomyLevel, RiskLevel


# Actions that ALWAYS require explicit approval regardless of autonomy level
ALWAYS_APPROVAL_ACTIONS = frozenset({
    "delete_data",
    "delete_file",
    "delete_directory",
    "system_settings",
    "install_software",
    "install_package",
    "sensitive_access",
    "external_communication",
    "send_email",
    "send_message",
    "publish_code",
    "deploy",
    "git_push",
    "spend_money",
    "modify_production",
    "security_scan_external",
})

# Risky shell patterns that must always be gated or blocked
RISKY_COMMAND_TOKENS = (
    "rm -rf",
    "del /f",
    "rmdir /s",
    "remove-item -recurse",
    "format ",
    "shutdown",
    "restart-computer",
    "reg add",
    "reg delete",
    "net user",
    "netsh ",
    "chmod 777",
    "curl ",
    "wget ",
    "invoke-webrequest",
    "git push",
    "pip install",
    "npm install -g",
    "winget install",
    "choco install",
)


@dataclass
class PolicyDecision:
    allowed: bool
    requires_approval: bool
    reason: str
    effective_risk: RiskLevel


class AutonomyPolicy:
    """Enforces JARVIS Autonomy Levels 1-4 and mandatory safety gates."""

    def __init__(self, level: AutonomyLevel = AutonomyLevel.EXECUTE_APPROVED):
        self._level = AutonomyLevel(int(level))

    @property
    def level(self) -> AutonomyLevel:
        return self._level

    def set_level(self, level: int | AutonomyLevel) -> AutonomyLevel:
        self._level = AutonomyLevel(int(level))
        return self._level

    def describe_level(self) -> dict[str, Any]:
        descriptions = {
            AutonomyLevel.ASSIST: "Level 1 — ASSIST: Answers, teaches, researches, and recommends only.",
            AutonomyLevel.PREPARE: "Level 2 — PREPARE: Creates plans, code drafts, and reports without executing changes.",
            AutonomyLevel.EXECUTE_APPROVED: "Level 3 — EXECUTE APPROVED TASKS: Performs approved file changes, coding, tests, and workflows.",
            AutonomyLevel.CONTROLLED_AUTONOMY: "Level 4 — CONTROLLED AUTONOMY: Completes low-risk tasks independently; high-risk actions still require approval.",
        }
        return {
            "level": int(self._level),
            "name": self._level.name,
            "description": descriptions[self._level],
        }

    def evaluate_action(
        self,
        action_name: str,
        risk_level: RiskLevel,
        explicit_requires_approval: bool = False,
        params: Optional[dict[str, Any]] = None,
        is_mutating: bool = False,
    ) -> PolicyDecision:
        """
        Determine whether an action can execute immediately, needs approval, or is blocked.
        """
        params = params or {}
        effective_risk = risk_level

        # Inspect terminal commands for dangerous patterns
        cmd_str = str(params.get("command", "") or params.get("cmd", "")).lower()
        if cmd_str and any(tok in cmd_str for tok in RISKY_COMMAND_TOKENS):
            effective_risk = RiskLevel.HIGH
            explicit_requires_approval = True

        # Always-gated actions cannot be bypassed at any autonomy level
        if action_name.lower() in ALWAYS_APPROVAL_ACTIONS or effective_risk == RiskLevel.CRITICAL:
            if self._level == AutonomyLevel.ASSIST:
                return PolicyDecision(
                    allowed=False,
                    requires_approval=True,
                    reason=f"Action '{action_name}' is blocked in ASSIST mode and requires explicit approval.",
                    effective_risk=RiskLevel.CRITICAL if effective_risk == RiskLevel.CRITICAL else RiskLevel.HIGH,
                )
            return PolicyDecision(
                allowed=True,
                requires_approval=True,
                reason=f"Action '{action_name}' requires explicit approval from Sir under safety policy.",
                effective_risk=effective_risk,
            )

        # Level 1 — ASSIST: read-only tools only
        if self._level == AutonomyLevel.ASSIST:
            if is_mutating or effective_risk in (RiskLevel.MEDIUM, RiskLevel.HIGH):
                return PolicyDecision(
                    allowed=False,
                    requires_approval=True,
                    reason=f"ASSIST mode (Level 1) does not allow executing mutating/risky action '{action_name}'.",
                    effective_risk=effective_risk,
                )
            return PolicyDecision(
                allowed=True,
                requires_approval=False,
                reason="Low-risk read/advisory action permitted in ASSIST mode.",
                effective_risk=effective_risk,
            )

        # Level 2 — PREPARE: plans & drafts allowed; mutations require approval
        if self._level == AutonomyLevel.PREPARE:
            if is_mutating or explicit_requires_approval or effective_risk != RiskLevel.LOW:
                return PolicyDecision(
                    allowed=True,
                    requires_approval=True,
                    reason=f"PREPARE mode (Level 2) requires approval before executing '{action_name}'.",
                    effective_risk=effective_risk,
                )
            return PolicyDecision(
                allowed=True,
                requires_approval=False,
                reason="Read-only inspection permitted in PREPARE mode.",
                effective_risk=effective_risk,
            )

        # Level 3 — EXECUTE APPROVED TASKS
        if self._level == AutonomyLevel.EXECUTE_APPROVED:
            if explicit_requires_approval or effective_risk in (RiskLevel.HIGH, RiskLevel.MEDIUM) or is_mutating:
                return PolicyDecision(
                    allowed=True,
                    requires_approval=True,
                    reason=f"Action '{action_name}' ({effective_risk.value}) requires Sir's approval in Level 3.",
                    effective_risk=effective_risk,
                )
            return PolicyDecision(
                allowed=True,
                requires_approval=False,
                reason="Low-risk read-only tool auto-approved in Level 3.",
                effective_risk=effective_risk,
            )

        # Level 4 — CONTROLLED AUTONOMY
        if explicit_requires_approval or effective_risk == RiskLevel.HIGH:
            return PolicyDecision(
                allowed=True,
                requires_approval=True,
                reason=f"High-risk action '{action_name}' requires explicit approval even in Level 4.",
                effective_risk=effective_risk,
            )
        return PolicyDecision(
            allowed=True,
            requires_approval=False,
            reason=f"Low/medium-risk predefined action permitted in Controlled Autonomy (Level 4).",
            effective_risk=effective_risk,
        )
