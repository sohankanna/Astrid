"""AI provider selection. Environment-driven; defaults to fully offline.

    SOC_AI_PROVIDER=mock    (default) deterministic MockAIAnalyst, no network
    SOC_AI_PROVIDER=claude  ClaudeAnalyst, falling back to the mock on failure

An unknown value falls back to mock and is reported, never guessed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

from .ai_analyst import AIAnalyst, MockAIAnalyst
from .claude_ai import ClaudeAnalyst, credentials_configured, sdk_available

PROVIDERS: Final[frozenset[str]] = frozenset({"mock", "claude"})


@dataclass(frozen=True)
class ProviderConfig:
    requested: str
    effective: str
    note: str | None = None

    def to_dict(self) -> dict:
        return {
            "requested": self.requested,
            "effective": self.effective,
            "note": self.note,
            "claude_sdk_installed": sdk_available(),
            "claude_credentials_configured": credentials_configured(),
        }


def configured_provider() -> ProviderConfig:
    raw = os.environ.get("SOC_AI_PROVIDER", "mock").strip().lower() or "mock"
    if raw not in PROVIDERS:
        return ProviderConfig(raw, "mock", f"unknown SOC_AI_PROVIDER {raw!r}; using mock")
    return ProviderConfig(raw, raw)


def build_analyst(config: ProviderConfig) -> AIAnalyst:
    return ClaudeAnalyst() if config.effective == "claude" else MockAIAnalyst()
