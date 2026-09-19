"""Provider abstractions for external systems.

Every external dependency (SIEM, LLM, response tooling) sits behind an
interface here, with a Mock implementation that runs offline. The core
simulation therefore needs no network, no API key, and no service.

Real integrations are added by implementing an interface -- never by wiring a
vendor SDK into the pipeline directly.
"""

from .ai_analyst import AIAnalyst, AIAnalysis, MockAIAnalyst
from .response import ResponseAction, ResponseProvider, ResponseResult, MockResponseProvider
from .siem import SIEMProvider, MockSIEMProvider

__all__ = [
    "AIAnalyst",
    "AIAnalysis",
    "MockAIAnalyst",
    "ResponseAction",
    "ResponseProvider",
    "ResponseResult",
    "MockResponseProvider",
    "SIEMProvider",
    "MockSIEMProvider",
]
