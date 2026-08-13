"""Shared types for compliance checks."""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class CheckResult:
    """The outcome of a single control against a single resource."""

    control_id: str
    title: str
    resource: str
    passed: bool
    detail: str
    evidence: dict = field(default_factory=dict)
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
