"""Shared types for compliance checks."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    DEVIATION = "deviation"   # known, documented and accepted in baselines/
    ERROR = "error"           # the check could not run


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
    status: Status | None = None

    def __post_init__(self):
        if self.status is None:
            self.status = Status.PASS if self.passed else Status.FAIL