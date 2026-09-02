"""Central configuration for the compliance checker."""

import os


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Required environment variable {name} is not set. "
            "Set it locally (export) or as a pipeline secret."
        )
    return value


SUBSCRIPTION_ID = _require_env("AZURE_SUBSCRIPTION_ID")

# Resource groups this project owns and manages through Terraform.
# Anything else in the subscription is unmanaged and gets flagged by AZ-GOV-001.
MANAGED_RESOURCE_GROUPS = [
    "RG-Security-Lab-WestUS2",
]

# Normalized for lookups — Azure preserves RG name casing but matches
# case-insensitively, so comparisons must be lowercase.
MANAGED_RESOURCE_GROUPS_LOWER = {rg.lower() for rg in MANAGED_RESOURCE_GROUPS}

# Created and owned by the Azure platform, not by this project. Azure creates
# NetworkWatcherRG automatically when Network Watcher is enabled in a region,
# and it cannot meaningfully be brought under Terraform. Recorded as reviewed
# rather than silently skipped — an auditor asks why a resource group is
# missing from the report, not why it is present.
PLATFORM_MANAGED_RESOURCE_GROUPS = [
    "NetworkWatcherRG",
]

PLATFORM_MANAGED_RESOURCE_GROUPS_LOWER = {
    rg.lower() for rg in PLATFORM_MANAGED_RESOURCE_GROUPS
}
# Deviations accepted and documented in baselines/. Each entry is a
# (control_id, resource) pair. Marking them here rather than inside the check
# keeps the check honest: it still reports the resource as non-compliant, and
# the acceptance is a separate, reviewable decision recorded in one place.
ACCEPTED_DEVIATIONS = {
    ("AZ-VM-001", "vm-lnx-lab-01"),   # Trusted Launch not enabled at deploy time
    ("AZ-VM-003", "vm-lnx-lab-01"),   # encryption at host — lab deviation
    ("AZ-VM-003", "vm-sec-lab-01"),   # encryption at host — lab deviation
    ("AZ-VM-005", "vm-lnx-lab-01"),   # ImageDefault patch mode
}
def get_subscription_id() -> str:
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        raise SystemExit("AZURE_SUBSCRIPTION_ID is not set")
    return subscription_id