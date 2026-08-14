"""Governance checks — subscription-level resource ownership.

AZ-GOV-001 exists because tooling scoped to a single resource group cannot see
resources outside it. Terraform, the baselines and this checker all target
RG-Security-Lab-WestUS2; anything else in the subscription is unmanaged by
definition and nobody is auditing it.
"""

from azure.mgmt.resource.resources import ResourceManagementClient

from checks.base import CheckResult
from config import (
    MANAGED_RESOURCE_GROUPS,
    MANAGED_RESOURCE_GROUPS_LOWER,
    PLATFORM_MANAGED_RESOURCE_GROUPS_LOWER,
)

CONTROL_ID = "AZ-GOV-001"
TITLE = "All resource groups in the subscription are managed by Terraform"


def check_unmanaged_resource_groups(credential, subscription_id) -> list[CheckResult]:
    client = ResourceManagementClient(credential, subscription_id)

    results: list[CheckResult] = []
    findings = 0

    for rg in client.resource_groups.list():
        name_lower = rg.name.lower()

        if name_lower in MANAGED_RESOURCE_GROUPS_LOWER:
            continue

        resource_count = sum(
            1 for _ in client.resources.list_by_resource_group(rg.name)
        )

        if name_lower in PLATFORM_MANAGED_RESOURCE_GROUPS_LOWER:
            results.append(
                CheckResult(
                    control_id=CONTROL_ID,
                    title=TITLE,
                    resource=rg.name,
                    passed=True,
                    detail=(
                        f"Resource group '{rg.name}' is created and owned by the "
                        "Azure platform; out of scope for Terraform management."
                    ),
                    evidence={
                        "resource_group": rg.name,
                        "location": rg.location,
                        "resource_count": resource_count,
                        "classification": "platform-managed",
                    },
                )
            )
            continue

        findings += 1
        results.append(
            CheckResult(
                control_id=CONTROL_ID,
                title=TITLE,
                resource=rg.name,
                passed=False,
                detail=(
                    f"Resource group '{rg.name}' is not in the managed list "
                    f"and holds {resource_count} resource(s)."
                ),
                evidence={
                    "resource_group": rg.name,
                    "location": rg.location,
                    "resource_count": resource_count,
                    "classification": "unmanaged",
                    "managed_resource_groups": MANAGED_RESOURCE_GROUPS,
                },
            )
        )

    if findings == 0:
        results.append(
            CheckResult(
                control_id=CONTROL_ID,
                title=TITLE,
                resource=subscription_id,
                passed=True,
                detail=(
                    "No unmanaged resource groups found in the subscription."
                ),
                evidence={
                    "managed_resource_groups": MANAGED_RESOURCE_GROUPS,
                    "classification": "summary",
                },
            )
        )

    return results