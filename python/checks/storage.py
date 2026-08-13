"""Storage account controls from baselines/azure-storage.md."""

from azure.mgmt.storage import StorageManagementClient

from .base import CheckResult


def check_secure_transfer(
    client: StorageManagementClient,
    resource_group: str,
) -> list[CheckResult]:
    """AZ-STO-003 — secure transfer and TLS 1.2 minimum."""
    results = []

    for account in client.storage_accounts.list_by_resource_group(resource_group):
        https_only = account.enable_https_traffic_only
        tls = account.minimum_tls_version
        anonymous = account.allow_blob_public_access

        problems = []
        if not https_only:
            problems.append("HTTP is accepted")
        if tls != "TLS1_2":
            problems.append(f"minimum TLS is {tls}")
        if anonymous is not False:
            problems.append("anonymous blob access is permitted")

        results.append(
            CheckResult(
                control_id="AZ-STO-003",
                title="Secure transfer and minimum TLS version",
                resource=account.name,
                passed=not problems,
                detail="; ".join(problems) if problems else "HTTPS enforced, TLS 1.2 minimum, anonymous access disabled",
                evidence={
                    "enableHttpsTrafficOnly": https_only,
                    "minimumTlsVersion": tls,
                    "allowBlobPublicAccess": anonymous,
                },
            )
        )

    return results

def check_shared_key_access(
    client: StorageManagementClient,
    resource_group: str,
) -> list[CheckResult]:
    """AZ-STO-002 — shared key access must be disabled."""
    results = []

    for account in client.storage_accounts.list_by_resource_group(resource_group):
        allowed = account.allow_shared_key_access
        # The API returns None when the property was never set, which the
        # service treats as enabled. Absence is not compliance.
        enabled = allowed is not False

        results.append(
            CheckResult(
                control_id="AZ-STO-002",
                title="Shared key access must be disabled",
                resource=account.name,
                passed=not enabled,
                detail=(
                    "Shared key access is enabled; the account keys bypass "
                    "every RBAC assignment protecting it"
                    if enabled
                    else "Shared key access is disabled"
                ),
                evidence={"allowSharedKeyAccess": allowed},
            )
        )

    return results
