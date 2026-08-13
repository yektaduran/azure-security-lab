"""Network security group controls from baselines/azure-network.md."""

from azure.mgmt.network import NetworkManagementClient

from .base import CheckResult

INTERNET_SOURCES = {"*", "internet", "0.0.0.0/0", "any"}
ADMIN_PORTS = {"22", "3389"}


def _is_internet_source(rule) -> bool:
    sources = [rule.source_address_prefix] + list(rule.source_address_prefixes or [])
    return any((s or "").lower() in INTERNET_SOURCES for s in sources)


def _covers_admin_port(rule) -> bool:
    ranges = [rule.destination_port_range] + list(rule.destination_port_ranges or [])
    for r in ranges:
        if not r:
            continue
        if r == "*" or r in ADMIN_PORTS:
            return True
        if "-" in r:
            low, high = r.split("-", 1)
            if any(low <= p <= high for p in ADMIN_PORTS):
                return True
    return False


def check_admin_ports_not_internet_facing(
    client: NetworkManagementClient,
    resource_group: str,
) -> list[CheckResult]:
    """AZ-NET-001 — remote administration ports must not be exposed."""
    results = []

    for nsg in client.network_security_groups.list(resource_group):
        offending = [
            rule.name
            for rule in (nsg.security_rules or [])
            if rule.direction == "Inbound"
            and rule.access == "Allow"
            and _is_internet_source(rule)
            and _covers_admin_port(rule)
        ]

        results.append(
            CheckResult(
                control_id="AZ-NET-001",
                title="Remote administration ports not exposed to the internet",
                resource=nsg.name,
                passed=not offending,
                detail=(
                    f"Rules exposing SSH/RDP to the internet: {', '.join(offending)}"
                    if offending
                    else "No inbound rule exposes SSH or RDP to the internet"
                ),
                evidence={"offendingRules": offending},
            )
        )

    return results
