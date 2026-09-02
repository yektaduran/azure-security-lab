#!/usr/bin/env python3
"""Run baseline compliance checks against the Azure lab subscription."""

import argparse
import sys

from config import ACCEPTED_DEVIATIONS, get_subscription_id
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from checks.base import Status

from checks.compute import (
    check_encryption_at_host,
    check_patch_mode,
    check_trusted_launch,
)
from checks.governance import check_unmanaged_resource_groups
from checks.network import check_admin_ports_not_internet_facing
from checks.storage import check_secure_transfer, check_shared_key_access
from report import write_reports


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--resource-group",
        default="RG-Security-Lab-WestUS2",
        help="Resource group to assess",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    subscription_id = get_subscription_id()

    credential = DefaultAzureCredential()

    results = []

    # Resource-group scoped checks
    storage_client = StorageManagementClient(credential, subscription_id)
    results.extend(check_shared_key_access(storage_client, args.resource_group))
    results.extend(check_secure_transfer(storage_client, args.resource_group))

    network_client = NetworkManagementClient(credential, subscription_id)
    results.extend(check_admin_ports_not_internet_facing(network_client, args.resource_group))

    compute_client = ComputeManagementClient(credential, subscription_id)
    results.extend(check_trusted_launch(compute_client, args.resource_group))
    results.extend(check_encryption_at_host(compute_client, args.resource_group))
    results.extend(check_patch_mode(compute_client, args.resource_group))

    # Subscription scoped checks — these see what the RG-scoped ones cannot
    results.extend(check_unmanaged_resource_groups(credential, subscription_id))

    for r in results:
        if r.status == Status.FAIL and (r.control_id, r.resource) in ACCEPTED_DEVIATIONS:
            r.status = Status.DEVIATION

    for r in results:
        print(f"[{r.status.value.upper():9}] {r.control_id}  {r.resource}  {r.detail}")

    blocking = sum(1 for r in results if r.status in (Status.FAIL, Status.ERROR))
    deviations = sum(1 for r in results if r.status == Status.DEVIATION)

    print(f"\n{len(results)} checks, {blocking} blocking, {deviations} accepted deviations")

    json_path, html_path = write_reports(results, subscription_id)
    print(f"\nReports written: {json_path}, {html_path}")

    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
