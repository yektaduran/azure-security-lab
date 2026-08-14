#!/usr/bin/env python3
"""Run baseline compliance checks against the Azure lab subscription."""

import argparse
import os
import sys

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient

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
        "--subscription-id",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID"),
        help="Azure subscription ID (defaults to AZURE_SUBSCRIPTION_ID)",
    )
    parser.add_argument(
        "--resource-group",
        default="RG-Security-Lab-WestUS2",
        help="Resource group to assess",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.subscription_id:
        sys.exit("No subscription ID: pass --subscription-id or set AZURE_SUBSCRIPTION_ID")

    credential = DefaultAzureCredential()

    results = []

    # Resource-group scoped checks
    storage_client = StorageManagementClient(credential, args.subscription_id)
    results.extend(check_shared_key_access(storage_client, args.resource_group))
    results.extend(check_secure_transfer(storage_client, args.resource_group))

    network_client = NetworkManagementClient(credential, args.subscription_id)
    results.extend(check_admin_ports_not_internet_facing(network_client, args.resource_group))

    compute_client = ComputeManagementClient(credential, args.subscription_id)
    results.extend(check_trusted_launch(compute_client, args.resource_group))
    results.extend(check_encryption_at_host(compute_client, args.resource_group))
    results.extend(check_patch_mode(compute_client, args.resource_group))

    # Subscription scoped checks — these see what the RG-scoped ones cannot
    results.extend(check_unmanaged_resource_groups(credential, args.subscription_id))

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"[{status}] {r.control_id}  {r.resource}  {r.detail}")

    json_path, html_path = write_reports(results)
    print(f"\nReports written: {json_path}, {html_path}")

    failed = sum(1 for r in results if not r.passed)
    print(f"\n{len(results)} checks, {failed} failed")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
