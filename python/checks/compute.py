"""Virtual machine controls from baselines/azure-vm.md."""

from azure.mgmt.compute import ComputeManagementClient

from .base import CheckResult


def check_trusted_launch(
    client: ComputeManagementClient,
    resource_group: str,
) -> list[CheckResult]:
    """AZ-VM-001 — Secure Boot and vTPM must be enabled."""
    results = []

    for vm in client.virtual_machines.list(resource_group):
        uefi = getattr(vm.security_profile, "uefi_settings", None) if vm.security_profile else None
        secure_boot = getattr(uefi, "secure_boot_enabled", None)
        vtpm = getattr(uefi, "v_tpm_enabled", None)

        problems = []
        if secure_boot is not True:
            problems.append("Secure Boot is not enabled")
        if vtpm is not True:
            problems.append("vTPM is not enabled")

        results.append(
            CheckResult(
                control_id="AZ-VM-001",
                title="Trusted Launch must be enabled",
                resource=vm.name,
                passed=not problems,
                detail="; ".join(problems) if problems else "Secure Boot and vTPM enabled",
                evidence={"secureBootEnabled": secure_boot, "vTpmEnabled": vtpm},
            )
        )

    return results


def check_encryption_at_host(
    client: ComputeManagementClient,
    resource_group: str,
) -> list[CheckResult]:
    """AZ-VM-003 — encryption at host must be enabled."""
    results = []

    for vm in client.virtual_machines.list(resource_group):
        enabled = getattr(vm.security_profile, "encryption_at_host", None) if vm.security_profile else None

        results.append(
            CheckResult(
                control_id="AZ-VM-003",
                title="Encryption at host must be enabled",
                resource=vm.name,
                passed=enabled is True,
                detail=(
                    "Encryption at host enabled"
                    if enabled is True
                    else "Temp disk, OS cache and host-to-storage traffic are not encrypted at the host"
                ),
                evidence={"encryptionAtHost": enabled},
            )
        )

    return results


def check_patch_mode(
    client: ComputeManagementClient,
    resource_group: str,
) -> list[CheckResult]:
    """AZ-VM-005 — automatic patching must be configured."""
    results = []

    for vm in client.virtual_machines.list(resource_group):
        profile = vm.os_profile
        settings = None
        if profile and profile.windows_configuration:
            settings = profile.windows_configuration.patch_settings
        elif profile and profile.linux_configuration:
            settings = profile.linux_configuration.patch_settings

        patch_mode = getattr(settings, "patch_mode", None)
        assessment = getattr(settings, "assessment_mode", None)
        ok = patch_mode == "AutomaticByPlatform" and assessment == "AutomaticByPlatform"

        results.append(
            CheckResult(
                control_id="AZ-VM-005",
                title="Automatic patching must be configured",
                resource=vm.name,
                passed=ok,
                detail=(
                    "Patch and assessment modes are AutomaticByPlatform"
                    if ok
                    else f"patchMode={patch_mode}, assessmentMode={assessment}"
                ),
                evidence={"patchMode": patch_mode, "assessmentMode": assessment},
            )
        )

    return results
