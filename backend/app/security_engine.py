# ============================================================
# CloudShield Security Scanning Engine
# ============================================================

from typing import Any


# ------------------------------------------------------------
# Severity weights
# ------------------------------------------------------------

SEVERITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
}


# ------------------------------------------------------------
# Individual security checks
# ------------------------------------------------------------

def check_resource(resource: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Run security checks against one cloud resource.

    The mock provider deliberately contains a mixture of
    healthy and vulnerable resources so that the dashboard
    can demonstrate meaningful security findings.
    """

    findings: list[dict[str, Any]] = []

    resource_id = resource.get("resource_id", "unknown")
    name = resource.get("name", "Unknown Resource")
    resource_type = resource.get("resource_type", "UNKNOWN")
    status = resource.get("status", "")
    security_state = resource.get("security_state", "")

    # --------------------------------------------------------
    # Check 1: Public / exposed resources
    # --------------------------------------------------------

    if security_state.upper() in {
        "PUBLIC",
        "EXPOSED",
        "OPEN",
        "INTERNET_FACING",
    }:
        findings.append(
            {
                "title": "Publicly exposed cloud resource",
                "severity": "HIGH",
                "resource_id": resource_id,
                "description": (
                    f"{name} is configured in a publicly exposed "
                    f"security state."
                ),
                "risk": (
                    "An internet-accessible resource can increase "
                    "the attack surface and may expose sensitive "
                    "services or data."
                ),
                "recommendation": (
                    "Restrict public access and allow only the "
                    "required trusted networks or services."
                ),
                "status": "OPEN",
            }
        )

    # --------------------------------------------------------
    # Check 2: Unencrypted resources
    # --------------------------------------------------------

    if security_state.upper() in {
        "UNENCRYPTED",
        "NOT_ENCRYPTED",
    }:
        findings.append(
            {
                "title": "Unencrypted cloud resource",
                "severity": "HIGH",
                "resource_id": resource_id,
                "description": (
                    f"{name} does not have encryption enabled."
                ),
                "risk": (
                    "Data stored on an unencrypted resource may be "
                    "exposed if unauthorized access occurs."
                ),
                "recommendation": (
                    "Enable encryption using the cloud provider's "
                    "managed encryption capabilities."
                ),
                "status": "OPEN",
            }
        )

    # --------------------------------------------------------
    # Check 3: Inactive resources
    # --------------------------------------------------------

    if status.upper() in {
        "STOPPED",
        "INACTIVE",
        "UNUSED",
    }:
        findings.append(
            {
                "title": "Inactive cloud resource",
                "severity": "MEDIUM",
                "resource_id": resource_id,
                "description": (
                    f"{name} is currently marked as {status.lower()}."
                ),
                "risk": (
                    "Inactive resources may remain unnecessarily "
                    "accessible and can increase operational and "
                    "security risk."
                ),
                "recommendation": (
                    "Review the resource and remove it or disable "
                    "it if it is no longer required."
                ),
                "status": "OPEN",
            }
        )

    # --------------------------------------------------------
    # Check 4: IAM-specific security check
    # --------------------------------------------------------

    if resource_type.upper() == "IAM_USER":
        if security_state.upper() in {
            "NO_MFA",
            "MFA_DISABLED",
        }:
            findings.append(
                {
                    "title": "IAM user without MFA",
                    "severity": "HIGH",
                    "resource_id": resource_id,
                    "description": (
                        f"IAM user {name} does not have "
                        "multi-factor authentication enabled."
                    ),
                    "risk": (
                        "A compromised password could provide direct "
                        "access to cloud resources."
                    ),
                    "recommendation": (
                        "Enable MFA for the IAM user and require MFA "
                        "for privileged access."
                    ),
                    "status": "OPEN",
                }
            )

    # --------------------------------------------------------
    # Check 5: Security group / network configuration
    # --------------------------------------------------------

    if resource_type.upper() == "SECURITY_GROUP":
        if security_state.upper() in {
            "OPEN",
            "PUBLIC",
            "ANYWHERE",
        }:
            findings.append(
                {
                    "title": "Overly permissive security group",
                    "severity": "CRITICAL",
                    "resource_id": resource_id,
                    "description": (
                        f"Security group {name} allows overly broad "
                        "network access."
                    ),
                    "risk": (
                        "Overly permissive network rules can expose "
                        "cloud services to unauthorized traffic."
                    ),
                    "recommendation": (
                        "Restrict inbound and outbound rules to only "
                        "the required ports, protocols, and sources."
                    ),
                    "status": "OPEN",
                }
            )

    return findings


# ------------------------------------------------------------
# Scan all resources
# ------------------------------------------------------------

def run_security_scan(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Run all security checks against all discovered resources.
    """

    findings: list[dict[str, Any]] = []

    for resource in resources:
        findings.extend(check_resource(resource))

    return findings


# ------------------------------------------------------------
# Calculate security score
# ------------------------------------------------------------

def calculate_security_score(
    resources: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> int:
    """
    Calculate a security score from 0 to 100.

    The score starts at 100 and is reduced according to the
    severity of discovered findings.

    More resources slightly increase the maximum deduction so
    that the score remains meaningful for different inventory
    sizes.
    """

    if not resources:
        return 100

    total_weight = sum(
        SEVERITY_WEIGHTS.get(
            finding.get("severity", "LOW").upper(),
            0,
        )
        for finding in findings
    )

    resource_factor = max(len(resources), 1)

    # Scale the penalty based on inventory size.
    penalty = (total_weight / resource_factor) * 4

    score = round(100 - penalty)

    return max(0, min(100, score))


# ------------------------------------------------------------
# Scan summary
# ------------------------------------------------------------

def build_scan_summary(
    resources: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build a summary that can later be returned directly
    through the FastAPI API.
    """

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = finding.get(
            "severity",
            "LOW",
        ).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    score = calculate_security_score(
        resources,
        findings,
    )

    return {
        "security_score": score,
        "total_resources": len(resources),
        "total_findings": len(findings),
        "critical_findings": severity_counts["CRITICAL"],
        "high_findings": severity_counts["HIGH"],
        "medium_findings": severity_counts["MEDIUM"],
        "low_findings": severity_counts["LOW"],
        "severity_counts": severity_counts,
    }