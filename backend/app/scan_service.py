# ============================================================
# CloudShield Scan Service
# ============================================================

from typing import Any

from app.cost_engine import analyze_costs
from app.providers import get_cloud_provider
from app.recommendation_engine import (
    build_recommendation_summary,
    generate_recommendations,
)
from app.security_engine import (
    build_scan_summary,
    run_security_scan,
)


def normalize_resource(
    resource: dict[str, Any],
) -> dict[str, Any]:
    """
    Normalize provider resource data into the structure
    expected by CloudShield.
    """

    return {
        "resource_id": str(
            resource.get(
                "resource_id",
                "unknown",
            )
        ),
        "name": str(
            resource.get(
                "name",
                "Unknown Resource",
            )
        ),
        "resource_type": str(
            resource.get(
                "resource_type",
                "UNKNOWN",
            )
        ),
        "region": str(
            resource.get(
                "region",
                "unknown",
            )
        ),
        "status": str(
            resource.get(
                "status",
                "UNKNOWN",
            )
        ),
        "security_state": str(
            resource.get(
                "security_state",
                "UNKNOWN",
            )
        ),
    }


def run_complete_scan() -> dict[str, Any]:
    """
    Execute the complete CloudShield analysis pipeline.

    Pipeline:

        Provider
            ↓
        Discovery
            ↓
        Security Analysis
            ↓
        Cost Analysis
            ↓
        Recommendations
            ↓
        Combined Result
    """

    # --------------------------------------------------------
    # 1. Select provider
    # --------------------------------------------------------

    provider = get_cloud_provider()

    provider_info = provider.get_provider_info()

    # --------------------------------------------------------
    # 2. Discover resources
    # --------------------------------------------------------

    raw_resources = provider.get_all_resources()

    resources = [
        normalize_resource(resource)
        for resource in raw_resources
    ]

    # --------------------------------------------------------
    # 3. Run security analysis
    # --------------------------------------------------------

    security_findings = run_security_scan(
        resources
    )

    security_summary = build_scan_summary(
        resources,
        security_findings,
    )

    # --------------------------------------------------------
    # 4. Analyze cloud costs
    # --------------------------------------------------------

    raw_cost_data = provider.get_cost_data()

    cost_analysis = analyze_costs(
        resources,
        raw_cost_data,
    )

    # --------------------------------------------------------
    # 5. Generate recommendations
    # --------------------------------------------------------

    recommendations = generate_recommendations(
        security_findings,
        cost_analysis["opportunities"],
    )

    recommendation_summary = (
        build_recommendation_summary(
            recommendations
        )
    )

    # --------------------------------------------------------
    # 6. Return complete analysis
    # --------------------------------------------------------

    return {
        "provider": provider_info,
        "resources": resources,
        "security": security_summary,
        "findings": security_findings,
        "costs": cost_analysis,
        "recommendations": recommendations,
        "recommendation_summary": recommendation_summary,
    }