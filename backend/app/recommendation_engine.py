# ============================================================
# CloudShield Recommendation Engine
# ============================================================

from typing import Any


def generate_recommendations(
    security_findings: list[dict[str, Any]],
    cost_opportunities: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Convert security findings and cost opportunities into
    actionable CloudShield recommendations.
    """

    recommendations: list[dict[str, Any]] = []

    # --------------------------------------------------------
    # Security recommendations
    # --------------------------------------------------------

    for finding in security_findings:
        severity = str(
            finding.get("severity", "LOW")
        ).upper()

        if severity == "CRITICAL":
            confidence = 98.0
        elif severity == "HIGH":
            confidence = 95.0
        elif severity == "MEDIUM":
            confidence = 90.0
        else:
            confidence = 85.0

        recommendations.append(
            {
                "title": finding.get(
                    "title",
                    "Security issue",
                ),
                "category": "SECURITY",
                "priority": (
                    "CRITICAL"
                    if severity == "CRITICAL"
                    else severity
                ),
                "explanation": finding.get(
                    "description",
                    "",
                ),
                "action": finding.get(
                    "recommendation",
                    "",
                ),
                "confidence": confidence,
                "status": "PENDING",
            }
        )

    # --------------------------------------------------------
    # Cost recommendations
    # --------------------------------------------------------

    for opportunity in cost_opportunities:
        priority = str(
            opportunity.get(
                "priority",
                "MEDIUM",
            )
        ).upper()

        if priority == "HIGH":
            confidence = 93.0
        elif priority == "MEDIUM":
            confidence = 88.0
        else:
            confidence = 80.0

        recommendations.append(
            {
                "title": opportunity.get(
                    "title",
                    "Cost optimization opportunity",
                ),
                "category": "COST",
                "priority": priority,
                "explanation": opportunity.get(
                    "explanation",
                    "",
                ),
                "action": opportunity.get(
                    "action",
                    "",
                ),
                "confidence": confidence,
                "status": "PENDING",
            }
        )

    # --------------------------------------------------------
    # Remove duplicate recommendations
    # --------------------------------------------------------

    unique_recommendations: list[
        dict[str, Any]
    ] = []

    seen: set[tuple[str, str]] = set()

    for recommendation in recommendations:
        key = (
            str(
                recommendation.get(
                    "title",
                    "",
                )
            ),
            str(
                recommendation.get(
                    "category",
                    "",
                )
            ),
        )

        if key not in seen:
            seen.add(key)
            unique_recommendations.append(
                recommendation
            )

    # --------------------------------------------------------
    # Sort by priority
    # --------------------------------------------------------

    priority_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    unique_recommendations.sort(
        key=lambda item: priority_order.get(
            str(
                item.get(
                    "priority",
                    "LOW",
                )
            ).upper(),
            4,
        )
    )

    return unique_recommendations


def build_recommendation_summary(
    recommendations: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build summary information for the dashboard.
    """

    summary = {
        "total": len(recommendations),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "security": 0,
        "cost": 0,
    }

    for recommendation in recommendations:
        priority = str(
            recommendation.get(
                "priority",
                "LOW",
            )
        ).lower()

        category = str(
            recommendation.get(
                "category",
                "",
            )
        ).upper()

        if priority in summary:
            summary[priority] += 1

        if category == "SECURITY":
            summary["security"] += 1
        elif category == "COST":
            summary["cost"] += 1

    return summary