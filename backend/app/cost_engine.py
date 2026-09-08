# ============================================================
# CloudShield Cost Optimization Engine
# ============================================================

from typing import Any


def analyze_costs(
    resources: list[dict[str, Any]],
    cost_data: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Analyze discovered cloud resources and provider cost data.

    Returns:
        - total monthly cost
        - service-level cost breakdown
        - optimization opportunities
        - potential monthly savings
    """

    total_cost = sum(
        float(item.get("amount", 0))
        for item in cost_data
    )

    opportunities: list[dict[str, Any]] = []

    # --------------------------------------------------------
    # Look for stopped / inactive resources
    # --------------------------------------------------------

    for resource in resources:
        status = str(
            resource.get("status", "")
        ).upper()

        resource_type = str(
            resource.get("resource_type", "")
        ).upper()

        resource_id = resource.get(
            "resource_id",
            "unknown",
        )

        name = resource.get(
            "name",
            "Unknown Resource",
        )

        if status in {
            "STOPPED",
            "INACTIVE",
            "UNUSED",
        }:
            estimated_savings = 25.00

            if resource_type == "EC2":
                estimated_savings = 60.00
            elif resource_type == "EBS":
                estimated_savings = 15.00
            elif resource_type == "S3":
                estimated_savings = 10.00

            opportunities.append(
                {
                    "title": "Review inactive resource",
                    "resource_id": resource_id,
                    "explanation": (
                        f"{name} is currently marked as "
                        f"{status.lower()} and may no longer "
                        "be required."
                    ),
                    "action": (
                        "Verify whether the resource is still "
                        "required. Stop, delete, or archive it "
                        "if it is no longer needed."
                    ),
                    "monthly_savings": estimated_savings,
                    "priority": "HIGH",
                    "status": "OPEN",
                }
            )

    # --------------------------------------------------------
    # Look for development resources
    # --------------------------------------------------------

    for resource in resources:
        name = str(
            resource.get("name", "")
        ).lower()

        resource_id = resource.get(
            "resource_id",
            "unknown",
        )

        if any(
            keyword in name
            for keyword in (
                "dev",
                "test",
                "testing",
                "development",
            )
        ):
            opportunities.append(
                {
                    "title": "Review development resource",
                    "resource_id": resource_id,
                    "explanation": (
                        "This resource appears to be associated "
                        "with a development or testing environment."
                    ),
                    "action": (
                        "Consider scheduling the resource to run "
                        "only during required development hours."
                    ),
                    "monthly_savings": 35.00,
                    "priority": "MEDIUM",
                    "status": "OPEN",
                }
            )

    # --------------------------------------------------------
    # Service-level optimization
    # --------------------------------------------------------

    service_costs: dict[str, float] = {}

    for item in cost_data:
        service = str(
            item.get("service", "Other")
        )

        amount = float(
            item.get("amount", 0)
        )

        service_costs[service] = (
            service_costs.get(service, 0.0)
            + amount
        )

    # --------------------------------------------------------
    # Large service spend recommendation
    # --------------------------------------------------------

    if service_costs:
        highest_service = max(
            service_costs,
            key=service_costs.get,
        )

        highest_amount = service_costs[
            highest_service
        ]

        if highest_amount >= 500:
            opportunities.append(
                {
                    "title": (
                        f"Optimize {highest_service} spending"
                    ),
                    "resource_id": "SERVICE",
                    "explanation": (
                        f"{highest_service} currently represents "
                        f"${highest_amount:.2f} of the monthly "
                        "cloud spend."
                    ),
                    "action": (
                        "Review utilization, instance sizing, "
                        "storage usage, and applicable pricing "
                        "plans for this service."
                    ),
                    "monthly_savings": round(
                        highest_amount * 0.10,
                        2,
                    ),
                    "priority": "MEDIUM",
                    "status": "OPEN",
                }
            )

    # --------------------------------------------------------
    # Remove duplicate opportunities
    # --------------------------------------------------------

    unique_opportunities: list[
        dict[str, Any]
    ] = []

    seen: set[tuple[str, str]] = set()

    for opportunity in opportunities:
        key = (
            opportunity["title"],
            opportunity["resource_id"],
        )

        if key not in seen:
            seen.add(key)
            unique_opportunities.append(
                opportunity
            )

    opportunities = unique_opportunities

    # --------------------------------------------------------
    # Calculate savings
    # --------------------------------------------------------

    potential_savings = sum(
        float(
            opportunity.get(
                "monthly_savings",
                0,
            )
        )
        for opportunity in opportunities
    )

    # Savings should never exceed total monthly cost.
    potential_savings = min(
        potential_savings,
        total_cost,
    )

    # --------------------------------------------------------
    # Build final result
    # --------------------------------------------------------

    return {
        "monthly_cost": round(
            total_cost,
            2,
        ),
        "currency": "USD",
        "service_costs": {
            service: round(
                amount,
                2,
            )
            for service, amount in service_costs.items()
        },
        "opportunities": opportunities,
        "opportunity_count": len(
            opportunities
        ),
        "potential_monthly_savings": round(
            potential_savings,
            2,
        ),
    }


def calculate_savings_percentage(
    monthly_cost: float,
    potential_savings: float,
) -> float:
    """
    Calculate the percentage of monthly spend that could
    potentially be saved.
    """

    if monthly_cost <= 0:
        return 0.0

    percentage = (
        potential_savings
        / monthly_cost
    ) * 100

    return round(
        min(percentage, 100.0),
        2,
    )