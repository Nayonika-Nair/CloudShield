# ============================================================
# CloudShield Database Persistence
# ============================================================

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy.orm import Session

from app.models import (
    CloudResource,
    CostOpportunity,
    CostRecord,
    Recommendation,
    Scan,
    SecurityFinding,
)


def save_scan_results(
    db: Session,
    scan_result: dict[str, Any],
) -> Scan:
    """
    Persist the results of a complete CloudShield scan.

    The latest inventory and analysis results replace the
    previous current snapshot, while the scans table keeps
    a history of completed scans.
    """

    resources = scan_result.get(
        "resources",
        [],
    )

    findings = scan_result.get(
        "findings",
        [],
    )

    costs = scan_result.get(
        "costs",
        {},
    )

    opportunities = costs.get(
        "opportunities",
        [],
    )

    recommendations = scan_result.get(
        "recommendations",
        [],
    )

    security = scan_result.get(
        "security",
        {},
    )

    # --------------------------------------------------------
    # Clear the current snapshot
    # --------------------------------------------------------

    db.query(SecurityFinding).delete(
        synchronize_session=False
    )

    db.query(CostOpportunity).delete(
        synchronize_session=False
    )

    db.query(Recommendation).delete(
        synchronize_session=False
    )

    db.query(CostRecord).delete(
        synchronize_session=False
    )

    db.query(CloudResource).delete(
        synchronize_session=False
    )

    # --------------------------------------------------------
    # Save resources
    # --------------------------------------------------------

    for resource in resources:
        db.add(
            CloudResource(
                resource_id=resource["resource_id"],
                name=resource["name"],
                resource_type=resource["resource_type"],
                region=resource["region"],
                status=resource["status"],
                security_state=resource["security_state"],
            )
        )

    # --------------------------------------------------------
    # Save security findings
    # --------------------------------------------------------

    for finding in findings:
        db.add(
            SecurityFinding(
                title=finding["title"],
                severity=finding["severity"],
                resource_id=finding["resource_id"],
                description=finding["description"],
                risk=finding["risk"],
                recommendation=finding["recommendation"],
                status=finding.get(
                    "status",
                    "OPEN",
                ),
            )
        )

    # --------------------------------------------------------
    # Save cost records
    # --------------------------------------------------------

    for service, amount in costs.get(
        "service_costs",
        {},
    ).items():
        db.add(
            CostRecord(
                service=service,
                amount=Decimal(str(amount)),
                currency=costs.get(
                    "currency",
                    "USD",
                ),
            )
        )

    # --------------------------------------------------------
    # Save cost opportunities
    # --------------------------------------------------------

    for opportunity in opportunities:
        db.add(
            CostOpportunity(
                title=opportunity["title"],
                resource_id=opportunity["resource_id"],
                explanation=opportunity["explanation"],
                action=opportunity["action"],
                monthly_savings=Decimal(
                    str(
                        opportunity.get(
                            "monthly_savings",
                            0,
                        )
                    )
                ),
                priority=opportunity["priority"],
                status=opportunity.get(
                    "status",
                    "OPEN",
                ),
            )
        )

    # --------------------------------------------------------
    # Save recommendations
    # --------------------------------------------------------

    for recommendation in recommendations:
        db.add(
            Recommendation(
                title=recommendation["title"],
                category=recommendation["category"],
                priority=recommendation["priority"],
                explanation=recommendation["explanation"],
                action=recommendation["action"],
                confidence=Decimal(
                    str(
                        recommendation.get(
                            "confidence",
                            0,
                        )
                    )
                ),
                status=recommendation.get(
                    "status",
                    "PENDING",
                ),
            )
        )

    # --------------------------------------------------------
    # Save scan history
    # --------------------------------------------------------

    scan = Scan(
        started_at=datetime.now(),
        completed_at=datetime.now(),
        status="COMPLETED",
        security_score=security.get(
            "security_score",
            0,
        ),
        findings_count=len(findings),
        monthly_cost=Decimal(
            str(
                costs.get(
                    "monthly_cost",
                    0,
                )
            )
        ),
        potential_savings=Decimal(
            str(
                costs.get(
                    "potential_monthly_savings",
                    0,
                )
            )
        ),
    )

    db.add(scan)

    # --------------------------------------------------------
    # Commit transaction
    # --------------------------------------------------------

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    db.refresh(scan)

    return scan