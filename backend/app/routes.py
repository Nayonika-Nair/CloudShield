# ============================================================
# CloudShield API Routes
# ============================================================

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.database import get_db
from app.models import User
from app.schemas import Token, UserLogin, UserRegister, UserResponse
from app.scan_service import run_complete_scan


router = APIRouter(
    prefix="/api",
    tags=["CloudShield"],
)


# ------------------------------------------------------------
# Auth: register
# ------------------------------------------------------------

@router.post(
    "/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: UserRegister,
    db: Session = Depends(get_db),
):
    """
    Register a new user account.
    """

    existing_user = (
        db.query(User)
        .filter(User.email == payload.email)
        .first()
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email already exists.",
        )

    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


# ------------------------------------------------------------
# Auth: login
# ------------------------------------------------------------

@router.post(
    "/auth/login",
    response_model=Token,
)
def login(
    payload: UserLogin,
    db: Session = Depends(get_db),
):
    """
    Authenticate a user and issue a JWT access token.
    """

    invalid_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password.",
    )

    user = (
        db.query(User)
        .filter(User.email == payload.email)
        .first()
    )

    if user is None:
        raise invalid_credentials

    if not verify_password(
        payload.password,
        user.password_hash,
    ):
        raise invalid_credentials

    access_token = create_access_token(
        data={"sub": user.email},
    )

    return Token(access_token=access_token)


# ------------------------------------------------------------
# Provider
# ------------------------------------------------------------

@router.get("/provider")
def get_provider():
    """
    Return the currently active cloud provider.
    """

    result = run_complete_scan()

    return result["provider"]


# ------------------------------------------------------------
# Inventory
# ------------------------------------------------------------

@router.get("/inventory")
def get_inventory():
    """
    Return the discovered cloud resource inventory.
    """

    result = run_complete_scan()

    resources = result["resources"]

    resources_by_type: dict[str, int] = {}

    for resource in resources:
        resource_type = resource["resource_type"]

        resources_by_type[resource_type] = (
            resources_by_type.get(
                resource_type,
                0,
            )
            + 1
        )

    return {
        "total_resources": len(resources),
        "resources_by_type": resources_by_type,
        "resources": resources,
    }


# ------------------------------------------------------------
# Security scan
# ------------------------------------------------------------

@router.get("/security")
def get_security():
    """
    Run the security analysis and return findings and score.
    """

    result = run_complete_scan()

    return {
        "security": result["security"],
        "findings": result["findings"],
    }


# ------------------------------------------------------------
# Cost analysis
# ------------------------------------------------------------

@router.get("/costs")
def get_costs():
    """
    Run the cost analysis and return cost information and
    optimization opportunities.
    """

    result = run_complete_scan()

    return result["costs"]


# ------------------------------------------------------------
# Recommendations
# ------------------------------------------------------------

@router.get("/recommendations")
def get_recommendations():
    """
    Return generated recommendations.
    """

    result = run_complete_scan()

    return {
        "recommendations": result["recommendations"],
        "summary": result["recommendation_summary"],
    }


# ------------------------------------------------------------
# Complete scan
# ------------------------------------------------------------

@router.get("/scan")
def run_scan(db: Session = Depends(get_db)):
    """
    Run the complete CloudShield analysis pipeline and
    persist the results.
    """

    result = run_complete_scan()

    from app.persistence import save_scan_results

    save_scan_results(db, result)

    return result


# ------------------------------------------------------------
# Dashboard
# ------------------------------------------------------------

@router.get("/dashboard")
def get_dashboard():
    """
    Return the key metrics required by the dashboard.
    """

    result = run_complete_scan()

    resources = result["resources"]

    resources_by_type: dict[str, int] = {}

    for resource in resources:
        resource_type = resource["resource_type"]

        resources_by_type[resource_type] = (
            resources_by_type.get(
                resource_type,
                0,
            )
            + 1
        )

    return {
        "provider": result["provider"],
        "total_resources": len(resources),
        "security_score": result["security"][
            "security_score"
        ],
        "total_findings": result["security"][
            "total_findings"
        ],
        "critical_findings": result["security"][
            "critical_findings"
        ],
        "monthly_cost": result["costs"][
            "monthly_cost"
        ],
        "potential_monthly_savings": result["costs"][
            "potential_monthly_savings"
        ],
        "recommendations_count": len(
            result["recommendations"]
        ),
        "resources_by_type": resources_by_type,
        "service_costs": result["costs"][
            "service_costs"
        ],
    }