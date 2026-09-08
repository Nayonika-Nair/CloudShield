# ============================================================
# CloudShield API Schemas
# ============================================================

from typing import Any

from pydantic import BaseModel, EmailStr, Field


# ------------------------------------------------------------
# Generic API response
# ------------------------------------------------------------

class StatusResponse(BaseModel):
    status: str
    message: str


# ------------------------------------------------------------
# Provider information
# ------------------------------------------------------------

class ProviderInfo(BaseModel):
    provider: str
    mode: str
    aws_enabled: bool = False
    credentials_required: bool = False


# ------------------------------------------------------------
# Cloud resource
# ------------------------------------------------------------

class CloudResourceResponse(BaseModel):
    resource_id: str
    name: str
    resource_type: str
    region: str
    status: str
    security_state: str


# ------------------------------------------------------------
# Security finding
# ------------------------------------------------------------

class SecurityFindingResponse(BaseModel):
    title: str
    severity: str
    resource_id: str
    description: str
    risk: str
    recommendation: str
    status: str


# ------------------------------------------------------------
# Security scan summary
# ------------------------------------------------------------

class SecuritySummaryResponse(BaseModel):
    security_score: int = Field(
        ge=0,
        le=100,
    )
    total_resources: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    severity_counts: dict[str, int]


# ------------------------------------------------------------
# Cost opportunity
# ------------------------------------------------------------

class CostOpportunityResponse(BaseModel):
    title: str
    resource_id: str
    explanation: str
    action: str
    monthly_savings: float
    priority: str
    status: str


# ------------------------------------------------------------
# Cost analysis
# ------------------------------------------------------------

class CostAnalysisResponse(BaseModel):
    monthly_cost: float
    currency: str
    service_costs: dict[str, float]
    opportunities: list[CostOpportunityResponse]
    opportunity_count: int
    potential_monthly_savings: float


# ------------------------------------------------------------
# Recommendation
# ------------------------------------------------------------

class RecommendationResponse(BaseModel):
    title: str
    category: str
    priority: str
    explanation: str
    action: str
    confidence: float
    status: str


# ------------------------------------------------------------
# Recommendation summary
# ------------------------------------------------------------

class RecommendationSummaryResponse(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    security: int
    cost: int


# ------------------------------------------------------------
# Complete scan response
# ------------------------------------------------------------

class ScanResponse(BaseModel):
    provider: ProviderInfo
    resources: list[CloudResourceResponse]
    security: SecuritySummaryResponse
    findings: list[SecurityFindingResponse]
    costs: CostAnalysisResponse
    recommendations: list[RecommendationResponse]
    recommendation_summary: RecommendationSummaryResponse


# ------------------------------------------------------------
# Inventory response
# ------------------------------------------------------------

class InventoryResponse(BaseModel):
    total_resources: int
    resources: list[CloudResourceResponse]


# ------------------------------------------------------------
# Dashboard response
# ------------------------------------------------------------

class DashboardResponse(BaseModel):
    provider: ProviderInfo
    total_resources: int
    security_score: int
    total_findings: int
    critical_findings: int
    monthly_cost: float
    potential_monthly_savings: float
    recommendations_count: int
    resources_by_type: dict[str, int]
    service_costs: dict[str, float]


# ------------------------------------------------------------
# Auth: registration
# ------------------------------------------------------------

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(
        min_length=8,
        max_length=128,
    )


# ------------------------------------------------------------
# Auth: login
# ------------------------------------------------------------

class UserLogin(BaseModel):
    email: EmailStr
    password: str


# ------------------------------------------------------------
# Auth: token response
# ------------------------------------------------------------

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ------------------------------------------------------------
# Auth: user response (never includes password_hash)
# ------------------------------------------------------------

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    created_at: Any