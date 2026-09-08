from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    Numeric,
    String,
    Text,
)

from app.database import Base


# ============================================================
# User
# ============================================================

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash = Column(
        String(255),
        nullable=False,
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )


# ============================================================
# Cloud Resource
# ============================================================

class CloudResource(Base):
    __tablename__ = "cloud_resources"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    resource_id = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    name = Column(
        String(255),
        nullable=False,
    )

    resource_type = Column(
        String(50),
        nullable=False,
        index=True,
    )

    region = Column(
        String(100),
        nullable=False,
        index=True,
    )

    status = Column(
        String(100),
        nullable=False,
    )

    security_state = Column(
        String(100),
        nullable=False,
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# ============================================================
# Security Finding
# ============================================================

class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    title = Column(
        String(255),
        nullable=False,
    )

    severity = Column(
        String(20),
        nullable=False,
        index=True,
    )

    resource_id = Column(
        String(255),
        nullable=False,
        index=True,
    )

    description = Column(
        Text,
        nullable=False,
    )

    risk = Column(
        Text,
        nullable=False,
    )

    recommendation = Column(
        Text,
        nullable=False,
    )

    status = Column(
        String(30),
        nullable=False,
        default="OPEN",
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )


# ============================================================
# Cost Record
# ============================================================

class CostRecord(Base):
    __tablename__ = "cost_records"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    service = Column(
        String(100),
        nullable=False,
        index=True,
    )

    amount = Column(
        Numeric(12, 2),
        nullable=False,
    )

    currency = Column(
        String(10),
        nullable=False,
        default="USD",
    )

    recorded_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )


# ============================================================
# Cost Optimization Opportunity
# ============================================================

class CostOpportunity(Base):
    __tablename__ = "cost_opportunities"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    title = Column(
        String(255),
        nullable=False,
    )

    resource_id = Column(
        String(255),
        nullable=False,
        index=True,
    )

    explanation = Column(
        Text,
        nullable=False,
    )

    action = Column(
        Text,
        nullable=False,
    )

    monthly_savings = Column(
        Numeric(12, 2),
        nullable=False,
        default=0,
    )

    priority = Column(
        String(20),
        nullable=False,
        index=True,
    )

    status = Column(
        String(30),
        nullable=False,
        default="OPEN",
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )


# ============================================================
# Recommendation
# ============================================================

class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    title = Column(
        String(255),
        nullable=False,
    )

    category = Column(
        String(50),
        nullable=False,
    )

    priority = Column(
        String(20),
        nullable=False,
        index=True,
    )

    explanation = Column(
        Text,
        nullable=False,
    )

    action = Column(
        Text,
        nullable=False,
    )

    confidence = Column(
        Numeric(5, 2),
        nullable=False,
        default=0,
    )

    status = Column(
        String(30),
        nullable=False,
        default="PENDING",
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )


# ============================================================
# Scan History
# ============================================================

class Scan(Base):
    __tablename__ = "scans"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    started_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    completed_at = Column(
        DateTime,
        nullable=True,
    )

    status = Column(
        String(30),
        nullable=False,
        default="COMPLETED",
    )

    security_score = Column(
        Integer,
        nullable=False,
        default=0,
    )

    findings_count = Column(
        Integer,
        nullable=False,
        default=0,
    )

    monthly_cost = Column(
        Numeric(12, 2),
        nullable=False,
        default=0,
    )

    potential_savings = Column(
        Numeric(12, 2),
        nullable=False,
        default=0,
    )