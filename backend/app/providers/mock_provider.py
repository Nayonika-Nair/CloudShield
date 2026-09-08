# ============================================================
# CloudShield Mock Cloud Provider
# ============================================================

from typing import Any

from app.providers.base import CloudProvider


class MockCloudProvider(CloudProvider):
    """
    Demo cloud provider used when AWS integration is disabled.

    The provider returns deterministic cloud inventory and cost
    data so CloudShield can be developed and demonstrated without
    AWS credentials.
    """

    provider_name = "Mock Cloud"
    mode = "DEMO"

    def get_ec2_instances(self) -> list[dict[str, Any]]:
        return [
            {
                "resource_id": "i-0prod001",
                "name": "prod-server-01",
                "resource_type": "EC2",
                "region": "us-east-1",
                "status": "Running",
                "security_state": "Open SSH",
            },
            {
                "resource_id": "i-0dev002",
                "name": "dev-server-01",
                "resource_type": "EC2",
                "region": "us-east-1",
                "status": "Running",
                "security_state": "Healthy",
            },
            {
                "resource_id": "i-0analytics03",
                "name": "analytics-server",
                "resource_type": "EC2",
                "region": "us-west-2",
                "status": "Stopped",
                "security_state": "Healthy",
            },
        ]

    def get_s3_buckets(self) -> list[dict[str, Any]]:
        return [
            {
                "resource_id": "s3-company-data",
                "name": "company-data",
                "resource_type": "S3",
                "region": "us-east-1",
                "status": "Private",
                "security_state": "Public access blocked",
            },
            {
                "resource_id": "s3-public-assets",
                "name": "public-assets",
                "resource_type": "S3",
                "region": "us-east-1",
                "status": "Public",
                "security_state": "Public",
            },
            {
                "resource_id": "s3-backups",
                "name": "company-backups",
                "resource_type": "S3",
                "region": "us-west-2",
                "status": "Private",
                "security_state": "Public access blocked",
            },
        ]

    def get_iam_users(self) -> list[dict[str, Any]]:
        return [
            {
                "resource_id": "iam-admin",
                "name": "admin-user",
                "resource_type": "IAM",
                "region": "global",
                "status": "Active",
                "security_state": "MFA disabled",
            },
            {
                "resource_id": "iam-dev",
                "name": "developer",
                "resource_type": "IAM",
                "region": "global",
                "status": "Active",
                "security_state": "MFA enabled",
            },
            {
                "resource_id": "iam-auditor",
                "name": "security-auditor",
                "resource_type": "IAM",
                "region": "global",
                "status": "Active",
                "security_state": "MFA enabled",
            },
        ]

    def get_security_groups(self) -> list[dict[str, Any]]:
        return [
            {
                "resource_id": "sg-ssh-open",
                "name": "web-open-ssh",
                "resource_type": "SECURITY_GROUP",
                "region": "us-east-1",
                "status": "Active",
                "security_state": "SSH 0.0.0.0/0",
            },
            {
                "resource_id": "sg-web",
                "name": "web-standard",
                "resource_type": "SECURITY_GROUP",
                "region": "us-east-1",
                "status": "Active",
                "security_state": "Healthy",
            },
            {
                "resource_id": "sg-db",
                "name": "database-private",
                "resource_type": "SECURITY_GROUP",
                "region": "us-west-2",
                "status": "Active",
                "security_state": "Healthy",
            },
        ]

    def get_ebs_volumes(self) -> list[dict[str, Any]]:
        return [
            {
                "resource_id": "vol-0248",
                "name": "old-volume",
                "resource_type": "EBS",
                "region": "us-east-1",
                "status": "Unattached",
                "security_state": "Encrypted",
            },
            {
                "resource_id": "vol-0249",
                "name": "prod-volume",
                "resource_type": "EBS",
                "region": "us-east-1",
                "status": "Attached",
                "security_state": "Encrypted",
            },
            {
                "resource_id": "vol-0250",
                "name": "backup-volume",
                "resource_type": "EBS",
                "region": "us-west-2",
                "status": "Attached",
                "security_state": "Encrypted",
            },
        ]

    def get_cost_data(self) -> list[dict[str, Any]]:
        return [
            {"service": "EC2", "amount": 620.0},
            {"service": "S3", "amount": 140.0},
            {"service": "RDS", "amount": 210.0},
            {"service": "EBS", "amount": 80.0},
            {"service": "Other", "amount": 70.0},
        ]

    def get_provider_info(self) -> dict[str, Any]:
        return {
            "provider": self.provider_name,
            "mode": self.mode,
            "aws_enabled": False,
            "credentials_required": False,
        }