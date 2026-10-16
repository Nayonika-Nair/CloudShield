"""Static catalogs used by the Fake AWS simulator.

All prices are SIMULATED. They are loosely shaped like public on-demand rates
but are not live AWS prices and must never be presented as such.
"""

from __future__ import annotations

# instance type -> (vCPUs, memory GiB, simulated USD per hour)
EC2_TYPES: dict[str, tuple[int, int, float]] = {
    "t3.micro": (2, 1, 0.0104),
    "t3.small": (2, 2, 0.0208),
    "t3.medium": (2, 4, 0.0416),
    "t3.large": (2, 8, 0.0832),
    "t3.xlarge": (4, 16, 0.1664),
    "t3.2xlarge": (8, 32, 0.3328),
    "m5.large": (2, 8, 0.096),
    "m5.xlarge": (4, 16, 0.192),
    "m5.2xlarge": (8, 32, 0.384),
    "m5.4xlarge": (16, 64, 0.768),
    "c5.large": (2, 4, 0.085),
    "c5.xlarge": (4, 8, 0.17),
    "c5.2xlarge": (8, 16, 0.34),
    "r5.large": (2, 16, 0.126),
    "r5.xlarge": (4, 32, 0.252),
    "r5.2xlarge": (8, 64, 0.504),
}

# Ordered size ladders used for right-sizing within a family.
EC2_FAMILIES: dict[str, list[str]] = {
    "t3": ["t3.micro", "t3.small", "t3.medium", "t3.large", "t3.xlarge", "t3.2xlarge"],
    "m5": ["m5.large", "m5.xlarge", "m5.2xlarge", "m5.4xlarge"],
    "c5": ["c5.large", "c5.xlarge", "c5.2xlarge"],
    "r5": ["r5.large", "r5.xlarge", "r5.2xlarge"],
}

# RDS class -> (vCPUs, memory GiB, simulated USD per hour)
RDS_CLASSES: dict[str, tuple[int, int, float]] = {
    "db.t3.medium": (2, 4, 0.068),
    "db.t3.large": (2, 8, 0.136),
    "db.m5.large": (2, 8, 0.171),
    "db.m5.xlarge": (4, 16, 0.342),
    "db.m5.2xlarge": (8, 32, 0.684),
    "db.r5.large": (2, 16, 0.24),
    "db.r5.xlarge": (4, 32, 0.48),
}
RDS_FAMILIES: dict[str, list[str]] = {
    "db.t3": ["db.t3.medium", "db.t3.large"],
    "db.m5": ["db.m5.large", "db.m5.xlarge", "db.m5.2xlarge"],
    "db.r5": ["db.r5.large", "db.r5.xlarge"],
}

DEFAULT_PRICING: dict = {
    "ec2_hourly": {k: v[2] for k, v in EC2_TYPES.items()},
    "rds_hourly": {k: v[2] for k, v in RDS_CLASSES.items()},
    "ebs_gb_month": {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "st1": 0.045},
    "s3_gb_month": 0.023,
    "rds_storage_gb_month": 0.115,
    "snapshot_gb_month": 0.05,
    "eip_idle_hourly": 0.005,
    "data_transfer_out_gb": 0.09,
    "alb_hourly": 0.0225,
    "alb_lcu_hourly": 0.008,
}

REGIONS: dict[str, list[str]] = {
    "us-east-1": ["us-east-1a", "us-east-1b", "us-east-1c"],
    "us-east-2": ["us-east-2a", "us-east-2b", "us-east-2c"],
    "us-west-2": ["us-west-2a", "us-west-2b", "us-west-2c"],
    "eu-west-1": ["eu-west-1a", "eu-west-1b", "eu-west-1c"],
    "eu-central-1": ["eu-central-1a", "eu-central-1b", "eu-central-1c"],
    "ap-south-1": ["ap-south-1a", "ap-south-1b", "ap-south-1c"],
    "ap-southeast-1": ["ap-southeast-1a", "ap-southeast-1b", "ap-southeast-1c"],
}

# port -> service label, used by the network and security rules.
SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}
DATABASE_PORTS = {1433, 3306, 5432, 6379, 9200, 27017}

MONTH_DAYS = 30  # billing month used for every monthly estimate

SERVICE_BY_TYPE: dict[str, str] = {
    "ec2_instance": "EC2",
    "ebs_volume": "EBS",
    "snapshot": "Snapshots",
    "s3_bucket": "S3",
    "rds_instance": "RDS",
    "elastic_ip": "Elastic IP",
    "load_balancer": "Load Balancing",
}

OS_CHOICES = ("linux", "windows")

FIRST_NAMES = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
    "ivan", "judy", "ken", "laura", "mallory", "nina", "oscar", "peggy",
    "quinn", "rupert", "sybil", "trent",
]

ROLE_SIZES = {
    "web": ["t3.medium", "t3.large", "m5.large", "c5.large"],
    "app": ["m5.large", "m5.xlarge", "m5.2xlarge", "c5.xlarge"],
    "worker": ["m5.xlarge", "m5.2xlarge", "c5.2xlarge", "r5.xlarge"],
    "batch": ["m5.2xlarge", "r5.xlarge", "r5.2xlarge", "m5.4xlarge"],
    "bastion": ["t3.micro", "t3.small"],
}
