# ============================================================
# CloudShield Cloud Provider Interface
# ============================================================
#
# This file defines the common interface that every cloud
# provider must implement.
#
# Currently:
#     MockCloudProvider is used.
#
# Later:
#     AWSCloudProvider can implement the same interface.
#
# The rest of CloudShield will interact with this interface
# rather than directly depending on AWS.
# ============================================================


from abc import ABC, abstractmethod


class CloudProvider(ABC):
    """
    Abstract interface for cloud providers.

    Every provider used by CloudShield must implement these
    operations.
    """

    # ========================================================
    # EC2
    # ========================================================

    @abstractmethod
    def get_ec2_instances(self):
        """
        Return EC2 instances.

        Expected format:

        [
            {
                "resource_id": "...",
                "name": "...",
                "type": "EC2",
                "region": "...",
                "status": "...",
                "security_state": "..."
            }
        ]
        """
        raise NotImplementedError

    # ========================================================
    # S3
    # ========================================================

    @abstractmethod
    def get_s3_buckets(self):
        """
        Return S3 buckets.
        """
        raise NotImplementedError

    # ========================================================
    # IAM
    # ========================================================

    @abstractmethod
    def get_iam_users(self):
        """
        Return IAM users.
        """
        raise NotImplementedError

    # ========================================================
    # Security Groups
    # ========================================================

    @abstractmethod
    def get_security_groups(self):
        """
        Return security groups.
        """
        raise NotImplementedError

    # ========================================================
    # EBS
    # ========================================================

    @abstractmethod
    def get_ebs_volumes(self):
        """
        Return EBS volumes.
        """
        raise NotImplementedError

    # ========================================================
    # Cost
    # ========================================================

    @abstractmethod
    def get_cost_data(self):
        """
        Return cloud cost information.

        Expected format:

        [
            {
                "service": "EC2",
                "amount": 620.00,
                "currency": "USD"
            }
        ]
        """
        raise NotImplementedError

    # ========================================================
    # Complete Inventory
    # ========================================================

    def get_all_resources(self):
        """
        Return all resources from the provider.

        This method combines the individual resource
        discovery operations into one inventory.
        """

        resources = []

        resources.extend(
            self.get_ec2_instances()
        )

        resources.extend(
            self.get_s3_buckets()
        )

        resources.extend(
            self.get_iam_users()
        )

        resources.extend(
            self.get_security_groups()
        )

        resources.extend(
            self.get_ebs_volumes()
        )

        return resources

    # ========================================================
    # Provider Information
    # ========================================================

    def get_provider_info(self):
        """
        Return basic information about the provider.
        """

        return {
            "provider": self.__class__.__name__,
            "mode": "UNKNOWN",
        }