# ============================================================
# CloudShield Cloud Provider Factory
# ============================================================
#
# This module provides the cloud provider used by the
# application.
#
# DEFAULT:
#     MockCloudProvider
#
# AWS will only be used later when explicitly enabled.
# ============================================================

import os

from app.providers.mock_provider import MockCloudProvider


def get_cloud_provider():
    """
    Return the cloud provider that CloudShield should use.

    Mock mode is the default and is intentionally used unless
    AWS integration has been explicitly enabled.
    """

    demo_mode = os.getenv(
        "DEMO_MODE",
        "true",
    ).lower() == "true"

    aws_enabled = os.getenv(
        "AWS_ENABLED",
        "false",
    ).lower() == "true"

    # --------------------------------------------------------
    # Default: Mock Provider
    # --------------------------------------------------------

    if demo_mode or not aws_enabled:
        return MockCloudProvider()

    # --------------------------------------------------------
    # AWS Provider
    # --------------------------------------------------------
    #
    # We intentionally do not import or initialize an AWS
    # provider yet.
    #
    # This prevents accidental AWS API calls while we are
    # developing the application.
    # --------------------------------------------------------

    raise RuntimeError(
        "AWS integration is not implemented yet. "
        "Keep DEMO_MODE=true and AWS_ENABLED=false."
    )