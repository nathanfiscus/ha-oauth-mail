# pylint: disable=protected-access,redefined-outer-name
"""Global fixtures for integration."""

import os
import sys
import pytest
from unittest.mock import patch
from homeassistant.core import HomeAssistant

# Add the project root to Python path for custom components
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Define constants locally to avoid import issues
DOMAIN = "oauth_mail"

pytest_plugins = [
    "pytest_homeassistant_custom_component",
]  # pylint: disable=invalid-name


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):  # pylint: disable=unused-argument
    """Automatically enable loading custom integrations in all tests."""
    return


@pytest.fixture(autouse=True)
def skip_notifications():
    """Skip notification calls."""
    with patch("homeassistant.components.persistent_notification.async_create"), \
         patch("homeassistant.components.persistent_notification.async_dismiss"):
        yield