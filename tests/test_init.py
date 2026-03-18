"""Test the component initialization."""

import pytest
from homeassistant.core import HomeAssistant

# Define constants locally to avoid import issues
DOMAIN = "oauth_mail"

try:
    from custom_components.oauth_mail import async_setup_entry
except ImportError:
    async_setup_entry = None

from .const import BASE_CONFIG_ENTRY


async def test_async_setup_entry_success(hass: HomeAssistant) -> None:
    """Test successful setup of a config entry."""
    pytest.importorskip("custom_components.oauth_mail")

    entry = pytest.mock.MagicMock()
    entry.data = BASE_CONFIG_ENTRY

    # Since our integration just provides OAuth tokens and doesn't create entities,
    # the setup should return True
    from custom_components.oauth_mail import async_setup_entry
    result = await async_setup_entry(hass, entry)

    assert result is True


async def test_async_setup_entry_minimal_data(hass: HomeAssistant) -> None:
    """Test setup with minimal config data."""
    pytest.importorskip("custom_components.oauth_mail")

    entry = pytest.mock.MagicMock()
    entry.data = {
        "entity_name": "test",
        "client_id": "test_id",
        "client_secret": "test_secret",
    }

    from custom_components.oauth_mail import async_setup_entry
    result = await async_setup_entry(hass, entry)

    assert result is True