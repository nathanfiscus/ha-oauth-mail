# pylint: disable=line-too-long
"""Test the config flow."""

import pytest
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import (
    RESULT_TYPE_ABORT,
    RESULT_TYPE_CREATE_ENTRY,
    RESULT_TYPE_EXTERNAL_STEP,
    RESULT_TYPE_FORM,
)
from requests_mock import Mocker

# Define constants locally to avoid import issues
DOMAIN = "oauth_mail"

from .const import BASE_CONFIG_ENTRY, MOCK_TOKEN_RESPONSE, TOKEN_URL


def build_token_url(auth_url: str) -> str:
    """Build a mock token URL for testing."""
    return f"{auth_url}&code=mock_auth_code&state=oauth_mail"


async def test_user_step_form(hass: HomeAssistant) -> None:
    """Test the user step form displays correctly."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    assert result.get("type") is RESULT_TYPE_FORM
    assert result["step_id"] == "user"
    assert "entity_name" in result["data_schema"].schema
    assert "client_id" in result["data_schema"].schema
    assert "client_secret" in result["data_schema"].schema
    assert "provider" in result["data_schema"].schema


async def test_user_step_submit_valid_data(hass: HomeAssistant) -> None:
    """Test the user step accepts valid data."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input=BASE_CONFIG_ENTRY,
    )

    assert result["type"] is RESULT_TYPE_FORM
    assert result["step_id"] == "authorize"


async def test_user_step_duplicate_entity_name(hass: HomeAssistant) -> None:
    """Test the user step rejects duplicate entity names."""
    # First create an entry
    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=0,
        domain=DOMAIN,
        title="test_account",
        data=BASE_CONFIG_ENTRY,
        source=config_entries.SOURCE_USER,
        entry_id="test_entry_id",
    )
    hass.config_entries._entries.append(entry)

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input=BASE_CONFIG_ENTRY,
    )

    assert result["type"] is RESULT_TYPE_FORM
    assert result["step_id"] == "user"
    assert "errors" in result
    assert "entity_name" in result["errors"]
    assert result["errors"]["entity_name"] == "already_configured"


async def test_authorize_step_form(hass: HomeAssistant) -> None:
    """Test the authorize step form displays correctly."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input=BASE_CONFIG_ENTRY,
    )

    assert result["type"] is RESULT_TYPE_FORM
    assert result["step_id"] == "authorize"
    assert "description_placeholders" in result
    assert "auth_url" in result["description_placeholders"]
    assert "failed_permissions" in result["description_placeholders"]
    assert "url" in result["data_schema"].schema


async def test_authorize_step_valid_token_exchange(
    hass: HomeAssistant, requests_mock: Mocker
) -> None:
    """Test successful token exchange."""
    # Mock the token endpoint
    requests_mock.post(TOKEN_URL, json=MOCK_TOKEN_RESPONSE)

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input=BASE_CONFIG_ENTRY,
    )

    # Build a mock callback URL
    auth_url = result["description_placeholders"]["auth_url"]
    callback_url = build_token_url(auth_url)

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={"url": callback_url},
    )

    assert result["type"] is RESULT_TYPE_CREATE_ENTRY
    assert "result" in result
    assert result["result"].data["entity_name"] == BASE_CONFIG_ENTRY["entity_name"]


async def test_authorize_step_invalid_url(hass: HomeAssistant) -> None:
    """Test invalid URL handling."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input=BASE_CONFIG_ENTRY,
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={"url": "invalid-url"},
    )

    assert result["type"] is RESULT_TYPE_FORM
    assert result["step_id"] == "authorize"
    assert "errors" in result
    assert "url" in result["errors"]
    assert result["errors"]["url"] == "invalid_url"


async def test_authorize_step_missing_code(hass: HomeAssistant) -> None:
    """Test URL without authorization code."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input=BASE_CONFIG_ENTRY,
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={"url": "https://example.com/callback?state=oauth_mail"},
    )

    assert result["type"] is RESULT_TYPE_FORM
    assert result["step_id"] == "authorize"
    assert "errors" in result
    assert "url" in result["errors"]
    assert result["errors"]["url"] == "invalid_url"


async def test_token_exchange_failure(hass: HomeAssistant, requests_mock: Mocker) -> None:
    """Test token exchange failure."""
    # Mock failed token request
    requests_mock.post(TOKEN_URL, status_code=400, json={"error": "invalid_request"})

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input=BASE_CONFIG_ENTRY,
    )

    auth_url = result["description_placeholders"]["auth_url"]
    callback_url = build_token_url(auth_url)

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={"url": callback_url},
    )

    assert result["type"] is RESULT_TYPE_ABORT
    assert result["reason"] == "token_request_failed"


async def test_gmail_provider(hass: HomeAssistant) -> None:
    """Test Gmail provider configuration."""
    gmail_config = BASE_CONFIG_ENTRY.copy()
    gmail_config["provider"] = "gmail"

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input=gmail_config,
    )

    assert result["type"] is RESULT_TYPE_FORM
    assert result["step_id"] == "authorize"
    # Gmail uses different auth URL
    auth_url = result["description_placeholders"]["auth_url"]
    assert "accounts.google.com" in auth_url


async def test_unsupported_provider(hass: HomeAssistant) -> None:
    """Test unsupported provider handling."""
    invalid_config = BASE_CONFIG_ENTRY.copy()
    invalid_config["provider"] = "unsupported"

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input=invalid_config,
    )

    assert result["type"] is RESULT_TYPE_ABORT
    assert result["reason"] == "unsupported_provider"