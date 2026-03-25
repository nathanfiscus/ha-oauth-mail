"""Tests for first-account proxy password handling in the config flow."""

from unittest.mock import AsyncMock, Mock, patch

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import RESULT_TYPE_CREATE_ENTRY, RESULT_TYPE_FORM
from requests_mock import Mocker

from custom_components.oauth_mail.config_flow import OAuthMailConfigFlow

DOMAIN = "oauth_mail"
GMAIL_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


def _build_callback_url(auth_url: str) -> str:
    """Build a mock callback URL for the authorize step."""
    return f"{auth_url}&code=mock_auth_code&state=oauth_mail"


def _build_flow(hass: HomeAssistant) -> OAuthMailConfigFlow:
    """Create a flow instance without requiring the full http dependency setup."""
    flow = OAuthMailConfigFlow()
    flow.hass = hass
    hass.http = Mock()
    return flow


async def test_first_account_prompts_for_proxy_password(hass: HomeAssistant) -> None:
    """The first configured account should prompt for the proxy password."""
    flow = _build_flow(hass)
    result = await flow.async_step_user()

    assert result["type"] is RESULT_TYPE_FORM
    assert result["step_id"] == "user"
    assert "proxy_password" in result["data_schema"].schema
    assert "first account" in result["description_placeholders"]["proxy_password_help"]


async def test_subsequent_accounts_reuse_saved_proxy_password(hass: HomeAssistant) -> None:
    """Later accounts should not prompt for the proxy password again."""
    entry = config_entries.ConfigEntry(
        version=1,
        domain=DOMAIN,
        title="existing_account",
        data={"proxy_password": "saved-proxy-password"},
        source=config_entries.SOURCE_USER,
        entry_id="existing_entry_id",
    )
    hass.config_entries._entries[entry.entry_id] = entry

    flow = _build_flow(hass)
    result = await flow.async_step_user()

    assert result["type"] is RESULT_TYPE_FORM
    assert result["step_id"] == "user"
    assert "proxy_password" not in result["data_schema"].schema
    assert result["description_placeholders"]["proxy_password_help"] == ""


async def test_first_account_stores_proxy_password_and_removes_auth_code(
    hass: HomeAssistant, requests_mock: Mocker
) -> None:
    """The first account should persist the user-set proxy password in the entry data."""
    requests_mock.post(
        GMAIL_TOKEN_URL,
        json={
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer",
        },
    )
    requests_mock.get(GMAIL_USERINFO_URL, json={"email": "user@example.com"})

    flow = _build_flow(hass)

    with patch("custom_components.oauth_mail.config_flow._write_proxy_account_config") as mock_write, patch(
        "custom_components.oauth_mail.config_flow.get_url", return_value="http://localhost:8123"
    ):
        result = await flow.async_step_user(
            user_input={
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "proxy_password": "user-set-password",
                "provider": "gmail",
            },
        )

        callback_url = _build_callback_url(result["description_placeholders"]["auth_url"])
        result = await flow.async_step_authorize(user_input={"url": callback_url})

    assert result["type"] is RESULT_TYPE_CREATE_ENTRY
    assert result["data"]["proxy_password"] == "user-set-password"
    assert "auth_code" not in result["data"]
    assert mock_write.call_args.kwargs["proxy_password"] == "user-set-password"


async def test_later_account_reuses_saved_proxy_password_for_encryption(
    hass: HomeAssistant, requests_mock: Mocker
) -> None:
    """Later accounts should reuse the previously stored proxy password automatically."""
    entry = config_entries.ConfigEntry(
        version=1,
        domain=DOMAIN,
        title="existing_account",
        data={"proxy_password": "saved-proxy-password"},
        source=config_entries.SOURCE_USER,
        entry_id="existing_entry_id",
    )
    hass.config_entries._entries[entry.entry_id] = entry

    requests_mock.post(
        GMAIL_TOKEN_URL,
        json={
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer",
        },
    )
    requests_mock.get(GMAIL_USERINFO_URL, json={"email": "later@example.com"})

    flow = _build_flow(hass)

    with patch("custom_components.oauth_mail.config_flow._write_proxy_account_config") as mock_write, patch(
        "custom_components.oauth_mail.config_flow.get_url", return_value="http://localhost:8123"
    ):
        result = await flow.async_step_user(
            user_input={
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "provider": "gmail",
            },
        )

        callback_url = _build_callback_url(result["description_placeholders"]["auth_url"])
        result = await flow.async_step_authorize(user_input={"url": callback_url})

    assert result["type"] is RESULT_TYPE_CREATE_ENTRY
    assert "proxy_password" not in result["data"]
    assert mock_write.call_args.kwargs["proxy_password"] == "saved-proxy-password"


async def test_callback_auto_submits_authorize_step(hass: HomeAssistant) -> None:
    """OAuth callback should auto-submit authorize step without manual URL paste."""
    flow = _build_flow(hass)
    flow.flow_id = "test-flow-id"

    mock_async_configure = AsyncMock()
    hass.config_entries.flow = Mock(async_configure=mock_async_configure)

    with patch("custom_components.oauth_mail.config_flow.get_url", return_value="http://localhost:8123"):
        await flow.async_step_user(
            user_input={
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "provider": "gmail",
                "proxy_password": "password",
            },
        )

    request = Mock()
    request.url = "http://localhost:8123/api/oauth_mail?code=mock_auth_code&state=oauth_mail"
    response = await flow.callback_view.get(request)
    await hass.async_block_till_done()

    mock_async_configure.assert_awaited_once_with(
        "test-flow-id",
        user_input={"url": str(request.url)},
    )
    assert "continue automatically" in response.text