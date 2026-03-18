"""Configuration flow for OAuth Mail."""

import configparser
import functools as ft
import logging
import time
from typing import Any

import homeassistant.helpers.config_validation as cv
import requests
import voluptuous as vol
from aiohttp import web_response
from homeassistant import config_entries
from homeassistant.components.http import HomeAssistantView
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.core import callback
from homeassistant.helpers.network import get_url

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

AUTH_CALLBACK_NAME = "api:oauth_mail"
AUTH_CALLBACK_PATH = "/api/oauth_mail"

REQUEST_AUTHORIZATION_SCHEMA = vol.Schema(
    {
        vol.Required("url"): cv.string,
    }
)

CONFIG_SCHEMA = vol.Schema(
    {
        vol.Required("entity_name"): vol.All(cv.string, vol.Strip),
        vol.Required("client_id"): vol.All(cv.string, vol.Strip),
        vol.Required("client_secret"): vol.All(cv.string, vol.Strip),
        vol.Optional("provider", default="outlook"): vol.In(["outlook", "gmail"]),
    }
)


class OAuthMailAuthCallbackView(HomeAssistantView):
    """OAuth Mail Authorization Callback View."""

    url = AUTH_CALLBACK_PATH
    name = AUTH_CALLBACK_NAME
    requires_auth = False

    def __init__(self):
        """Initialize the callback view."""
        self.token_url = ""

    @callback
    async def get(self, request):
        """Handle the GET request."""
        self.token_url = str(request.url)
        return web_response.Response(
            headers={"content-type": "text/html"},
            text="<script>window.close()</script>This window can be closed",
        )


class OAuthMailConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """OAuth Mail config flow."""

    VERSION = 1

    def __init__(self):
        """Initialize the config flow."""
        self.user_input = {}
        self.callback_view = None
        self._auth_url = None

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        if user_input:
            self.user_input = user_input
            # Check if entity_name is already configured
            existing_entries = [
                entry
                for entry in self.hass.config_entries.async_entries(DOMAIN)
                if entry.data.get("entity_name") == user_input.get("entity_name")
            ]
            if existing_entries:
                errors["entity_name"] = "already_configured"
            else:
                return await self.async_step_authorize()

        return self.async_show_form(
            step_id="user",
            data_schema=CONFIG_SCHEMA,
            errors=errors,
        )

    async def async_step_authorize(self, user_input=None):
        """Handle the authorization step."""
        errors = {}

        provider = self.user_input["provider"]
        if provider == "outlook":
            permission_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
            scope = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
        elif provider == "gmail":
            permission_url = "https://accounts.google.com/o/oauth2/auth"
            scope = "https://mail.google.com/"
        else:
            return self.async_abort(reason="unsupported_provider")

        redirect_uri = f"{get_url(self.hass)}{AUTH_CALLBACK_PATH}"

        params = {
            "client_id": self.user_input["client_id"],
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": "oauth_mail",
        }

        self._auth_url = f"{permission_url}?{'&'.join(f'{k}={requests.utils.quote(str(v))}' for k, v in params.items())}"

        if user_input is not None:
            errors = await self._async_validate_response(user_input)
            if not errors:
                return await self._async_create_entry()

        return self.async_show_form(
            step_id="authorize",
            description_placeholders={"auth_url": self._auth_url},
            data_schema=REQUEST_AUTHORIZATION_SCHEMA,
            errors=errors,
        )

    async def _async_validate_response(self, user_input):
        """Validate the authorization response."""
        errors = {}
        url = user_input.get("url", "")

        if not url:
            errors["url"] = "invalid_url"
            return errors

        if "code=" not in url:
            errors["url"] = "invalid_url"
            return errors

        # Extract the authorization code from the URL
        try:
            code = None
            for param in url.split("?")[1].split("&"):
                if param.startswith("code="):
                    code = param.split("=")[1]
                    break

            if not code:
                errors["url"] = "invalid_url"
                return errors

            self.user_input["auth_code"] = code
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error("Error extracting code from URL: %s", err)
            errors["url"] = "invalid_url"
            return errors

        return errors

    async def _async_create_entry(self):
        """Create the config entry."""
        try:
            # Exchange the authorization code for tokens
            provider = self.user_input["provider"]
            if provider == "outlook":
                token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            elif provider == "gmail":
                token_url = "https://oauth2.googleapis.com/token"
            else:
                return self.async_abort(reason="unsupported_provider")

            redirect_uri = f"{get_url(self.hass)}{AUTH_CALLBACK_PATH}"

            data = {
                "client_id": self.user_input["client_id"],
                "client_secret": self.user_input["client_secret"],
                "code": self.user_input.get("auth_code"),
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            }

            response = await self.hass.async_add_executor_job(
                ft.partial(requests.post, token_url, data=data)
            )

            if response.status_code != 200:
                _LOGGER.error("Token request failed: %s", response.text)
                return self.async_abort(reason="token_request_failed")

            tokens = response.json()

            # Save configuration
            config = configparser.ConfigParser(interpolation=None)
            config.add_section(self.user_input["entity_name"])
            config.set(self.user_input["entity_name"], "access_token", tokens.get("access_token", ""))
            if "refresh_token" in tokens:
                config.set(self.user_input["entity_name"], "refresh_token", tokens["refresh_token"])
            config.set(
                self.user_input["entity_name"],
                "access_token_expiry",
                str(int(tokens.get("expires_in", 3600)) + int(time.time())),
            )
            config.set(self.user_input["entity_name"], "last_activity", str(int(time.time())))

            # Write to /share/oauth-mail-tokens
            cache_file = "/share/oauth-mail-tokens"
            with open(cache_file, "w", encoding="utf-8") as f:
                config.write(f)

            # Also write account config for the proxy
            account_config_file = "/share/oauth-mail-accounts.ini"
            with open(account_config_file, "w", encoding="utf-8") as f:
                f.write(f"[{self.user_input['entity_name']}]\n")
                if self.user_input["provider"] == "outlook":
                    f.write("permission_url = https://login.microsoftonline.com/common/oauth2/v2.0/authorize\n")
                    f.write("token_url = https://login.microsoftonline.com/common/oauth2/v2.0/token\n")
                    f.write("oauth2_scope = https://outlook.office.com/IMAP.AccessAsUser.All offline_access\n")
                elif self.user_input["provider"] == "gmail":
                    f.write("permission_url = https://accounts.google.com/o/oauth2/auth\n")
                    f.write("token_url = https://oauth2.googleapis.com/token\n")
                    f.write("oauth2_scope = https://mail.google.com/\n")
                f.write(f"client_id = {self.user_input['client_id']}\n")
                f.write(f"client_secret = {self.user_input['client_secret']}\n")
                f.write("redirect_uri = http://localhost\n")

            return self.async_create_entry(
                title=self.user_input["entity_name"],
                data=self.user_input,
            )
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error("Error creating entry: %s", err)
            return self.async_abort(reason="token_request_failed")