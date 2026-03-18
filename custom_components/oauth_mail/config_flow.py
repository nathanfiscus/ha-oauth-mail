"""Configuration flow for OAuth Mail."""

import base64
import configparser
import logging
import os
import time
from collections.abc import Mapping
from typing import Any

import homeassistant.helpers.config_validation as cv
import requests
import voluptuous as vol
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from homeassistant import config_entries
from homeassistant.components.http import HomeAssistantView
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.core import callback
from homeassistant.data_entry_flow import section
from homeassistant.helpers.network import get_url

from .const import DOMAIN


class Cryptographer:
    """Cryptographer for encrypting tokens."""

    ITERATIONS = 1_200_000
    LEGACY_ITERATIONS = 100_000

    def __init__(self, username, password):
        """Initialize the cryptographer."""
        self._salt = os.urandom(16)
        self._iterations_options = [self.ITERATIONS]
        self._fernets = [
            Fernet(
                base64.urlsafe_b64encode(
                    PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=self._salt,
                        iterations=iterations,
                        backend=default_backend(),
                    ).derive(password.encode("utf-8"))
                )
            )
            for iterations in self._iterations_options
        ]
        self.fernet = MultiFernet(self._fernets)

    @property
    def salt(self):
        """Return the salt."""
        return base64.b64encode(self._salt).decode("utf-8")

    @property
    def iterations(self):
        """Return the iterations."""
        return self._iterations_options[0]

    def encrypt(self, value):
        """Encrypt a value."""
        return self.fernet.encrypt(value.encode("utf-8")).decode("utf-8")


AUTH_CALLBACK_NAME = "api:oauth_mail"
AUTH_CALLBACK_PATH = "/api/oauth_mail"

REQUEST_AUTHORIZATION_SCHEMA = vol.Schema(
    {
        vol.Required("code"): cv.string,
    }
)

CONFIG_SCHEMA = vol.Schema(
    {
        vol.Required("email"): vol.All(cv.string, vol.Strip),
        vol.Required("client_id"): vol.All(cv.string, vol.Strip),
        vol.Required("client_secret"): vol.All(cv.string, vol.Strip),
        vol.Required("password"): vol.All(cv.string, vol.Strip),
        vol.Optional("provider", default="outlook"): vol.In(["outlook", "gmail"]),
    }
)


class OAuthMailAuthCallbackView(HomeAssistantView):
    """OAuth Mail Authorization Callback View."""

    url = AUTH_CALLBACK_PATH
    name = AUTH_CALLBACK_NAME
    requires_auth = False

    def __init__(self, flow):
        """Initialize the callback view."""
        self.flow = flow

    async def get(self, request):
        """Handle the GET request."""
        code = request.query.get("code")
        if code:
            self.flow.auth_code = code
            return self.flow.async_show_progress_done(next_step_id="request_tokens")
        return "Authorization failed"


class OAuthMailConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """OAuth Mail config flow."""

    VERSION = 1

    def __init__(self):
        """Initialize the config flow."""
        self.auth_code = None
        self.user_input = {}
        self.callback_view = None

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        if user_input:
            self.user_input = user_input
            # Start OAuth flow
            return await self.async_step_authorize()

        return self.async_show_form(
            step_id="user",
            data_schema=CONFIG_SCHEMA,
            errors=errors,
        )

    async def async_step_authorize(self, user_input=None):
        """Handle the authorization step."""
        if user_input and user_input.get("code"):
            self.auth_code = user_input["code"]
            return await self.async_step_request_tokens()

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

        auth_url = f"{permission_url}?{'&'.join(f'{k}={requests.utils.quote(str(v))}' for k, v in params.items())}"

        return self.async_show_form(
            step_id="authorize",
            description_placeholders={"auth_url": auth_url},
            data_schema=REQUEST_AUTHORIZATION_SCHEMA,
        )

    async def async_step_request_tokens(self, user_input=None):
        """Handle requesting tokens."""
        provider = self.user_input["provider"]
        if provider == "outlook":
            token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        elif provider == "gmail":
            token_url = "https://oauth2.googleapis.com/token"

        redirect_uri = f"{get_url(self.hass)}{AUTH_CALLBACK_PATH}"

        data = {
            "client_id": self.user_input["client_id"],
            "client_secret": self.user_input["client_secret"],
            "code": self.auth_code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }

        response = await self.hass.async_add_executor_job(
            requests.post, token_url, data=data
        )

        if response.status_code == 200:
            tokens = response.json()
            # Encrypt and save tokens
            cryptographer = Cryptographer(self.user_input["email"], self.user_input["password"])
            config = configparser.ConfigParser(interpolation=None)
            config.add_section(self.user_input["email"])
            config.set(self.user_input["email"], "token_salt", cryptographer.salt)
            config.set(self.user_input["email"], "token_iterations", str(cryptographer.iterations))
            config.set(self.user_input["email"], "access_token", cryptographer.encrypt(tokens["access_token"]))
            if "refresh_token" in tokens:
                config.set(self.user_input["email"], "refresh_token", cryptographer.encrypt(tokens["refresh_token"]))
            config.set(self.user_input["email"], "access_token_expiry", str(int(tokens.get("expires_in", 3600)) + int(time.time())))
            config.set(self.user_input["email"], "last_activity", str(int(time.time())))

            # Write to /share/oauth-mail-tokens
            cache_file = "/share/oauth-mail-tokens"
            with open(cache_file, "w", encoding="utf-8") as f:
                config.write(f)

            # Also write account config for the proxy
            account_config_file = "/share/oauth-mail-accounts.ini"
            with open(account_config_file, "w", encoding="utf-8") as f:
                f.write(f"[{self.user_input['email']}]\n")
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
                title=self.user_input["email"],
                data=self.user_input,
            )
        else:
            return self.async_abort(reason="token_request_failed")

    @callback
    def async_remove(self):
        """Remove the callback view."""
        if self.callback_view:
            self.hass.http.unregister_view(self.callback_view)