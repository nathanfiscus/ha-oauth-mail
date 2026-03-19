"""Configuration flow for OAuth Mail."""

import base64
import binascii
import configparser
import functools as ft
import logging
import os
import time
import urllib.parse
from typing import Any, Dict, Optional

import homeassistant.helpers.config_validation as cv
import requests
import voluptuous as vol
from aiohttp import web_response
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from homeassistant import config_entries
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import callback
from homeassistant.helpers.network import get_url

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

AUTH_CALLBACK_NAME = "api:oauth_mail"
AUTH_CALLBACK_PATH = "/api/oauth_mail"
ACCOUNT_CONFIG_FILE = "/share/oauth-mail-accounts.ini"
DEFAULT_PROXY_PASSWORD = "oauth_mail"


class Cryptographer:
    """Mirror email-oauth2-proxy token encryption behavior."""

    ITERATIONS = 1_200_000
    LEGACY_ITERATIONS = 100_000

    def __init__(self, config: configparser.ConfigParser, username: str, password: str) -> None:
        """Build a Fernet encryptor compatible with email-oauth2-proxy."""
        self._salt = None

        token_salt = config.get(username, "token_salt", fallback=None) if config.has_section(username) else None
        if token_salt:
            try:
                self._salt = base64.b64decode(token_salt.encode("utf-8"))
            except (binascii.Error, UnicodeError):
                _LOGGER.info(
                    "Invalid token_salt for account %s; generating a new token_salt",
                    username,
                )

        if not self._salt:
            self._salt = os.urandom(16)

        iterations = (
            config.getint(username, "token_iterations", fallback=self.LEGACY_ITERATIONS)
            if config.has_section(username)
            else self.LEGACY_ITERATIONS
        )
        self._iterations_options = sorted(
            {self.ITERATIONS, iterations, self.LEGACY_ITERATIONS},
            reverse=True,
        )
        self._fernets = [
            Fernet(
                base64.urlsafe_b64encode(
                    PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=self._salt,
                        iterations=iteration,
                        backend=default_backend(),
                    ).derive(password.encode("utf-8"))
                )
            )
            for iteration in self._iterations_options
        ]
        self.fernet = MultiFernet(self._fernets)

    @property
    def salt(self) -> str:
        """Return the current salt as base64 text."""
        return base64.b64encode(self._salt).decode("utf-8")

    @property
    def iterations(self) -> int:
        """Return the preferred iteration count for new secrets."""
        return self._iterations_options[0]

    def encrypt(self, value: str) -> str:
        """Encrypt a string value."""
        return self.fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def decrypt(self, value: str) -> str:
        """Decrypt a string value."""
        return self.fernet.decrypt(value.encode("utf-8")).decode("utf-8")

    def requires_rotation(self, value: str) -> bool:
        """Return whether an existing secret should be rotated to current settings."""
        try:
            self._fernets[0].decrypt(value.encode("utf-8"))
            return False
        except InvalidToken:
            try:
                self.decrypt(value)
                return True
            except InvalidToken:
                return False

    def rotate(self, value: str) -> str:
        """Rotate an encrypted value to the current preferred settings."""
        return self.fernet.rotate(value.encode("utf-8")).decode("utf-8")


def _write_proxy_account_config(
    entity_name: str,
    provider: str,
    client_id: str,
    client_secret: str,
    proxy_password: str,
    tokens: Dict[str, Any],
) -> None:
    """Persist proxy account details and encrypted tokens."""
    config = configparser.ConfigParser(interpolation=None)
    if os.path.exists(ACCOUNT_CONFIG_FILE):
        config.read(ACCOUNT_CONFIG_FILE, encoding="utf-8")

    if not config.has_section(entity_name):
        config.add_section(entity_name)

    cryptographer = Cryptographer(config, entity_name, proxy_password)
    access_token_expiry = str(int(tokens.get("expires_in", 3600)) + int(time.time()))
    last_activity = str(int(time.time()))

    if provider == "outlook":
        permission_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        oauth2_scope = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access openid profile email"
    else:
        permission_url = "https://accounts.google.com/o/oauth2/auth"
        token_url = "https://oauth2.googleapis.com/token"
        oauth2_scope = "https://mail.google.com/ https://www.googleapis.com/auth/userinfo.email"

    config.set(entity_name, "permission_url", permission_url)
    config.set(entity_name, "token_url", token_url)
    config.set(entity_name, "oauth2_scope", oauth2_scope)
    config.set(entity_name, "redirect_uri", "http://localhost")
    config.set(entity_name, "client_id", client_id)
    config.set(entity_name, "client_secret", client_secret)
    config.set(entity_name, "token_salt", cryptographer.salt)
    config.set(entity_name, "token_iterations", str(cryptographer.iterations))
    config.set(entity_name, "access_token", cryptographer.encrypt(tokens.get("access_token", "")))
    config.set(entity_name, "access_token_expiry", access_token_expiry)
    config.set(entity_name, "last_activity", last_activity)

    if "refresh_token" in tokens:
        config.set(entity_name, "refresh_token", cryptographer.encrypt(tokens["refresh_token"]))
    else:
        config.remove_option(entity_name, "refresh_token")

    with open(ACCOUNT_CONFIG_FILE, "w", encoding="utf-8") as config_file:
        config.write(config_file)


def get_authorization_schema(auth_url):
    """Get the authorization schema with the auth URL."""
    return vol.Schema(
        {
            vol.Required("auth_url_display", default=auth_url): cv.string,
            vol.Required("url"): cv.string,
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

    def _get_saved_proxy_password(self) -> Optional[str]:
        """Return the stored proxy password from an existing entry, if available."""
        for entry in self._async_current_entries():
            proxy_password = entry.data.get("proxy_password")
            if proxy_password:
                return proxy_password
        return None

    def _needs_proxy_password(self) -> bool:
        """Return whether the user must provide the proxy password in the UI."""
        return self._get_saved_proxy_password() is None

    def _get_user_schema(self) -> vol.Schema:
        """Return the schema for the first step, including proxy password only when needed."""
        schema: Dict[Any, Any] = {
            vol.Required("client_id"): vol.All(cv.string, vol.Strip),
            vol.Required("client_secret"): vol.All(cv.string, vol.Strip),
        }
        if self._needs_proxy_password():
            schema[vol.Required("proxy_password")] = vol.All(cv.string, vol.Strip, vol.Length(min=1))
        schema[vol.Optional("provider", default="outlook")] = vol.In(["outlook", "gmail"])
        return vol.Schema(schema)

    def _get_user_description_placeholders(self) -> Dict[str, str]:
        """Return user step placeholders describing proxy password use when required."""
        if not self._needs_proxy_password():
            return {"proxy_password_help": ""}

        return {
            "proxy_password_help": (
                "\n\nSet the local proxy password for the first account. This is not your mailbox password. "
                "Use this same password in your email client when it connects to the proxy. "
                "You only need to enter it once; later accounts will reuse it automatically."
            )
        }

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        if user_input:
            self.user_input = user_input
            return await self.async_step_authorize()

        return self.async_show_form(
            step_id="user",
            data_schema=self._get_user_schema(),
            description_placeholders=self._get_user_description_placeholders(),
            errors=errors,
        )

    async def async_step_authorize(self, user_input=None):
        """Handle the authorization step."""
        errors = {}

        provider = self.user_input["provider"]
        if provider == "outlook":
            permission_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
            scope = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access openid profile email"
        elif provider == "gmail":
            permission_url = "https://accounts.google.com/o/oauth2/auth"
            scope = "https://mail.google.com/ https://www.googleapis.com/auth/userinfo.email"
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

        # Register callback view if not already registered
        if not self.callback_view:
            self.callback_view = OAuthMailAuthCallbackView()
            self.hass.http.register_view(self.callback_view)

        if user_input is not None:
            errors = await self._async_validate_response(user_input)
            if not errors:
                return await self._async_create_entry()

        return self.async_show_form(
            step_id="authorize",
            description_placeholders={
                "auth_url": self._auth_url,
                "failed_permissions": self._get_failed_permissions(),
            },
            data_schema=get_authorization_schema(self._auth_url),
            errors=errors,
            last_step=False,
        )

    def _get_failed_permissions(self):
        """Get failed permissions string."""
        # For now, return empty string since OAuth Mail doesn't check specific permissions
        # This can be expanded later if permission checking is added
        return ""

    async def _async_validate_response(self, user_input):
        """Validate the authorization response."""
        errors = {}
        url = user_input.get("url", "")

        _LOGGER.debug("Validating authorization response URL: %s", url)

        if not url:
            errors["url"] = "invalid_url"
            return errors

        if "code=" not in url:
            _LOGGER.error("No authorization code found in URL: %s", url)
            errors["url"] = "invalid_url"
            return errors

        # Extract the authorization code from the URL
        try:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Check for state parameter
            state = query_params.get("state", [None])[0]
            if state != "oauth_mail":
                _LOGGER.error("Invalid state parameter: %s", state)
                errors["url"] = "invalid_url"
                return errors
            
            if "code" in query_params:
                code = query_params["code"][0]
                # URL decode the authorization code
                code = urllib.parse.unquote(code)
                _LOGGER.debug("Extracted authorization code: %s...", code[:10] if code else "None")
            else:
                _LOGGER.error("No 'code' parameter found in URL query: %s", parsed_url.query)
                errors["url"] = "invalid_url"
                return errors

            if not code:
                _LOGGER.error("Authorization code is empty")
                errors["url"] = "invalid_url"
                return errors

            self.user_input["auth_code"] = code
            _LOGGER.debug("Successfully stored authorization code")
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error("Error extracting code from URL: %s", err)
            errors["url"] = "invalid_url"
            return errors

        return errors

    async def _async_create_entry(self):
        """Create the config entry."""
        try:
            # Validate that we have an authorization code
            auth_code = self.user_input.get("auth_code")
            if not auth_code:
                _LOGGER.error("No authorization code available for token exchange")
                return self.async_abort(reason="token_request_failed")

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
                "code": auth_code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            }

            _LOGGER.debug("Token request data: %s", {k: v[:10] + "..." if len(str(v)) > 10 else v for k, v in data.items()})

            response = await self.hass.async_add_executor_job(
                ft.partial(requests.post, token_url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
            )

            _LOGGER.debug("Token response status: %s", response.status_code)
            _LOGGER.debug("Token response headers: %s", dict(response.headers))

            if response.status_code != 200:
                _LOGGER.error("Token request failed: %s", response.text)
                _LOGGER.error("Request URL: %s", token_url)
                _LOGGER.error("Request data keys: %s", list(data.keys()))
                return self.async_abort(reason="token_request_failed")

            tokens = response.json()

            # Get user email from token response or userinfo endpoint
            user_email = None
            if provider == "outlook":
                # For Outlook, we can get email from the id_token or userinfo
                if "id_token" in tokens:
                    import jwt
                    id_token = tokens["id_token"]
                    decoded = jwt.decode(id_token, options={"verify_signature": False})
                    _LOGGER.debug("Decoded id_token claims: %s", {k: v for k, v in decoded.items() if k not in ["aud", "iss", "sub"]})
                    user_email = decoded.get("email") or decoded.get("preferred_username")
                if not user_email:
                    # Fallback to userinfo endpoint
                    userinfo_url = "https://graph.microsoft.com/v1.0/me"
                    userinfo_response = await self.hass.async_add_executor_job(
                        ft.partial(requests.get, userinfo_url, headers={"Authorization": f"Bearer {tokens['access_token']}"})
                    )
                    _LOGGER.debug("Outlook userinfo response status: %s", userinfo_response.status_code)
                    if userinfo_response.status_code == 200:
                        userinfo = userinfo_response.json()
                        _LOGGER.debug("Outlook userinfo keys: %s", list(userinfo.keys()))
                        user_email = userinfo.get("mail") or userinfo.get("userPrincipalName")
                    else:
                        _LOGGER.error("Failed to get Outlook userinfo: %s", userinfo_response.text[:200])
            elif provider == "gmail":
                # For Gmail, get email from userinfo endpoint
                userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
                userinfo_response = await self.hass.async_add_executor_job(
                    ft.partial(requests.get, userinfo_url, headers={"Authorization": f"Bearer {tokens['access_token']}"})
                )
                _LOGGER.debug("Gmail userinfo response status: %s", userinfo_response.status_code)
                if userinfo_response.status_code == 200:
                    userinfo = userinfo_response.json()
                    _LOGGER.debug("Gmail userinfo keys: %s", list(userinfo.keys()))
                    user_email = userinfo.get("email")
                else:
                    _LOGGER.error("Failed to get Gmail userinfo: %s", userinfo_response.text[:200])

            if not user_email:
                _LOGGER.error("Could not retrieve user email from OAuth provider")
                return self.async_abort(reason="token_request_failed")

            # Use email as entity_name
            entity_name = user_email
            self.user_input["entity_name"] = entity_name

            proxy_password = (
                self.user_input.get("proxy_password")
                or self._get_saved_proxy_password()
                or DEFAULT_PROXY_PASSWORD
            )

            _write_proxy_account_config(
                entity_name=entity_name,
                provider=self.user_input["provider"],
                client_id=self.user_input["client_id"],
                client_secret=self.user_input["client_secret"],
                proxy_password=proxy_password,
                tokens=tokens,
            )

            entry_data = {
                key: value
                for key, value in self.user_input.items()
                if key != "auth_code"
            }
            if self.user_input.get("proxy_password"):
                entry_data["proxy_password"] = self.user_input["proxy_password"]

            return self.async_create_entry(
                title=entity_name,
                data=entry_data,
            )
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error("Error creating entry: %s", err)
            return self.async_abort(reason="token_request_failed")