"""Configuration flow for OAuth Mail."""

import base64
import configparser
import functools as ft
import hashlib
import logging
import os
import time
import urllib.parse
from typing import Any

import homeassistant.helpers.config_validation as cv
import requests
import voluptuous as vol
from aiohttp import web_response
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
from homeassistant import config_entries
from homeassistant.components.http import HomeAssistantView
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.core import callback
from homeassistant.helpers.network import get_url

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

AUTH_CALLBACK_NAME = "api:oauth_mail"
AUTH_CALLBACK_PATH = "/api/oauth_mail"

# Default encryption password for tokens (must match what proxy expects)
DEFAULT_TOKEN_PASSWORD = "oauth_mail_default_password"
# Iteration count for PBKDF2 (matching email-oauth2-proxy default for new tokens)
TOKEN_ITERATIONS = 1_200_000


def _get_token_cipher(password: str, salt: bytes) -> Fernet:
    """Get Fernet cipher for token encryption/decryption using PBKDF2 key derivation.
    
    Matches the email-oauth2-proxy encryption method:
    https://github.com/simonrob/email-oauth2-proxy/blob/main/emailproxy.py#L677-L683
    """
    # Derive a key using PBKDF2-HMAC-SHA256
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=TOKEN_ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)


def _encrypt_token(token: str, password: str = None, salt: bytes = None) -> tuple:
    """Encrypt a token using Fernet with PBKDF2 key derivation.
    
    Returns: (encrypted_token, salt_b64, iterations)
    Where salt_b64 and iterations should be stored in config for later decryption.
    """
    try:
        if password is None:
            password = DEFAULT_TOKEN_PASSWORD
        if salt is None:
            salt = os.urandom(16)  # Generate random salt of 16 bytes
        
        cipher = _get_token_cipher(password, salt)
        encrypted = cipher.encrypt(token.encode())
        
        # Return encrypted token, base64-encoded salt, and iterations for config storage
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        _LOGGER.debug("Token encrypted successfully - salt length: %d bytes, iterations: %d", len(salt), TOKEN_ITERATIONS)
        return encrypted.decode(), salt_b64, TOKEN_ITERATIONS
    except Exception as err:
        _LOGGER.error("Failed to encrypt token: %s", err)
        return token, "", 0


def _decrypt_token(encrypted_token: str, password: str = None, salt_b64: str = "", iterations: int = 0) -> str:
    """Decrypt a token using Fernet with PBKDF2 key derivation."""
    try:
        if password is None:
            password = DEFAULT_TOKEN_PASSWORD
        if not salt_b64 or not iterations:
            _LOGGER.error("Cannot decrypt token - missing salt or iterations from config")
            return encrypted_token
        
        # Decode salt from base64
        salt = base64.b64decode(salt_b64.encode('utf-8'))
        
        # Temporarily use the stored iterations for decryption
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher = Fernet(key)
        
        decrypted = cipher.decrypt(encrypted_token.encode())
        _LOGGER.debug("Token decrypted successfully (length: %d -> %d)", len(encrypted_token), len(decrypted))
        return decrypted.decode()
    except Exception as err:
        _LOGGER.error("Failed to decrypt token: %s", err)
        return encrypted_token

def get_authorization_schema(auth_url):
    """Get the authorization schema with the auth URL."""
    return vol.Schema(
        {
            vol.Required("auth_url_display", default=auth_url): cv.string,
            vol.Required("url"): cv.string,
        }
    )

CONFIG_SCHEMA = vol.Schema(
    {
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

            # Save configuration with encrypted tokens
            config = configparser.ConfigParser(interpolation=None)
            config.add_section(self.user_input["entity_name"])
            
            # Encrypt access token (returns encrypted_token, salt_b64, iterations)
            access_token = tokens.get("access_token", "")
            encrypted_access_token, salt_b64, iterations = _encrypt_token(access_token)
            config.set(self.user_input["entity_name"], "access_token", encrypted_access_token)
            config.set(self.user_input["entity_name"], "token_salt", salt_b64)
            config.set(self.user_input["entity_name"], "token_iterations", str(iterations))
            
            # Encrypt refresh token if present (reuse same salt/iterations)
            if "refresh_token" in tokens:
                refresh_token = tokens["refresh_token"]
                # Use same salt and iterations approach as proxy expects
                kdf = PBKDF2(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=base64.b64decode(salt_b64),
                    iterations=iterations,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(DEFAULT_TOKEN_PASSWORD.encode()))
                cipher = Fernet(key)
                encrypted_refresh_token = cipher.encrypt(refresh_token.encode()).decode()
                config.set(self.user_input["entity_name"], "refresh_token", encrypted_refresh_token)
            
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
                f.write(f"[{entity_name}]\n")
                if self.user_input["provider"] == "outlook":
                    f.write("permission_url = https://login.microsoftonline.com/common/oauth2/v2.0/authorize\n")
                    f.write("token_url = https://login.microsoftonline.com/common/oauth2/v2.0/token\n")
                    f.write("oauth2_scope = https://outlook.office.com/IMAP.AccessAsUser.All offline_access openid profile email\n")
                elif self.user_input["provider"] == "gmail":
                    f.write("permission_url = https://accounts.google.com/o/oauth2/auth\n")
                    f.write("token_url = https://oauth2.googleapis.com/token\n")
                    f.write("oauth2_scope = https://mail.google.com/ https://www.googleapis.com/auth/userinfo.email\n")
                f.write(f"client_id = {self.user_input['client_id']}\n")
                f.write(f"client_secret = {self.user_input['client_secret']}\n")
                f.write("redirect_uri = http://localhost\n")
                f.write(f"token_encryption_password = {DEFAULT_TOKEN_PASSWORD}\n")

            return self.async_create_entry(
                title=entity_name,
                data=self.user_input,
            )
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error("Error creating entry: %s", err)
            return self.async_abort(reason="token_request_failed")