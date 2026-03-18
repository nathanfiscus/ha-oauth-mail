"""Test constants."""

ENTITY_NAME = "test_account"
CLIENT_ID = "test_client_id"
CLIENT_SECRET = "test_client_secret"

BASE_CONFIG_ENTRY = {
    "entity_name": ENTITY_NAME,
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "provider": "outlook",
}

AUTH_URL_BASE = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

MOCK_TOKEN_RESPONSE = {
    "access_token": "mock_access_token",
    "refresh_token": "mock_refresh_token",
    "expires_in": 3600,
    "token_type": "Bearer",
}