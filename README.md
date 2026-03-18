# OAuth Mail Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)

This Home Assistant integration provides OAuth authentication for email services and automatically configures the OAuth Mail Proxy addon with the account details and tokens.

## Installation

### Recommended: Using HACS

Click the button below to open the integration in HACS:

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=nathanfiscus&repository=ha-oauth-mail&category=integration)

Alternatively, you can:

1. Open HACS in Home Assistant
2. Click "Integrations"
3. Search for "OAuth Mail Integration"
4. Click "Install"

### Manual Installation

1. Download the `custom_components/oauth_mail` folder from the [latest release](https://github.com/nathanfiscus/ha-oauth-mail/releases)
2. Copy it to your Home Assistant's `custom_components` directory
3. Restart Home Assistant

## Configuration

### Add the Integration

Click the button below to quickly add the OAuth Mail integration to Home Assistant:

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=oauth_mail)

### Setup Steps

### Setup Steps

1. Install OAuth Mail Proxy Addon
2. Click the button above or add the integration manually in Home Assistant.
3. Enter your email, client_id, client_secret, password, and provider.
4. Follow the OAuth flow to authorize.
5. The integration will automatically configure the proxy with account details and encrypted tokens.
6. Start OAuth Mail Proxy Addon

## How It Works

- The integration handles OAuth authentication and obtains tokens
- Account configuration and encrypted tokens are written to `/share` for the addon to use
- The addon automatically loads the configuration and tokens on startup
- No manual configuration of the proxy is required
