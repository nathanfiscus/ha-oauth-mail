# OAuth Mail Integration

This Home Assistant integration provides OAuth authentication for email services and automatically configures the OAuth Mail Proxy addon with the account details and tokens.

## Installation

Copy the `custom_components/oauth_mail` folder to your Home Assistant's `custom_components` directory.

## Configuration

1. Install and start the OAuth Mail Proxy addon (no account configuration needed).
2. Install this integration.
3. Add a new OAuth Mail integration entry.
4. Enter your email, client_id, client_secret, password, and provider.
5. Follow the OAuth flow to authorize.
6. The integration will automatically configure the proxy with account details and encrypted tokens.

## How It Works

- The integration handles OAuth authentication and obtains tokens
- Account configuration and encrypted tokens are written to `/share` for the addon to use
- The addon automatically loads the configuration and tokens on startup
- No manual configuration of the proxy is required
