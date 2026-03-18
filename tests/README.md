# Testing

This directory contains tests for the OAuth Mail integration.

## Running Tests

1. Install test dependencies:

   ```bash
   pip install -r requirements-test.txt
   ```

2. Run tests:

   ```bash
   pytest
   ```

3. Run tests with coverage:
   ```bash
   pytest --cov=custom_components.oauth_mail
   ```

## Test Structure

- `conftest.py` - Global test fixtures and configuration
- `test_config_flow.py` - Tests for the configuration flow
- `test_init.py` - Tests for component initialization
- `const.py` - Test constants and mock data

## Test Coverage

The tests cover:

- Config flow user input validation
- OAuth URL generation
- Token exchange process
- Error handling for invalid inputs
- Different email providers (Outlook/Gmail)
- Duplicate entity name detection
