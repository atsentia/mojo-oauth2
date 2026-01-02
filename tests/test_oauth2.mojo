"""
Tests for mojo-oauth2 library.
"""

from testing import assert_equal, assert_true, assert_false

from mojo_oauth2 import (
    OAuth2Client,
    Providers,
    PKCE,
    generate_state,
    generate_nonce,
    TokenResponse,
    OAuthError,
    CallbackHandler,
)


fn test_pkce_generation():
    """Test PKCE code verifier and challenge generation."""
    var pkce = PKCE.generate()

    # Verifier should be 64 characters
    assert_equal(len(pkce.code_verifier), 64)

    # Challenge should be base64url encoded (43 chars for SHA256)
    assert_equal(len(pkce.code_challenge), 43)

    # Method should be S256
    assert_equal(pkce.method, "S256")

    print("  [PASS] test_pkce_generation")


fn test_pkce_plain():
    """Test PKCE with plain method."""
    var pkce = PKCE.generate("plain")

    # With plain, challenge equals verifier
    assert_equal(pkce.code_challenge, pkce.code_verifier)
    assert_equal(pkce.method, "plain")

    print("  [PASS] test_pkce_plain")


fn test_state_generation():
    """Test state parameter generation."""
    var state1 = generate_state()
    var state2 = generate_state()

    # Should be 32 characters
    assert_equal(len(state1), 32)
    assert_equal(len(state2), 32)

    # Should be random (different)
    assert_true(state1 != state2)

    print("  [PASS] test_state_generation")


fn test_nonce_generation():
    """Test nonce generation for OIDC."""
    var nonce = generate_nonce()
    assert_equal(len(nonce), 32)
    print("  [PASS] test_nonce_generation")


fn test_google_provider():
    """Test Google provider configuration."""
    var google = Providers.google()

    assert_equal(google.name, "google")
    assert_true("accounts.google.com" in google.authorization_endpoint)
    assert_true("googleapis.com/token" in google.token_endpoint)
    assert_true(len(google.userinfo_endpoint) > 0)
    assert_true(len(google.jwks_uri) > 0)

    print("  [PASS] test_google_provider")


fn test_github_provider():
    """Test GitHub provider configuration."""
    var github = Providers.github()

    assert_equal(github.name, "github")
    assert_true("github.com/login/oauth/authorize" in github.authorization_endpoint)
    assert_true("github.com/login/oauth/access_token" in github.token_endpoint)

    print("  [PASS] test_github_provider")


fn test_custom_provider():
    """Test custom provider creation."""
    var provider = Providers.custom(
        "my-provider",
        "https://auth.example.com/authorize",
        "https://auth.example.com/token"
    )

    assert_equal(provider.name, "my-provider")
    assert_equal(provider.authorization_endpoint, "https://auth.example.com/authorize")
    assert_equal(provider.token_endpoint, "https://auth.example.com/token")

    print("  [PASS] test_custom_provider")


fn test_oauth_client_authorization_url():
    """Test OAuth client authorization URL generation."""
    var client = OAuth2Client(
        Providers.google(),
        client_id="test-client-id",
        redirect_uri="http://localhost:8080/callback"
    )

    var url = client.authorization_url(
        scope="openid email",
        state="test-state",
        code_challenge="test-challenge"
    )

    assert_true("accounts.google.com" in url)
    assert_true("response_type=code" in url)
    assert_true("client_id=test-client-id" in url)
    assert_true("redirect_uri=" in url)
    assert_true("scope=" in url)
    assert_true("state=test-state" in url)
    assert_true("code_challenge=test-challenge" in url)

    print("  [PASS] test_oauth_client_authorization_url")


fn test_token_response():
    """Test TokenResponse struct."""
    var token = TokenResponse(
        access_token="abc123",
        token_type="Bearer",
        expires_in=3600,
        refresh_token="refresh123"
    )

    assert_equal(token.access_token, "abc123")
    assert_equal(token.token_type, "Bearer")
    assert_equal(token.expires_in, 3600)
    assert_true(token.has_refresh_token())
    assert_equal(token.authorization_header(), "Bearer abc123")

    print("  [PASS] test_token_response")


fn test_token_expiry():
    """Test token expiry checking."""
    var token = TokenResponse(access_token="abc", expires_in=3600)
    token.issued_at = 1000

    # Not expired at issue time
    assert_false(token.is_expired(1000))

    # Not expired before expiry
    assert_false(token.is_expired(4500))

    # Expired after expiry
    assert_true(token.is_expired(5000))

    print("  [PASS] test_token_expiry")


fn test_oauth_error():
    """Test OAuthError struct."""
    var error = OAuthError(
        OAuthError.INVALID_GRANT,
        "The authorization code has expired"
    )

    assert_equal(error.error, "invalid_grant")
    assert_true("expired" in str(error))

    print("  [PASS] test_oauth_error")


fn test_callback_handler_success():
    """Test callback handler with successful callback."""
    var handler = CallbackHandler("code=abc123&state=xyz789")

    assert_true(handler.is_success())
    assert_false(handler.is_error())
    assert_equal(handler.code, "abc123")
    assert_equal(handler.state, "xyz789")
    assert_true(handler.validate_state("xyz789"))
    assert_false(handler.validate_state("wrong"))

    print("  [PASS] test_callback_handler_success")


fn test_callback_handler_error():
    """Test callback handler with error callback."""
    var handler = CallbackHandler("error=access_denied&error_description=User+denied")

    assert_false(handler.is_success())
    assert_true(handler.is_error())
    assert_equal(handler.error, "access_denied")

    var err = handler.get_error()
    assert_equal(err.error, "access_denied")

    print("  [PASS] test_callback_handler_error")


fn test_okta_provider():
    """Test Okta provider with custom domain."""
    var okta = Providers.okta("dev-123456.okta.com")

    assert_equal(okta.name, "okta")
    assert_true("dev-123456.okta.com" in okta.authorization_endpoint)
    assert_true("dev-123456.okta.com" in okta.token_endpoint)

    print("  [PASS] test_okta_provider")


fn test_auth0_provider():
    """Test Auth0 provider with custom domain."""
    var auth0 = Providers.auth0("myapp.auth0.com")

    assert_equal(auth0.name, "auth0")
    assert_true("myapp.auth0.com" in okta.authorization_endpoint)

    print("  [PASS] test_auth0_provider")


fn main():
    """Run all tests."""
    print("Running mojo-oauth2 tests...")
    print()

    # PKCE tests
    test_pkce_generation()
    test_pkce_plain()
    test_state_generation()
    test_nonce_generation()

    # Provider tests
    test_google_provider()
    test_github_provider()
    test_custom_provider()
    test_okta_provider()

    # Client tests
    test_oauth_client_authorization_url()

    # Token tests
    test_token_response()
    test_token_expiry()
    test_oauth_error()

    # Callback tests
    test_callback_handler_success()
    test_callback_handler_error()

    print()
    print("All tests passed!")
