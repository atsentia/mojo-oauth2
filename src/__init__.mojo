"""
mojo-oauth2

Pure Mojo OAuth 2.0 client library with PKCE support.

Supports all major OAuth 2.0 grant types:
- Authorization Code (with PKCE)
- Client Credentials
- Refresh Token

Pre-configured providers:
- Google (OIDC)
- GitHub
- Microsoft (Azure AD)
- Apple Sign In
- Auth0
- Okta
- Keycloak
- Custom

Usage (Authorization Code with PKCE):
    from mojo_oauth2 import OAuth2Client, Providers, PKCE, generate_state

    # Create client for Google
    var client = OAuth2Client(
        Providers.google(),
        client_id="your-client-id",
        redirect_uri="http://localhost:8080/callback"
    )

    # Generate authorization URL with PKCE
    var pkce = PKCE.generate()
    var state = generate_state()
    var auth_url = client.authorization_url(
        scope="openid email profile",
        state=state,
        code_challenge=pkce.code_challenge
    )
    print("Visit: " + auth_url)

    # After callback, exchange code for tokens
    var token = client.exchange_code(
        code=callback_code,
        code_verifier=pkce.code_verifier
    )
    print("Access Token: " + token.access_token)

Usage (Client Credentials):
    var client = OAuth2Client(
        Providers.custom("my-api", auth_url, token_url),
        client_id="...",
        client_secret="..."
    )
    var token = client.client_credentials(scope="read write")
    print("Token: " + token.access_token)
"""

# Core types
from .types import (
    GrantType,
    ResponseType,
    TokenResponse,
    TokenRequest,
    AuthorizationRequest,
    OAuthError,
)

# PKCE support
from .pkce import (
    PKCE,
    generate_state,
    generate_nonce,
)

# Provider configuration
from .provider import (
    OAuthProvider,
    Providers,
)

# OAuth client
from .client import (
    OAuth2Client,
    CallbackHandler,
)
