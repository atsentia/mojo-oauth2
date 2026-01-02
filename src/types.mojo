"""
OAuth 2.0 Core Types

Defines the fundamental data structures for OAuth 2.0 flows.
"""


# =============================================================================
# Grant Types
# =============================================================================

struct GrantType:
    """OAuth 2.0 grant types."""
    alias AUTHORIZATION_CODE = "authorization_code"
    alias CLIENT_CREDENTIALS = "client_credentials"
    alias REFRESH_TOKEN = "refresh_token"
    alias PASSWORD = "password"  # Legacy, not recommended
    alias DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"


# =============================================================================
# Response Types
# =============================================================================

struct ResponseType:
    """OAuth 2.0 response types for authorization endpoint."""
    alias CODE = "code"
    alias TOKEN = "token"  # Implicit flow, deprecated


# =============================================================================
# Token Response
# =============================================================================

struct TokenResponse:
    """
    OAuth 2.0 token response.

    Contains access token, refresh token, and metadata.
    """
    var access_token: String
    var token_type: String
    var expires_in: Int
    var refresh_token: String
    var scope: String
    var id_token: String  # For OIDC
    var issued_at: Int    # Unix timestamp

    fn __init__(out self):
        self.access_token = ""
        self.token_type = "Bearer"
        self.expires_in = 3600
        self.refresh_token = ""
        self.scope = ""
        self.id_token = ""
        self.issued_at = 0

    fn __init__(
        out self,
        access_token: String,
        token_type: String = "Bearer",
        expires_in: Int = 3600,
        refresh_token: String = "",
        scope: String = "",
        id_token: String = "",
    ):
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token
        self.scope = scope
        self.id_token = id_token
        self.issued_at = 0  # Set by caller

    fn is_expired(self, current_time: Int) -> Bool:
        """Check if token has expired."""
        if self.expires_in <= 0:
            return False  # No expiry
        return current_time >= (self.issued_at + self.expires_in)

    fn has_refresh_token(self) -> Bool:
        """Check if refresh token is available."""
        return len(self.refresh_token) > 0

    fn authorization_header(self) -> String:
        """Get Authorization header value."""
        return self.token_type + " " + self.access_token


# =============================================================================
# OAuth Error
# =============================================================================

struct OAuthError:
    """
    OAuth 2.0 error response.

    Standard error codes from RFC 6749.
    """
    var error: String
    var error_description: String
    var error_uri: String

    # Standard error codes
    alias INVALID_REQUEST = "invalid_request"
    alias INVALID_CLIENT = "invalid_client"
    alias INVALID_GRANT = "invalid_grant"
    alias UNAUTHORIZED_CLIENT = "unauthorized_client"
    alias UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    alias INVALID_SCOPE = "invalid_scope"
    alias ACCESS_DENIED = "access_denied"
    alias EXPIRED_TOKEN = "expired_token"
    alias INVALID_TOKEN = "invalid_token"

    fn __init__(out self, error: String, description: String = ""):
        self.error = error
        self.error_description = description
        self.error_uri = ""

    fn __str__(self) -> String:
        if len(self.error_description) > 0:
            return self.error + ": " + self.error_description
        return self.error


# =============================================================================
# Authorization Request
# =============================================================================

struct AuthorizationRequest:
    """
    OAuth 2.0 authorization request parameters.

    Used to build the authorization URL for the authorization code flow.
    """
    var client_id: String
    var redirect_uri: String
    var scope: String
    var state: String
    var response_type: String
    var code_challenge: String        # PKCE
    var code_challenge_method: String  # PKCE (S256 or plain)
    var nonce: String                  # OIDC
    var prompt: String                 # none, login, consent, select_account
    var login_hint: String
    var extra_params: Dict[String, String]

    fn __init__(
        out self,
        client_id: String,
        redirect_uri: String,
        scope: String = "",
        state: String = "",
    ):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.state = state
        self.response_type = ResponseType.CODE
        self.code_challenge = ""
        self.code_challenge_method = ""
        self.nonce = ""
        self.prompt = ""
        self.login_hint = ""
        self.extra_params = Dict[String, String]()

    fn with_pkce(inout self, code_challenge: String, method: String = "S256"):
        """Add PKCE parameters."""
        self.code_challenge = code_challenge
        self.code_challenge_method = method

    fn with_nonce(inout self, nonce: String):
        """Add OIDC nonce."""
        self.nonce = nonce

    fn with_prompt(inout self, prompt: String):
        """Set prompt parameter."""
        self.prompt = prompt

    fn with_login_hint(inout self, hint: String):
        """Set login_hint parameter."""
        self.login_hint = hint

    fn add_param(inout self, key: String, value: String):
        """Add extra parameter."""
        self.extra_params[key] = value


# =============================================================================
# Token Request
# =============================================================================

struct TokenRequest:
    """
    OAuth 2.0 token request parameters.

    Used for exchanging authorization code or refreshing tokens.
    """
    var grant_type: String
    var client_id: String
    var client_secret: String
    var code: String           # For authorization_code grant
    var redirect_uri: String   # For authorization_code grant
    var code_verifier: String  # PKCE
    var refresh_token: String  # For refresh_token grant
    var scope: String
    var username: String       # For password grant (deprecated)
    var password: String       # For password grant (deprecated)

    fn __init__(out self, grant_type: String, client_id: String):
        self.grant_type = grant_type
        self.client_id = client_id
        self.client_secret = ""
        self.code = ""
        self.redirect_uri = ""
        self.code_verifier = ""
        self.refresh_token = ""
        self.scope = ""
        self.username = ""
        self.password = ""

    @staticmethod
    fn authorization_code(
        client_id: String,
        code: String,
        redirect_uri: String,
        code_verifier: String = "",
    ) -> TokenRequest:
        """Create token request for authorization code exchange."""
        var req = TokenRequest(GrantType.AUTHORIZATION_CODE, client_id)
        req.code = code
        req.redirect_uri = redirect_uri
        req.code_verifier = code_verifier
        return req

    @staticmethod
    fn client_credentials(
        client_id: String,
        client_secret: String,
        scope: String = "",
    ) -> TokenRequest:
        """Create token request for client credentials grant."""
        var req = TokenRequest(GrantType.CLIENT_CREDENTIALS, client_id)
        req.client_secret = client_secret
        req.scope = scope
        return req

    @staticmethod
    fn refresh(
        client_id: String,
        refresh_token: String,
        scope: String = "",
    ) -> TokenRequest:
        """Create token request for refresh token grant."""
        var req = TokenRequest(GrantType.REFRESH_TOKEN, client_id)
        req.refresh_token = refresh_token
        req.scope = scope
        return req
