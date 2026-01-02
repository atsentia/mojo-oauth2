"""
OAuth 2.0 Client Implementation

Pure Mojo OAuth 2.0 client with support for all major grant types.
"""

from .types import (
    TokenResponse, TokenRequest, AuthorizationRequest, OAuthError,
    GrantType, ResponseType,
)
from .provider import OAuthProvider
from .pkce import PKCE, generate_state, generate_nonce


# =============================================================================
# OAuth2 Client
# =============================================================================

struct OAuth2Client:
    """
    OAuth 2.0 Client.

    Supports authorization code flow (with PKCE), client credentials,
    and token refresh.

    Usage (Authorization Code Flow with PKCE):
        var client = OAuth2Client(
            Providers.google(),
            client_id="your-client-id",
            redirect_uri="http://localhost:8080/callback"
        )

        # Generate authorization URL
        var pkce = PKCE.generate()
        var state = generate_state()
        var auth_url = client.authorization_url(
            scope="openid email profile",
            state=state,
            code_challenge=pkce.code_challenge
        )
        # Redirect user to auth_url...

        # After callback, exchange code for token
        var token = client.exchange_code(code, pkce.code_verifier)

    Usage (Client Credentials):
        var client = OAuth2Client(
            provider,
            client_id="...",
            client_secret="..."
        )
        var token = client.client_credentials(scope="read write")
    """
    var provider: OAuthProvider
    var client_id: String
    var client_secret: String
    var redirect_uri: String
    var token: TokenResponse
    var use_pkce: Bool

    fn __init__(
        out self,
        provider: OAuthProvider,
        client_id: String,
        client_secret: String = "",
        redirect_uri: String = "",
    ):
        self.provider = provider
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.token = TokenResponse()
        self.use_pkce = True

    # =========================================================================
    # Authorization Code Flow
    # =========================================================================

    fn authorization_url(
        self,
        scope: String = "",
        state: String = "",
        code_challenge: String = "",
        code_challenge_method: String = "S256",
        nonce: String = "",
    ) -> String:
        """
        Build the authorization URL for the authorization code flow.

        Args:
            scope: Space-separated scopes to request
            state: Random state for CSRF protection
            code_challenge: PKCE code challenge
            code_challenge_method: "S256" or "plain"
            nonce: OIDC nonce

        Returns:
            Full authorization URL to redirect user to
        """
        var url = self.provider.authorization_endpoint + "?"
        url += "response_type=" + ResponseType.CODE
        url += "&client_id=" + _url_encode(self.client_id)

        if len(self.redirect_uri) > 0:
            url += "&redirect_uri=" + _url_encode(self.redirect_uri)

        if len(scope) > 0:
            url += "&scope=" + _url_encode(scope)

        if len(state) > 0:
            url += "&state=" + _url_encode(state)

        if len(code_challenge) > 0:
            url += "&code_challenge=" + _url_encode(code_challenge)
            url += "&code_challenge_method=" + code_challenge_method

        if len(nonce) > 0:
            url += "&nonce=" + _url_encode(nonce)

        return url

    fn build_auth_request(
        self,
        scope: String = "",
    ) -> Tuple[String, PKCE, String]:
        """
        Build authorization request with auto-generated PKCE and state.

        Returns:
            Tuple of (authorization_url, pkce, state)
        """
        var pkce = PKCE.generate()
        var state = generate_state()
        var url = self.authorization_url(
            scope=scope,
            state=state,
            code_challenge=pkce.code_challenge,
        )
        return (url, pkce, state)

    fn exchange_code(
        self,
        code: String,
        code_verifier: String = "",
    ) raises -> TokenResponse:
        """
        Exchange authorization code for tokens.

        Args:
            code: Authorization code from callback
            code_verifier: PKCE code verifier (if used)

        Returns:
            TokenResponse with access_token, refresh_token, etc.
        """
        var req = TokenRequest.authorization_code(
            self.client_id,
            code,
            self.redirect_uri,
            code_verifier,
        )
        req.client_secret = self.client_secret

        return self._execute_token_request(req)

    # =========================================================================
    # Client Credentials Flow
    # =========================================================================

    fn client_credentials(self, scope: String = "") raises -> TokenResponse:
        """
        Obtain token using client credentials grant.

        Used for machine-to-machine authentication.

        Args:
            scope: Space-separated scopes to request

        Returns:
            TokenResponse with access_token
        """
        if len(self.client_secret) == 0:
            raise Error("Client credentials flow requires client_secret")

        var req = TokenRequest.client_credentials(
            self.client_id,
            self.client_secret,
            scope,
        )

        return self._execute_token_request(req)

    # =========================================================================
    # Token Refresh
    # =========================================================================

    fn refresh_token(self, refresh_token: String, scope: String = "") raises -> TokenResponse:
        """
        Refresh an access token using a refresh token.

        Args:
            refresh_token: The refresh token
            scope: Optional new scope (defaults to original)

        Returns:
            New TokenResponse
        """
        var req = TokenRequest.refresh(self.client_id, refresh_token, scope)
        req.client_secret = self.client_secret

        return self._execute_token_request(req)

    fn refresh(inout self, scope: String = "") raises -> TokenResponse:
        """Refresh using the stored token's refresh token."""
        if not self.token.has_refresh_token():
            raise Error("No refresh token available")

        self.token = self.refresh_token(self.token.refresh_token, scope)
        return self.token

    # =========================================================================
    # Token Validation
    # =========================================================================

    fn is_authenticated(self) -> Bool:
        """Check if client has a valid (non-empty) access token."""
        return len(self.token.access_token) > 0

    fn is_token_expired(self, current_time: Int) -> Bool:
        """Check if the current token has expired."""
        return self.token.is_expired(current_time)

    fn get_authorization_header(self) -> String:
        """Get Authorization header value for API requests."""
        return self.token.authorization_header()

    # =========================================================================
    # Internal Methods
    # =========================================================================

    fn _execute_token_request(self, req: TokenRequest) raises -> TokenResponse:
        """
        Execute a token request.

        Note: This is a placeholder. In production, this would use
        mojo-http to make the actual HTTP POST request.
        """
        # Build form data
        var form_data = "grant_type=" + _url_encode(req.grant_type)
        form_data += "&client_id=" + _url_encode(req.client_id)

        if len(req.client_secret) > 0:
            form_data += "&client_secret=" + _url_encode(req.client_secret)

        if len(req.code) > 0:
            form_data += "&code=" + _url_encode(req.code)

        if len(req.redirect_uri) > 0:
            form_data += "&redirect_uri=" + _url_encode(req.redirect_uri)

        if len(req.code_verifier) > 0:
            form_data += "&code_verifier=" + _url_encode(req.code_verifier)

        if len(req.refresh_token) > 0:
            form_data += "&refresh_token=" + _url_encode(req.refresh_token)

        if len(req.scope) > 0:
            form_data += "&scope=" + _url_encode(req.scope)

        # In production: Use mojo-http to POST to token_endpoint
        # var response = http_client.post(
        #     self.provider.token_endpoint,
        #     body=form_data,
        #     headers={"Content-Type": "application/x-www-form-urlencoded"}
        # )
        # return _parse_token_response(response.body)

        # Placeholder return
        raise Error("Token request requires mojo-http integration. Form data: " + form_data)


# =============================================================================
# URL Encoding
# =============================================================================

fn _url_encode(value: String) -> String:
    """URL encode a string (percent encoding)."""
    alias SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

    var result = String()
    for i in range(len(value)):
        var c = value[i]
        if c in SAFE:
            result += c
        elif c == " ":
            result += "+"
        else:
            # Percent encode
            var byte = UInt8(ord(c))
            result += "%" + _hex_char(byte >> 4) + _hex_char(byte & 0x0F)

    return result


fn _hex_char(nibble: UInt8) -> String:
    """Convert nibble (0-15) to hex character."""
    alias HEX = "0123456789ABCDEF"
    return HEX[Int(nibble)]


# =============================================================================
# Callback Handler
# =============================================================================

struct CallbackHandler:
    """
    Helper for handling OAuth callbacks.

    Parses callback URL query parameters and validates state.
    """
    var code: String
    var state: String
    var error: String
    var error_description: String

    fn __init__(out self, query_string: String):
        """Parse callback query string."""
        self.code = ""
        self.state = ""
        self.error = ""
        self.error_description = ""

        var params = query_string.split("&")
        for param in params:
            var parts = param[].split("=")
            if len(parts) == 2:
                var key = parts[0]
                var value = _url_decode(parts[1])

                if key == "code":
                    self.code = value
                elif key == "state":
                    self.state = value
                elif key == "error":
                    self.error = value
                elif key == "error_description":
                    self.error_description = value

    fn is_success(self) -> Bool:
        """Check if callback contains authorization code."""
        return len(self.code) > 0 and len(self.error) == 0

    fn is_error(self) -> Bool:
        """Check if callback contains an error."""
        return len(self.error) > 0

    fn validate_state(self, expected: String) -> Bool:
        """
        Validate state parameter matches expected value.

        Security Note:
            Uses constant-time comparison to prevent timing attacks that could
            allow an attacker to guess the state parameter character by character.
        """
        return _constant_time_string_compare(self.state, expected)

    fn get_error(self) -> OAuthError:
        """Get error details."""
        return OAuthError(self.error, self.error_description)


fn _url_decode(value: String) -> String:
    """URL decode a string."""
    var result = String()
    var i = 0

    while i < len(value):
        var c = value[i]
        if c == "+":
            result += " "
            i += 1
        elif c == "%" and i + 2 < len(value):
            var hex = value[i+1:i+3]
            var byte = _parse_hex(hex)
            result += chr(Int(byte))
            i += 3
        else:
            result += c
            i += 1

    return result


fn _parse_hex(hex: String) -> UInt8:
    """Parse 2-character hex string to byte."""
    var result: UInt8 = 0
    for i in range(len(hex)):
        var c = hex[i]
        var digit: UInt8 = 0
        if c >= "0" and c <= "9":
            digit = UInt8(ord(c) - ord("0"))
        elif c >= "A" and c <= "F":
            digit = UInt8(ord(c) - ord("A") + 10)
        elif c >= "a" and c <= "f":
            digit = UInt8(ord(c) - ord("a") + 10)
        result = (result << 4) | digit
    return result


fn _constant_time_string_compare(a: String, b: String) -> Bool:
    """
    Compare two strings in constant time to prevent timing attacks.

    Security Note:
        This function avoids early returns that could leak timing information.
        The length difference is XORed into the result rather than causing
        an early return, ensuring consistent execution time regardless of
        where the first difference occurs.
    """
    # XOR length difference into result (avoids timing leak from early return)
    var result: UInt8 = 0
    if len(a) != len(b):
        result = 1

    # Compare all characters up to the shorter length
    var min_len = min(len(a), len(b))
    for i in range(min_len):
        result |= UInt8(ord(a[i]) ^ ord(b[i]))

    return result == 0
