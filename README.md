# mojo-oauth2

Pure Mojo OAuth 2.0 client library with PKCE support.

## Features

- **OAuth 2.0 Flows**: Authorization Code, Client Credentials, Refresh Token
- **PKCE Support**: Proof Key for Code Exchange (RFC 7636)
- **Pre-configured Providers**: Google, GitHub, Microsoft, Apple, Auth0, Okta, Keycloak
- **Pure Mojo**: SHA-256, Base64URL encoding built-in
- **Type-Safe**: Compile-time type checking for all OAuth structures

## Installation

Add to your `pixi.toml`:

```toml
[workspace.dependencies]
mojo-oauth2 = { path = "../mojo-libs/mojo-oauth2" }
```

## Usage

### Authorization Code Flow with PKCE

```mojo
from mojo_oauth2 import OAuth2Client, Providers, PKCE, generate_state

fn main() raises:
    # Create client for Google
    var client = OAuth2Client(
        Providers.google(),
        client_id="your-client-id",
        redirect_uri="http://localhost:8080/callback"
    )

    # Generate PKCE and state
    var pkce = PKCE.generate()
    var state = generate_state()

    # Build authorization URL
    var auth_url = client.authorization_url(
        scope="openid email profile",
        state=state,
        code_challenge=pkce.code_challenge
    )
    print("Visit: " + auth_url)

    # After user authorizes and is redirected back...
    var callback_code = "code-from-callback"

    # Exchange code for tokens
    var token = client.exchange_code(
        code=callback_code,
        code_verifier=pkce.code_verifier
    )

    print("Access Token: " + token.access_token)
    print("Refresh Token: " + token.refresh_token)
```

### Client Credentials Flow

```mojo
from mojo_oauth2 import OAuth2Client, Providers

fn main() raises:
    var client = OAuth2Client(
        Providers.custom(
            "my-api",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token"
        ),
        client_id="service-account-id",
        client_secret="service-account-secret"
    )

    # Get machine-to-machine token
    var token = client.client_credentials(scope="read write")
    print("Token: " + token.access_token)

    # Use token in requests
    var auth_header = token.authorization_header()  # "Bearer xyz..."
```

### Token Refresh

```mojo
from mojo_oauth2 import OAuth2Client, Providers

fn main() raises:
    var client = OAuth2Client(Providers.github(), client_id="...")

    # ... initial authorization ...

    # Later, refresh the token
    if client.is_token_expired(current_time):
        var new_token = client.refresh()
        print("New access token: " + new_token.access_token)
```

### Handling Callbacks

```mojo
from mojo_oauth2 import CallbackHandler

fn handle_oauth_callback(query_string: String, expected_state: String) raises:
    var handler = CallbackHandler(query_string)

    if handler.is_error():
        var error = handler.get_error()
        raise Error("OAuth error: " + str(error))

    if not handler.validate_state(expected_state):
        raise Error("State mismatch - possible CSRF attack")

    if handler.is_success():
        print("Authorization code: " + handler.code)
        # Exchange code for token...
```

## Pre-configured Providers

| Provider | Usage |
|----------|-------|
| Google | `Providers.google()` |
| GitHub | `Providers.github()` |
| Microsoft | `Providers.microsoft()` |
| Apple | `Providers.apple()` |
| Auth0 | `Providers.auth0("tenant.auth0.com")` |
| Okta | `Providers.okta("dev-123456.okta.com")` |
| Keycloak | `Providers.keycloak("https://kc.example.com", "realm")` |
| Custom | `Providers.custom(name, auth_url, token_url)` |

### Custom Provider Example

```mojo
var provider = Providers.custom(
    "internal-idp",
    "https://auth.internal.com/authorize",
    "https://auth.internal.com/token"
)
provider.with_userinfo("https://auth.internal.com/userinfo")
provider.with_revocation("https://auth.internal.com/revoke")
provider.with_jwks("https://auth.internal.com/.well-known/jwks.json")
```

## API Reference

### OAuth2Client

| Method | Description |
|--------|-------------|
| `authorization_url(scope, state, code_challenge)` | Build auth URL |
| `build_auth_request(scope)` | Build URL with auto PKCE/state |
| `exchange_code(code, code_verifier)` | Exchange code for tokens |
| `client_credentials(scope)` | Client credentials grant |
| `refresh_token(refresh_token, scope)` | Refresh access token |
| `refresh()` | Refresh stored token |
| `is_authenticated()` | Check if has access token |
| `is_token_expired(current_time)` | Check expiry |
| `get_authorization_header()` | Get "Bearer xxx" header |

### PKCE

| Method | Description |
|--------|-------------|
| `PKCE.generate(method)` | Generate verifier + challenge |
| `PKCE.from_verifier(verifier, method)` | Create from existing verifier |

### TokenResponse

| Property | Type | Description |
|----------|------|-------------|
| `access_token` | String | OAuth access token |
| `token_type` | String | Usually "Bearer" |
| `expires_in` | Int | Seconds until expiry |
| `refresh_token` | String | Refresh token (optional) |
| `scope` | String | Granted scopes |
| `id_token` | String | OIDC ID token (optional) |

### CallbackHandler

| Method | Description |
|--------|-------------|
| `is_success()` | Has authorization code |
| `is_error()` | Has error |
| `validate_state(expected)` | Validate CSRF token |
| `get_error()` | Get OAuthError details |

## PKCE Security

PKCE (RFC 7636) protects public clients (mobile apps, SPAs) from authorization code interception attacks.

```
┌─────────────────────────────────────────────────────────────────┐
│                     PKCE Flow                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Generate code_verifier (random string)                      │
│  2. Calculate code_challenge = BASE64URL(SHA256(verifier))      │
│  3. Send code_challenge to authorization endpoint               │
│  4. Receive authorization code                                  │
│  5. Send code + code_verifier to token endpoint                 │
│  6. Server verifies: SHA256(verifier) == challenge              │
│                                                                 │
│  ✓ Even if code is intercepted, attacker can't exchange it     │
│    without the code_verifier (which was never transmitted)      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Grant Types

| Grant Type | Use Case |
|------------|----------|
| `authorization_code` | Web/mobile apps with user interaction |
| `client_credentials` | Machine-to-machine, service accounts |
| `refresh_token` | Renewing expired access tokens |
| `password` | Legacy only, not recommended |

## Error Handling

```mojo
try:
    var token = client.exchange_code(code, verifier)
except e:
    if "invalid_grant" in str(e):
        print("Code expired or already used")
    elif "invalid_client" in str(e):
        print("Client ID/secret incorrect")
```

Standard error codes:
- `invalid_request` - Malformed request
- `invalid_client` - Invalid client credentials
- `invalid_grant` - Invalid authorization code/refresh token
- `unauthorized_client` - Client not authorized for grant type
- `unsupported_grant_type` - Grant type not supported
- `invalid_scope` - Invalid scope requested
- `access_denied` - User denied authorization

## Integration with mojo-server

```mojo
from mojo_server import Server, HttpRequest, HttpResponse, redirect
from mojo_oauth2 import OAuth2Client, Providers, PKCE, generate_state, CallbackHandler

var oauth_client = OAuth2Client(Providers.google(), client_id="...")
var pending_states = Dict[String, PKCE]()

fn login_handler(request: HttpRequest) raises -> HttpResponse:
    var pkce = PKCE.generate()
    var state = generate_state()
    pending_states[state] = pkce

    var auth_url = oauth_client.authorization_url(
        scope="openid email",
        state=state,
        code_challenge=pkce.code_challenge
    )
    return redirect(auth_url)

fn callback_handler(request: HttpRequest) raises -> HttpResponse:
    var handler = CallbackHandler(request.query_string)

    if not handler.is_success():
        return bad_request("OAuth failed: " + handler.error)

    var pkce = pending_states[handler.state]
    var token = oauth_client.exchange_code(handler.code, pkce.code_verifier)

    return ok("Welcome! Token: " + token.access_token[:20] + "...")

fn main() raises:
    var server = Server(port=8080)
    server.get("/login", login_handler)
    server.get("/callback", callback_handler)
    server.run()
```

## License

MIT

## Part of mojo-contrib

This library is part of [mojo-contrib](https://github.com/atsentia/mojo-contrib), a collection of pure Mojo libraries.
