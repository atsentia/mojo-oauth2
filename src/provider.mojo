"""
OAuth 2.0 Provider Configuration

Pre-configured providers and custom provider support.
"""


# =============================================================================
# OAuth Provider Configuration
# =============================================================================

struct OAuthProvider:
    """
    OAuth 2.0 provider configuration.

    Contains endpoints and settings for an OAuth provider.
    """
    var name: String
    var authorization_endpoint: String
    var token_endpoint: String
    var userinfo_endpoint: String
    var revocation_endpoint: String
    var jwks_uri: String
    var issuer: String
    var scopes_supported: List[String]
    var supports_pkce: Bool
    var supports_state: Bool

    fn __init__(
        out self,
        name: String,
        authorization_endpoint: String,
        token_endpoint: String,
    ):
        self.name = name
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = ""
        self.revocation_endpoint = ""
        self.jwks_uri = ""
        self.issuer = ""
        self.scopes_supported = List[String]()
        self.supports_pkce = True
        self.supports_state = True

    fn with_userinfo(inout self, endpoint: String):
        """Set userinfo endpoint."""
        self.userinfo_endpoint = endpoint

    fn with_revocation(inout self, endpoint: String):
        """Set token revocation endpoint."""
        self.revocation_endpoint = endpoint

    fn with_jwks(inout self, uri: String):
        """Set JWKS URI for token verification."""
        self.jwks_uri = uri

    fn with_issuer(inout self, issuer: String):
        """Set issuer for token validation."""
        self.issuer = issuer


# =============================================================================
# Pre-configured Providers
# =============================================================================

struct Providers:
    """Pre-configured OAuth 2.0 providers."""

    @staticmethod
    fn google() -> OAuthProvider:
        """Google OAuth 2.0 / OIDC provider."""
        var p = OAuthProvider(
            "google",
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
        )
        p.with_userinfo("https://openidconnect.googleapis.com/v1/userinfo")
        p.with_revocation("https://oauth2.googleapis.com/revoke")
        p.with_jwks("https://www.googleapis.com/oauth2/v3/certs")
        p.with_issuer("https://accounts.google.com")
        p.scopes_supported = List[String]()
        p.scopes_supported.append("openid")
        p.scopes_supported.append("email")
        p.scopes_supported.append("profile")
        return p

    @staticmethod
    fn github() -> OAuthProvider:
        """GitHub OAuth 2.0 provider."""
        var p = OAuthProvider(
            "github",
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
        )
        p.with_userinfo("https://api.github.com/user")
        p.scopes_supported = List[String]()
        p.scopes_supported.append("read:user")
        p.scopes_supported.append("user:email")
        p.scopes_supported.append("repo")
        return p

    @staticmethod
    fn microsoft() -> OAuthProvider:
        """Microsoft Identity Platform (Azure AD) provider."""
        var p = OAuthProvider(
            "microsoft",
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        )
        p.with_userinfo("https://graph.microsoft.com/v1.0/me")
        p.with_jwks("https://login.microsoftonline.com/common/discovery/v2.0/keys")
        p.with_issuer("https://login.microsoftonline.com")
        p.scopes_supported = List[String]()
        p.scopes_supported.append("openid")
        p.scopes_supported.append("email")
        p.scopes_supported.append("profile")
        p.scopes_supported.append("User.Read")
        return p

    @staticmethod
    fn apple() -> OAuthProvider:
        """Apple Sign In provider."""
        var p = OAuthProvider(
            "apple",
            "https://appleid.apple.com/auth/authorize",
            "https://appleid.apple.com/auth/token",
        )
        p.with_jwks("https://appleid.apple.com/auth/keys")
        p.with_issuer("https://appleid.apple.com")
        p.scopes_supported = List[String]()
        p.scopes_supported.append("name")
        p.scopes_supported.append("email")
        return p

    @staticmethod
    fn okta(domain: String) -> OAuthProvider:
        """
        Okta provider.

        Args:
            domain: Your Okta domain (e.g., "dev-123456.okta.com")
        """
        var base = "https://" + domain
        var p = OAuthProvider(
            "okta",
            base + "/oauth2/v1/authorize",
            base + "/oauth2/v1/token",
        )
        p.with_userinfo(base + "/oauth2/v1/userinfo")
        p.with_revocation(base + "/oauth2/v1/revoke")
        p.with_jwks(base + "/oauth2/v1/keys")
        p.with_issuer(base)
        p.scopes_supported = List[String]()
        p.scopes_supported.append("openid")
        p.scopes_supported.append("email")
        p.scopes_supported.append("profile")
        return p

    @staticmethod
    fn auth0(domain: String) -> OAuthProvider:
        """
        Auth0 provider.

        Args:
            domain: Your Auth0 domain (e.g., "myapp.auth0.com")
        """
        var base = "https://" + domain
        var p = OAuthProvider(
            "auth0",
            base + "/authorize",
            base + "/oauth/token",
        )
        p.with_userinfo(base + "/userinfo")
        p.with_revocation(base + "/oauth/revoke")
        p.with_jwks(base + "/.well-known/jwks.json")
        p.with_issuer(base + "/")
        p.scopes_supported = List[String]()
        p.scopes_supported.append("openid")
        p.scopes_supported.append("email")
        p.scopes_supported.append("profile")
        return p

    @staticmethod
    fn keycloak(base_url: String, realm: String) -> OAuthProvider:
        """
        Keycloak provider.

        Args:
            base_url: Keycloak server URL (e.g., "https://keycloak.example.com")
            realm: Keycloak realm name
        """
        var base = base_url + "/realms/" + realm + "/protocol/openid-connect"
        var p = OAuthProvider(
            "keycloak",
            base + "/auth",
            base + "/token",
        )
        p.with_userinfo(base + "/userinfo")
        p.with_revocation(base + "/revoke")
        p.with_jwks(base + "/certs")
        p.with_issuer(base_url + "/realms/" + realm)
        p.scopes_supported = List[String]()
        p.scopes_supported.append("openid")
        p.scopes_supported.append("email")
        p.scopes_supported.append("profile")
        return p

    @staticmethod
    fn custom(
        name: String,
        authorization_endpoint: String,
        token_endpoint: String,
    ) -> OAuthProvider:
        """
        Create a custom OAuth 2.0 provider.

        Args:
            name: Provider name
            authorization_endpoint: URL for authorization
            token_endpoint: URL for token exchange
        """
        return OAuthProvider(name, authorization_endpoint, token_endpoint)
