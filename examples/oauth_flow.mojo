"""OAuth 2.0 authorization flow example."""
from mojo_oauth2 import OAuth2Client, OAuth2Config, PKCEChallenge

fn main() raises:
    # Configure OAuth client
    var config = OAuth2Config(
        client_id="your-client-id",
        client_secret="your-client-secret",
        authorize_url="https://auth.example.com/authorize",
        token_url="https://auth.example.com/token",
        redirect_uri="http://localhost:8080/callback",
    )
    var client = OAuth2Client(config)
    
    # Generate PKCE challenge (recommended for public clients)
    var pkce = PKCEChallenge.generate()
    print("Code verifier:", pkce.verifier[:20], "...")
    print("Code challenge:", pkce.challenge[:20], "...")
    
    # Build authorization URL
    var auth_url = client.authorization_url(pkce.challenge)
    print("Authorize at:", auth_url[:60], "...")
    
    # After user authorizes, exchange code for token:
    # var token = client.exchange_code(code, pkce.verifier)
