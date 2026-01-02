"""
PKCE (Proof Key for Code Exchange) Implementation

RFC 7636 - Pure Mojo implementation for secure OAuth 2.0 flows
in public clients (mobile apps, SPAs).
"""

from random import random_ui64


# =============================================================================
# PKCE Code Verifier/Challenge
# =============================================================================

struct PKCE:
    """
    PKCE implementation for OAuth 2.0.

    Provides code verifier generation and S256/plain challenge derivation.

    Usage:
        var pkce = PKCE.generate()
        var auth_url = client.authorization_url(
            code_challenge=pkce.code_challenge,
            code_challenge_method="S256"
        )
        # After callback:
        var token = client.exchange_code(code, pkce.code_verifier)
    """
    var code_verifier: String
    var code_challenge: String
    var method: String

    fn __init__(out self, code_verifier: String, code_challenge: String, method: String):
        self.code_verifier = code_verifier
        self.code_challenge = code_challenge
        self.method = method

    @staticmethod
    fn generate(method: String = "S256") -> PKCE:
        """
        Generate PKCE code verifier and challenge.

        Args:
            method: Challenge method ("S256" or "plain")

        Returns:
            PKCE struct with verifier and challenge
        """
        var verifier = _generate_code_verifier()
        var challenge: String

        if method == "plain":
            challenge = verifier
        else:
            # S256: BASE64URL(SHA256(code_verifier))
            challenge = _s256_challenge(verifier)

        return PKCE(verifier, challenge, method)

    @staticmethod
    fn from_verifier(verifier: String, method: String = "S256") -> PKCE:
        """Create PKCE from existing verifier."""
        var challenge: String
        if method == "plain":
            challenge = verifier
        else:
            challenge = _s256_challenge(verifier)
        return PKCE(verifier, challenge, method)


# =============================================================================
# Internal Functions
# =============================================================================

fn _generate_code_verifier() -> String:
    """
    Generate a random code verifier.

    RFC 7636 requires:
    - 43-128 characters
    - Only unreserved URI characters [A-Za-z0-9-._~]
    """
    # Use 64 characters (well within 43-128 range)
    alias CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    alias VERIFIER_LENGTH = 64

    var result = String()
    for _ in range(VERIFIER_LENGTH):
        var idx = Int(random_ui64() % len(CHARSET))
        result += CHARSET[idx]

    return result


fn _s256_challenge(verifier: String) -> String:
    """
    Compute S256 challenge from verifier.

    S256 = BASE64URL(SHA256(verifier))

    Note: This is a simplified implementation. In production,
    use mojo-jwt's SHA256 or a crypto library.
    """
    # Compute SHA256 of verifier
    var hash = _sha256(verifier)

    # Base64URL encode (without padding)
    return _base64url_encode(hash)


fn _sha256(data: String) -> List[UInt8]:
    """
    SHA-256 hash implementation.

    Based on FIPS 180-4 specification.
    """
    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    var h0: UInt32 = 0x6a09e667
    var h1: UInt32 = 0xbb67ae85
    var h2: UInt32 = 0x3c6ef372
    var h3: UInt32 = 0xa54ff53a
    var h4: UInt32 = 0x510e527f
    var h5: UInt32 = 0x9b05688c
    var h6: UInt32 = 0x1f83d9ab
    var h7: UInt32 = 0x5be0cd19

    # Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    var k = List[UInt32]()
    k.append(0x428a2f98); k.append(0x71374491); k.append(0xb5c0fbcf); k.append(0xe9b5dba5)
    k.append(0x3956c25b); k.append(0x59f111f1); k.append(0x923f82a4); k.append(0xab1c5ed5)
    k.append(0xd807aa98); k.append(0x12835b01); k.append(0x243185be); k.append(0x550c7dc3)
    k.append(0x72be5d74); k.append(0x80deb1fe); k.append(0x9bdc06a7); k.append(0xc19bf174)
    k.append(0xe49b69c1); k.append(0xefbe4786); k.append(0x0fc19dc6); k.append(0x240ca1cc)
    k.append(0x2de92c6f); k.append(0x4a7484aa); k.append(0x5cb0a9dc); k.append(0x76f988da)
    k.append(0x983e5152); k.append(0xa831c66d); k.append(0xb00327c8); k.append(0xbf597fc7)
    k.append(0xc6e00bf3); k.append(0xd5a79147); k.append(0x06ca6351); k.append(0x14292967)
    k.append(0x27b70a85); k.append(0x2e1b2138); k.append(0x4d2c6dfc); k.append(0x53380d13)
    k.append(0x650a7354); k.append(0x766a0abb); k.append(0x81c2c92e); k.append(0x92722c85)
    k.append(0xa2bfe8a1); k.append(0xa81a664b); k.append(0xc24b8b70); k.append(0xc76c51a3)
    k.append(0xd192e819); k.append(0xd6990624); k.append(0xf40e3585); k.append(0x106aa070)
    k.append(0x19a4c116); k.append(0x1e376c08); k.append(0x2748774c); k.append(0x34b0bcb5)
    k.append(0x391c0cb3); k.append(0x4ed8aa4a); k.append(0x5b9cca4f); k.append(0x682e6ff3)
    k.append(0x748f82ee); k.append(0x78a5636f); k.append(0x84c87814); k.append(0x8cc70208)
    k.append(0x90befffa); k.append(0xa4506ceb); k.append(0xbef9a3f7); k.append(0xc67178f2)

    # Prepare message
    var msg = List[UInt8]()
    for i in range(len(data)):
        msg.append(UInt8(ord(data[i])))

    var orig_len = len(msg)

    # Append bit '1' to message
    msg.append(0x80)

    # Pad to 448 bits mod 512 (56 bytes mod 64)
    while (len(msg) % 64) != 56:
        msg.append(0x00)

    # Append original length in bits as 64-bit big-endian
    var bit_len = UInt64(orig_len * 8)
    for i in range(8):
        msg.append(UInt8((bit_len >> (56 - i * 8)) & 0xFF))

    # Process each 512-bit (64-byte) chunk
    var num_chunks = len(msg) // 64
    for chunk_idx in range(num_chunks):
        var w = List[UInt32]()
        for _ in range(64):
            w.append(0)

        # Copy chunk into first 16 words
        for i in range(16):
            var offset = chunk_idx * 64 + i * 4
            w[i] = (
                (UInt32(msg[offset]) << 24) |
                (UInt32(msg[offset + 1]) << 16) |
                (UInt32(msg[offset + 2]) << 8) |
                UInt32(msg[offset + 3])
            )

        # Extend to 64 words
        for i in range(16, 64):
            var s0 = _rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            var s1 = _rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = w[i-16] + s0 + w[i-7] + s1

        # Initialize working variables
        var a = h0
        var b = h1
        var c = h2
        var d = h3
        var e = h4
        var f = h5
        var g = h6
        var h = h7

        # Compression function main loop
        for i in range(64):
            var S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            var ch = (e & f) ^ ((~e) & g)
            var temp1 = h + S1 + ch + k[i] + w[i]
            var S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            var maj = (a & b) ^ (a & c) ^ (b & c)
            var temp2 = S0 + maj

            h = g
            g = f
            f = e
            e = d + temp1
            d = c
            c = b
            b = a
            a = temp1 + temp2

        # Add compressed chunk to hash
        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e
        h5 += f
        h6 += g
        h7 += h

    # Produce final hash value (big-endian)
    var result = List[UInt8]()
    for val in List[UInt32](h0, h1, h2, h3, h4, h5, h6, h7):
        result.append(UInt8((val[] >> 24) & 0xFF))
        result.append(UInt8((val[] >> 16) & 0xFF))
        result.append(UInt8((val[] >> 8) & 0xFF))
        result.append(UInt8(val[] & 0xFF))

    return result


fn _rotr(x: UInt32, n: Int) -> UInt32:
    """Right rotate 32-bit value."""
    return (x >> n) | (x << (32 - n))


fn _base64url_encode(data: List[UInt8]) -> String:
    """
    Base64URL encode without padding.

    RFC 4648 Section 5 - URL-safe Base64.
    """
    alias CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    var result = String()
    var i = 0
    var length = len(data)

    while i < length:
        var b0 = UInt32(data[i])
        var b1 = UInt32(data[i + 1]) if i + 1 < length else UInt32(0)
        var b2 = UInt32(data[i + 2]) if i + 2 < length else UInt32(0)

        var triple = (b0 << 16) | (b1 << 8) | b2

        result += CHARSET[Int((triple >> 18) & 0x3F)]
        result += CHARSET[Int((triple >> 12) & 0x3F)]

        if i + 1 < length:
            result += CHARSET[Int((triple >> 6) & 0x3F)]
        if i + 2 < length:
            result += CHARSET[Int(triple & 0x3F)]

        i += 3

    return result


# =============================================================================
# State Parameter
# =============================================================================

fn generate_state() -> String:
    """
    Generate a random state parameter.

    Used to prevent CSRF attacks in OAuth flows.
    """
    alias CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    alias STATE_LENGTH = 32

    var result = String()
    for _ in range(STATE_LENGTH):
        var idx = Int(random_ui64() % len(CHARSET))
        result += CHARSET[idx]

    return result


fn generate_nonce() -> String:
    """
    Generate a random nonce for OIDC.

    Used to associate client session with ID Token.
    """
    return generate_state()  # Same format as state
