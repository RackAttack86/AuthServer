// service/TokenService.java
package com.rackleet.authserver.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.rackleet.authserver.crypto.HashUtils;
import com.rackleet.authserver.crypto.KeyManager;
import com.rackleet.authserver.dto.request.TokenRequest;
import com.rackleet.authserver.entity.AuthorizationCode;
import com.rackleet.authserver.entity.OAuthClient;
import com.rackleet.authserver.entity.RefreshToken;
import com.rackleet.authserver.entity.RevokedToken;
import com.rackleet.authserver.exception.OAuthError;
import com.rackleet.authserver.exception.OAuthException;
import com.rackleet.authserver.repository.AuthorizationCodeRepository;
import com.rackleet.authserver.repository.RefreshTokenRepository;
import com.rackleet.authserver.repository.RevokedTokenRepository;
import com.rackleet.authserver.util.JsonUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    // The issuer claim in JWTs — must match your discovery document (Phase 5)
    private static final String ISSUER = "http://localhost:9000";

    private final AuthorizationCodeRepository authCodeRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RevokedTokenRepository revokedTokenRepository;
    private final KeyManager keyManager;

    // ── Authorization Code Exchange ─────────────────────────────

    @Transactional
    public Map<String, Object> exchangeAuthorizationCode(
            TokenRequest request, OAuthClient client) {

        if (request.getCode() == null || request.getCode().isBlank()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST,
                    "code is required", HttpStatus.BAD_REQUEST);
        }

        if (request.getRedirectUri() == null || request.getRedirectUri().isBlank()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST,
                    "redirect_uri is required", HttpStatus.BAD_REQUEST);
        }

        String codeHash = HashUtils.sha256(request.getCode());
        AuthorizationCode authCode = authCodeRepository.findByCodeHash(codeHash)
                .orElseThrow(() -> new OAuthException(OAuthError.INVALID_GRANT,
                        "Invalid authorization code", HttpStatus.BAD_REQUEST));

        if (authCode.isUsed()) {
            log.warn("Authorization code reuse detected for client '{}'. "
                    + "Revoking all associated tokens.", client.getClientId());
            // Revoke all refresh tokens for this user/client pair
            revokeAllTokensForUserAndClient(authCode.getClientId(), authCode.getUserId());
            throw new OAuthException(OAuthError.INVALID_GRANT,
                    "Authorization code has already been used", HttpStatus.BAD_REQUEST);
        }

        if (authCode.isExpired()) {
            throw new OAuthException(OAuthError.INVALID_GRANT,
                    "Authorization code has expired", HttpStatus.BAD_REQUEST);
        }

        if (!authCode.getClientId().equals(client.getClientId())) {
            throw new OAuthException(OAuthError.INVALID_GRANT,
                    "Authorization code was not issued to this client",
                    HttpStatus.BAD_REQUEST);
        }

        if (!authCode.getRedirectUri().equals(request.getRedirectUri())) {
            throw new OAuthException(OAuthError.INVALID_GRANT,
                    "redirect_uri does not match the authorization request",
                    HttpStatus.BAD_REQUEST);
        }

        if (authCode.getCodeChallenge() != null) {
            validatePkce(request.getCodeVerifier(), authCode);
        }

        authCode.setUsed(true);
        authCodeRepository.save(authCode);

        log.debug("Authorization code exchanged for client '{}', user '{}'",
                client.getClientId(), authCode.getUserId());

        return buildTokenResponse(authCode.getUserId(), authCode.getScope(), client, null);
    }

    // ── Refresh Token Grant ─────────────────────────────────────

    /**
     * Exchanges a refresh token for a new token pair.
     * Implements refresh token rotation with automatic reuse detection.
     */
    @Transactional
    public Map<String, Object> refreshAccessToken(
            TokenRequest request, OAuthClient client) {

        if (request.getRefreshToken() == null || request.getRefreshToken().isBlank()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST,
                    "refresh_token is required", HttpStatus.BAD_REQUEST);
        }

        // Look up the refresh token by its hash
        String tokenHash = HashUtils.sha256(request.getRefreshToken());
        RefreshToken existingToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new OAuthException(OAuthError.INVALID_GRANT,
                        "Invalid refresh token", HttpStatus.BAD_REQUEST));

        // Reuse detection: if a revoked token is presented, the entire
        // family has been compromised. Revoke everything.
        if (existingToken.isRevoked()) {
            log.warn("Revoked refresh token presented for client '{}'. "
                    + "Possible token theft. Revoking entire token family.",
                    client.getClientId());
            revokeTokenFamily(existingToken);
            throw new OAuthException(OAuthError.INVALID_GRANT,
                    "Refresh token has been revoked", HttpStatus.BAD_REQUEST);
        }

        if (existingToken.isExpired()) {
            throw new OAuthException(OAuthError.INVALID_GRANT,
                    "Refresh token has expired", HttpStatus.BAD_REQUEST);
        }

        // Must belong to the authenticated client
        if (!existingToken.getClientId().equals(client.getClientId())) {
            throw new OAuthException(OAuthError.INVALID_GRANT,
                    "Refresh token was not issued to this client",
                    HttpStatus.BAD_REQUEST);
        }

        // Handle scope narrowing: if the request includes a scope parameter,
        // it must be a subset of the original scope. Never expand.
        String grantedScope = existingToken.getScope();
        if (request.getScope() != null && !request.getScope().isBlank()) {
            grantedScope = validateScopeNarrowing(request.getScope(), existingToken.getScope());
        }

        // Rotate: revoke the old token
        existingToken.setRevoked(true);
        refreshTokenRepository.save(existingToken);

        log.debug("Refresh token rotated for client '{}', user '{}'",
                client.getClientId(), existingToken.getUserId());

        // Determine the family parent for the new token.
        // If the existing token has a parent, use that same parent.
        // If it doesn't (it's the first in the family), use its own hash.
        String familyParent = existingToken.getParentTokenHash() != null
                ? existingToken.getParentTokenHash()
                : existingToken.getTokenHash();

        return buildTokenResponse(
                existingToken.getUserId(), grantedScope, client, familyParent);
    }

    // ── Token Revocation (RFC 7009) ─────────────────────────────

    /**
     * Revokes a token. Handles both access tokens (JWTs) and refresh tokens.
     * Always returns successfully — even if the token is invalid or already
     * revoked.
     * This prevents token scanning attacks.
     */
    @Transactional
    public void revokeToken(String token, String tokenTypeHint, OAuthClient client) {
        // Try refresh token first if hinted, otherwise try both
        if ("refresh_token".equals(tokenTypeHint)) {
            if (tryRevokeRefreshToken(token, client))
                return;
            tryRevokeAccessToken(token);
        } else {
            // Default: try access token first, then refresh token
            if (tryRevokeAccessToken(token))
                return;
            tryRevokeRefreshToken(token, client);
        }
        // If neither found, silently succeed — spec requires 200 OK regardless
    }

    // ── Token Introspection (RFC 7662) ──────────────────────────

    /**
     * Introspects a token — tells the caller whether it's active and its metadata.
     * Used by resource servers to validate tokens.
     */
    public Map<String, Object> introspectToken(String token, String tokenTypeHint) {
        // Try as JWT access token first
        Map<String, Object> result = tryIntrospectAccessToken(token);
        if (result != null)
            return result;

        // Try as refresh token
        result = tryIntrospectRefreshToken(token);
        if (result != null)
            return result;

        // Token not found or invalid — return inactive
        return Map.of("active", false);
    }

    // ── JWT Generation ──────────────────────────────────────────

    /**
     * Generates a signed JWT access token with standard claims.
     */
    private String generateAccessToken(Long userId, String scope, OAuthClient client) {
        RSAKey signingKey = keyManager.getSigningKey();

        // Every JWT gets a unique ID for revocation tracking
        String jti = UUID.randomUUID().toString();

        Instant now = Instant.now();
        Instant expiration = now.plus(client.getAccessTokenTtlSeconds(), ChronoUnit.SECONDS);

        // Build the claims per RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens)
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER) // iss — your auth server
                .subject(String.valueOf(userId)) // sub — the resource owner
                .audience(ISSUER) // aud — intended recipient(s)
                .jwtID(jti) // jti — unique token identifier
                .issueTime(Date.from(now)) // iat — when it was issued
                .notBeforeTime(Date.from(now)) // nbf — valid from now
                .expirationTime(Date.from(expiration)) // exp — when it expires
                .claim("client_id", client.getClientId()) // which client requested it
                .claim("scope", scope) // granted permissions
                .build();

        // Build the JWT header with algorithm and key ID
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signingKey.getKeyID()) // kid — tells verifiers which key to use
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);

        try {
            // Sign with the private key
            signedJWT.sign(new RSASSASigner(signingKey));
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to sign JWT", e);
        }

        return signedJWT.serialize();
    }

    /**
     * Generates an opaque refresh token stored as a SHA-256 hash.
     * Returns the plaintext token — the hash is stored in the database.
     */
    private String generateRefreshToken(
            Long userId, String scope, OAuthClient client, String parentTokenHash) {

        String rawToken = HashUtils.generateRandomToken();
        String tokenHash = HashUtils.sha256(rawToken);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setTokenHash(tokenHash);
        refreshToken.setClientId(client.getClientId());
        refreshToken.setUserId(userId);
        refreshToken.setScope(scope);
        refreshToken.setExpiresAt(
                Instant.now().plus(client.getRefreshTokenTtlSeconds(), ChronoUnit.SECONDS));
        refreshToken.setParentTokenHash(parentTokenHash);

        refreshTokenRepository.save(refreshToken);

        // Return plaintext to the client — only time it's available
        return rawToken;
    }

    // ── Token Response Builder ───────────────────────────────────

    /**
     * Builds the complete token response.
     * parentTokenHash is null for initial grants (auth code exchange)
     * and set for refresh token rotation (to track the family).
     */
    private Map<String, Object> buildTokenResponse(
            Long userId, String scope, OAuthClient client, String parentTokenHash) {

        String accessToken = generateAccessToken(userId, scope, client);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("access_token", accessToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", client.getAccessTokenTtlSeconds());

        // Only issue a refresh token if the client is allowed
        List<String> allowedGrants = JsonUtils.fromJson(client.getAllowedGrantTypes());
        if (allowedGrants.contains("refresh_token")) {
            String refreshToken = generateRefreshToken(
                    userId, scope, client, parentTokenHash);
            response.put("refresh_token", refreshToken);
        }

        if (scope != null && !scope.isBlank()) {
            response.put("scope", scope);
        }

        return response;
    }

    // ── PKCE Validation ─────────────────────────────────────────

    private void validatePkce(String codeVerifier, AuthorizationCode authCode) {
        if (codeVerifier == null || codeVerifier.isBlank()) {
            throw new OAuthException(OAuthError.INVALID_GRANT,
                    "code_verifier is required — a code_challenge was used "
                            + "in the authorization request",
                    HttpStatus.BAD_REQUEST);
        }

        if (!"S256".equals(authCode.getCodeChallengeMethod())) {
            throw new OAuthException(OAuthError.INVALID_REQUEST,
                    "Unsupported code_challenge_method", HttpStatus.BAD_REQUEST);
        }

        String computedChallenge = computeS256Challenge(codeVerifier);

        if (!MessageDigest.isEqual(
                computedChallenge.getBytes(StandardCharsets.UTF_8),
                authCode.getCodeChallenge().getBytes(StandardCharsets.UTF_8))) {
            throw new OAuthException(OAuthError.INVALID_GRANT,
                    "PKCE verification failed — code_verifier does not match "
                            + "the code_challenge",
                    HttpStatus.BAD_REQUEST);
        }
    }

    private String computeS256Challenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(
                    codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    // ── Scope Narrowing ─────────────────────────────────────────

    /**
     * Validates that requested scopes are a subset of the original grant.
     * You can reduce scope on refresh, never expand.
     */
    private String validateScopeNarrowing(String requestedScope, String originalScope) {
        Set<String> original = new HashSet<>(Arrays.asList(originalScope.split(" ")));
        Set<String> requested = new HashSet<>(Arrays.asList(requestedScope.split(" ")));

        for (String scope : requested) {
            if (!original.contains(scope)) {
                throw new OAuthException(OAuthError.INVALID_SCOPE,
                        "Cannot expand scope during refresh. "
                                + "Requested scope '" + scope + "' was not in the original grant.",
                        HttpStatus.BAD_REQUEST);
            }
        }

        // Return the narrowed scope as a space-delimited string
        return requestedScope;
    }

    // ── Revocation Helpers ──────────────────────────────────────

    private boolean tryRevokeRefreshToken(String token, OAuthClient client) {
        String tokenHash = HashUtils.sha256(token);
        Optional<RefreshToken> found = refreshTokenRepository.findByTokenHash(tokenHash);

        if (found.isPresent()) {
            RefreshToken rt = found.get();
            // Only the client that was issued the token can revoke it
            if (!rt.getClientId().equals(client.getClientId())) {
                // Silently ignore — don't reveal that the token exists
                return true;
            }
            rt.setRevoked(true);
            refreshTokenRepository.save(rt);
            log.debug("Refresh token revoked for client '{}'", client.getClientId());
            return true;
        }
        return false;
    }

    private boolean tryRevokeAccessToken(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            String jti = jwt.getJWTClaimsSet().getJWTID();
            Date expiration = jwt.getJWTClaimsSet().getExpirationTime();

            if (jti != null && expiration != null) {
                // Only add to revocation list if not already there
                if (!revokedTokenRepository.existsByJti(jti)) {
                    RevokedToken revoked = new RevokedToken();
                    revoked.setJti(jti);
                    revoked.setExpiresAt(expiration.toInstant());
                    revokedTokenRepository.save(revoked);
                    log.debug("Access token revoked, jti '{}'", jti);
                }
                return true;
            }
        } catch (ParseException e) {
            // Not a valid JWT — might be a refresh token
        }
        return false;
    }

    /**
     * Revokes all tokens in a refresh token family.
     * Triggered by reuse detection — if someone presents a revoked token,
     * the whole chain is compromised.
     */
    private void revokeTokenFamily(RefreshToken compromisedToken) {
        // Determine the family root
        String familyParent = compromisedToken.getParentTokenHash() != null
                ? compromisedToken.getParentTokenHash()
                : compromisedToken.getTokenHash();

        int revoked = refreshTokenRepository.revokeTokenFamily(familyParent);
        log.warn("Revoked {} tokens in family due to reuse detection", revoked);
    }

    /**
     * Revokes all refresh tokens for a user/client pair.
     * Called when an authorization code is reused.
     */
    private void revokeAllTokensForUserAndClient(String clientId, Long userId) {
        List<RefreshToken> tokens = refreshTokenRepository
                .findByClientIdAndUserIdAndRevokedFalse(clientId, userId);
        for (RefreshToken token : tokens) {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
        }
        log.warn("Revoked {} refresh tokens for client '{}', user '{}' "
                + "due to authorization code reuse", tokens.size(), clientId, userId);
    }

    // ── Introspection Helpers ───────────────────────────────────

    /**
     * Attempts to introspect a token as a JWT access token.
     * Verifies the signature, expiration, and revocation status.
     */
    private Map<String, Object> tryIntrospectAccessToken(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);

            // Verify the signature using the key identified by kid
            String kid = jwt.getHeader().getKeyID();
            RSAKey key = keyManager.getKeyById(kid);
            if (key == null)
                return null;

            boolean signatureValid = jwt.verify(
                    new com.nimbusds.jose.crypto.RSASSAVerifier(key.toPublicJWK()));
            if (!signatureValid)
                return null;

            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // Check expiration
            if (claims.getExpirationTime() != null
                    && claims.getExpirationTime().before(new Date())) {
                return Map.of("active", false);
            }

            // Check revocation list
            if (claims.getJWTID() != null
                    && revokedTokenRepository.existsByJti(claims.getJWTID())) {
                return Map.of("active", false);
            }

            // Token is valid — return metadata
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("active", true);
            result.put("token_type", "Bearer");
            result.put("client_id", claims.getStringClaim("client_id"));
            result.put("sub", claims.getSubject());
            result.put("scope", claims.getStringClaim("scope"));
            result.put("iss", claims.getIssuer());
            result.put("exp", claims.getExpirationTime().getTime() / 1000);
            result.put("iat", claims.getIssueTime().getTime() / 1000);
            if (claims.getJWTID() != null) {
                result.put("jti", claims.getJWTID());
            }

            return result;

        } catch (ParseException | JOSEException e) {
            // Not a valid JWT
            return null;
        }
    }

    /**
     * Attempts to introspect a token as a refresh token.
     */
    private Map<String, Object> tryIntrospectRefreshToken(String token) {
        String tokenHash = HashUtils.sha256(token);
        Optional<RefreshToken> found = refreshTokenRepository.findByTokenHash(tokenHash);

        if (found.isEmpty())
            return null;

        RefreshToken rt = found.get();

        if (rt.isRevoked() || rt.isExpired()) {
            return Map.of("active", false);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("active", true);
        result.put("token_type", "refresh_token");
        result.put("client_id", rt.getClientId());
        result.put("sub", String.valueOf(rt.getUserId()));
        result.put("scope", rt.getScope());
        result.put("exp", rt.getExpiresAt().getEpochSecond());

        return result;
    }
}