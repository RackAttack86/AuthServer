package com.rackleet.authserver.service;

import com.rackleet.authserver.crypto.HashUtils;
import com.rackleet.authserver.dto.request.TokenRequest;
import com.rackleet.authserver.entity.AuthorizationCode;
import com.rackleet.authserver.entity.OAuthClient;
import com.rackleet.authserver.exception.OAuthError;
import com.rackleet.authserver.exception.OAuthException;
import com.rackleet.authserver.repository.AuthorizationCodeRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {
    
    private final AuthorizationCodeRepository authCodeRepo;

    /**
     * Exchanges an authorization code for tokens
     * THe client has already been authenticated by ClientAuthenticationService
     * before this method is called - the authenticated client is passed in
     */
    public Map<String, Object> exchangeAuthorizationCode(
        TokenRequest request, OAuthClient client) {
            
            // 1. Validate required parameters
            if (request.getCode() == null || request.getCode().isBlank())  {
                throw new OAuthException(OAuthError.INVALID_REQUEST, "code is required", HttpStatus.BAD_REQUEST);
            }

            if (request.getRedirectUri() == null || request.getRedirectUri().isBlank()) {
                throw new OAuthException(OAuthError.INVALID_REQUEST, "redirect_uri is required", HttpStatus.BAD_REQUEST);
            }

            // 2. Look up the code by its hash
            String codeHash = HashUtils.sha256(request.getCode());
            AuthorizationCode authCode = authCodeRepo.findByCodeHash(codeHash).orElseThrow(() -> OAuthException(OAuthError.INVALID_GRANT, "Invalid authorization code", HttpStatus.BAD_REQUEST));

            // 3. Check if the code was already used - this is a security critical check
            // If a used code is presented again, it means either the code was stolen
            // or there's a replay attack. The spec requires revoking all tokens
            // that were issued from this code. For now just reject it;
            // token revocation added later
            if (authCode.isUsed()) {
                log.warn("Authorization code reuse detected for client '{}'. " + "Possible token theft.", client.getClientId());
                // TODO: revoke all tokens issued from this code
                throw new OAuthException(OAuthError.INVALID_GRANT, "Authorization code has already been used", HttpStatus.BAD_REQUEST);
            }

            // 4. Check expiration
            if (authCode.isExpired()) {
                throw new OAuthException(OAuthError.INVALID_GRANT, "Authorization code has expired", HttpStatus.BAD_REQUEST);
            }

            // 6. Verify redirect_uri matches exactly
            // RFC 6749 - must be identical to the one in the
            // authorization request. Prevents code injection attacks where
            // an attacker substitutes their own redirect URI
            if (!authCode.getRedirectUri().equals(request.getRedirectUri())) {
                throw new OAuthException(OAuthError.INVALID_GRANT, "redirect_uri does not match the authorization request", HttpStatus.BAD_REQUEST);
            } 

            // 7. Validate PKCE if a code_challenge was stored
            if (authCode.getCodeChallenge() != null) {
                validatePkce(request.getCodeVerifier(), authCode);
            }

            // 8. Mark the code as used - single use enforcement
            authCode.setUsed(true);
            authCodeRepo.save(authCode);

            log.debug("Authorization code exchanged for client '{}', user '{}'", client.getClientId(), authCode.getUserId());

            // 9. Generate tokens
            // Stub for now - returns opaque placeholder tokens
            // Next phase replaces this with real JWT access tokens
            // and opaque refresh tokens
            return buildTokenResponse(authCode, client);
        }

        // -- PKCE Validation ----

        /**
         * Validate the PKCE code_verifier against the stored code_challenge
         * 
         * For S256: Base64url(SHA256(code_verifier)) must equal code_challenge
         * This proves the caller that's exchanging the code is the same one
         * that initiated the authorization request - even if an attacker
         * intercepted the code in transit, they don't have the verifier
         */
        private void validatePkce(String codeVerifier, AuthorizationCode authCode) {
            if (codeVerifier == null || codeVerifier.isBlank()) {
                throw new OAuthException(OAuthError.INVALID_GRANT, "code_verifier is required - a code_challenge was used in the authorization request", HttpStatus.BAD_REQUEST);
            }

            if (!"S256".equals(authCode.getCodeChallenge())) {
                throw new OAuthException(OAuthError.INVALID_REQUEST, "Unsupported code_challenge_method", HttpStatus.BAD_REQUEST);
            }

            // Compute the challenge from the verifier:
            // BASE64URL(SHA256(ascii(code_verifier)))
            String computeChallenge = computeS256Challenge(codeVerifier);

            // Constant-time comparison to prevent timing attacks
            // Message.Digest.isEqual compares byte-by-byte in constant time
            if (!MessageDigest.isEqual(computeChallenge.getBytes(StandardCharsets.UTF_8), authCode.getCodeChallenge().getBytes(StandardCharsets.UTF_8))) {
                throw new OAuthException(OAuthError.INVALID_GRANT, "PKCE verification failed - code_verifier does not match the code_challenge", HttpStatus.BAD_REQUEST);
            }
        }

        /**
         * Computes the S256 PKCE challenge from a verifier.
         * Per RFC 7636: BASE64URL(SHA256(ASCII(code_verifier)))
         *
         * This is different from HashUtils.sha256() which returns hex.
         * PKCE requires Base64url encoding, not hex.
         */

        private String computeS256Challenge(String codeVerifier) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            } catch (NoSuchAlgorithmException e) {
                throw new RunTimeException("SHA-256 no available", e);
            }
        }

        // -- Token Response -----

        /**
         * Builds the token response per RFC 6749
         * Currently returns stub tokens - real JWT generation coming
         */
        private Map<String, Object> buildTokenResponse(
            AuthorizationCode authCode, OAuthClient client) {

                // Stub tokens for now
                String accessToken = "stub_access_token" + HashUtils.generateRandomToken();
                String refreshToken = "stub_refresh_token" + HashUtils.generateRandomToken();

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("access_token", accessToken);
                response.put("token_type", "Bearer");
                response.put("expires_in", client.getAccessTokenTtlSeconds());

                // Only include refresh token if the client is allowed to use it
                if (client.getAllowedGrantTypes().contains("refresh_token")) {
                    response.put("refresh_token", refreshToken);
                }

                // Return the granted scope
                if (authCode.getScope() != null && !authCode.getScope().isBlank()) {
                    response.put("scope", authCode.getScope());
                }

                return response;
            }
        
}
