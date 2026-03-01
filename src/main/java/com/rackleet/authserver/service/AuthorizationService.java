package com.rackleet.authserver.service;

import com.rackleet.authserver.crypto.HashUtils;
import com.rackleet.authserver.dto.request.AuthorizationRequest;
import com.rackleet.authserver.entity.AuthorizationCode;
import com.rackleet.authserver.entity.OAuthClient;
import com.rackleet.authserver.exception.OAuthError;
import com.rackleet.authserver.exception.OAuthException;
import com.rackleet.authserver.exception.OAuthRedirectException;
import com.rackleet.authserver.repository.AuthorizationCodeRepository;
import com.rackleet.authserver.repository.OAuthClientRepository;
import com.rackleet.authserver.util.JsonUtils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthorizationService {

    private static final int CODE_LIFETIME_MINUTES = 10;

    private final OAuthClientRepository clientRepo;
    private final AuthorizationCodeRepository authCodeRepo;

    // Validate Client and redirect URI
    // If these fail, do NOT redirect - show error directly.
    public OAuthClient validateAuthorizationRequest(AuthorizationRequest request) {
        if (request.getClientId() == null || request.getClientId().isBlank()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "client_id is required", HttpStatus.BAD_REQUEST);
        }

        OAuthClient client = clientRepo.findByClientId(request.getClientId())
            .filter(OAuthClient::isActive)
            .orElseThrow(() -> new OAuthException(OAuthError.INVALID_CLIENT, "Unknown client: " + request.getClientId(), HttpStatus.BAD_REQUEST));

        if (request.getRedirectUri() == null || request.getRedirectUri().isBlank())
            throw new OAuthException(OAuthError.INVALID_REQUEST, "redirect_uri is required", HttpStatus.BAD_REQUEST);

        List<String> registeredUris = JsonUtils.fromJson(client.getRedirectUris());
        if (!registeredUris.contains(request.getRedirectUri())) {
            // Prevent open redirect uri attacks by requiring an exact match
            throw new OAuthException(OAuthError.INVALID_REQUEST, "redirect_uri does not match any registered URI", HttpStatus.BAD_REQUEST);
        }

        // Validate remaining parameters
        // redirect_uri is trusted, errors can be returned as redirects to the client.
        if (!"code".equals(request.getResponseType())) {
            throw buildRedirectException(OAuthError.UNSUPPORTED_RESPONSE_TYPE, "response_type must be 'code'", request);
        } 

        // Validate requested scopes against client's allowed scopes
        if (request.getScope() != null && request.getScope().isBlank()) {
            List<String> requestedScopes = Arrays.asList(request.getScope().split(" "));
            List<String> allowedScopes = JsonUtils.fromJson(client.getAllowedScopes());

            for (String scope : requestedScopes) {
                if (!allowedScopes.contains(scope)) {
                    throw buildRedirectException(OAuthError.INVALID_SCOPE, "Scope not allowed for this client: " + scope, request);
                }
            }
        }

        // Validate PKCE - required for public clients, optional for confidential
        if (client.isRequirePkce()) {
            if (request.getCodeChallenge() == null || request.getCodeChallenge().isBlank()) {
                throw buildRedirectException(OAuthError.INVALID_CLIENT, "code_challenge is required for this client", request);
            }
        }

        // If a code_challenge is provided, validate the method
        if (request.getCodeChallenge() != null && request.getCodeChallenge().isBlank()) {
            String method = request.getCodeChallengeMethod();
            if (method == null) {
                // Default to "plain" per RFC 7636, only S256 supported
                request.setCodeChallengeMethod("S256");
            }
            if (!"S256".equals(request.getCodeChallengeMethod())) {
                throw buildRedirectException(OAuthError.INVALID_REQUEST, "Only S256 code_challenge_method is supported", request);
            }
        }

        // Validate the client is allowed to use authorization_code grant
        List<String> allowedGrants = JsonUtils.fromJson(client.getAllowedGrantTypes());
        if (!allowedGrants.contains("authorization_code")) {
            throw buildRedirectException(OAuthError.UNAUTHORIZED_CLIENT, "Client is not authorized for authorization_code grant", request);
        }

        log.debug("Authorization request validated for client '{}'" + client.getClientId());
        return client;
    }

    /**
     * Generates an authorization code after the user has authenticated
     * and granted consent.
     *
     * @return the plaintext code (to include in the redirect URI)
     */
    public String generateAuthorizationCode(AuthorizationRequest request, Long userId) {
        // Generate a high-entropy random code
        String rawCode = HashUtils.generateRandomToken();

        // Store the SHA-256 hash - never the plaintext
        AuthorizationCode authCode = new AuthorizationCode();
        authCode.setCodeHash(HashUtils.sha256(rawCode));
        authCode.setClientId(request.getClientId());
        authCode.setUserId(userId);
        authCode.setRedirectUri(request.getRedirectUri());
        authCode.setScope(request.getScope());
        authCode.setCodeChallenge(request.getCodeChallenge());
        authCode.setCodeChallengeMethod(request.getCodeChallengeMethod());
        authCode.setExpiresAt(Instant.now().plus(CODE_LIFETIME_MINUTES, ChronoUnit.MINUTES));

        authCodeRepo.save(authCode);

        log.debug("Authorization code generated for client '{}', user '{}'", request.getClientId(), userId);

        // Return plaintext - goes in the redirect uri to the client
        return rawCode;
    }

    private OAuthRedirectException buildRedirectException(
        OAuthError error, String description, AuthorizationRequest request) {
            return new OAuthRedirectException(
                error, 
                description, 
                request.getRedirectUri(), 
                request.getState());
        }
    
}
