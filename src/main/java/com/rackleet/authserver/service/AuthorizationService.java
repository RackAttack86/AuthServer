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

    private final OAuthClientRepository clientRepository;
    private final AuthorizationCodeRepository authCodeRepository;
    private final ConsentService consentService;

    /**
     * Validates the authorization request and resolves scopes.
     * If no scope is requested, default scopes are applied.
     * Scopes are validated against both the database and the client's allowed set.
     */
    public OAuthClient validateAuthorizationRequest(AuthorizationRequest request) {

        // Tier 1: client_id and redirect_uri 

        if (request.getClientId() == null || request.getClientId().isBlank()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST,
                    "client_id is required",
                    HttpStatus.BAD_REQUEST);
        }

        OAuthClient client = clientRepository.findByClientId(request.getClientId())
                .filter(OAuthClient::isActive)
                .orElseThrow(() -> new OAuthException(OAuthError.INVALID_CLIENT,
                        "Unknown client: " + request.getClientId(),
                        HttpStatus.BAD_REQUEST));

        if (request.getRedirectUri() == null || request.getRedirectUri().isBlank()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST,
                    "redirect_uri is required",
                    HttpStatus.BAD_REQUEST);
        }

        List<String> registeredUris = JsonUtils.fromJson(client.getRedirectUris());
        if (!registeredUris.contains(request.getRedirectUri())) {
            throw new OAuthException(OAuthError.INVALID_REQUEST,
                    "redirect_uri does not match any registered URI",
                    HttpStatus.BAD_REQUEST);
        }

        // Tier 2: everything else

        if (!"code".equals(request.getResponseType())) {
            throw buildRedirectException(OAuthError.UNSUPPORTED_RESPONSE_TYPE,
                    "response_type must be 'code'",
                    request);
        }

        // Resolve scopes: if none requested, use defaults
        if (request.getScope() == null || request.getScope().isBlank()) {
            String defaultScopes = consentService.getDefaultScopes();
            if (defaultScopes != null) {
                request.setScope(defaultScopes);
            }
        }

        // Validate scopes exist in the database
        if (request.getScope() != null && !request.getScope().isBlank()) {
            List<String> invalidScopes = consentService.validateScopesExist(request.getScope());
            if (!invalidScopes.isEmpty()) {
                throw buildRedirectException(OAuthError.INVALID_SCOPE,
                        "Unknown scope(s): " + String.join(", ", invalidScopes),
                        request);
            }

            // Validate scopes are in the client's allowed set
            List<String> requestedScopes = Arrays.asList(request.getScope().split(" "));
            List<String> allowedScopes = JsonUtils.fromJson(client.getAllowedScopes());

            for (String scope : requestedScopes) {
                if (!allowedScopes.contains(scope)) {
                    throw buildRedirectException(OAuthError.INVALID_SCOPE,
                            "Scope not allowed for this client: " + scope,
                            request);
                }
            }
        }

        // Validate PKCE
        if (client.isRequirePkce()) {
            if (request.getCodeChallenge() == null || request.getCodeChallenge().isBlank()) {
                throw buildRedirectException(OAuthError.INVALID_REQUEST,
                        "code_challenge is required for this client",
                        request);
            }
        }

        if (request.getCodeChallenge() != null && !request.getCodeChallenge().isBlank()) {
            String method = request.getCodeChallengeMethod();
            if (method == null) {
                request.setCodeChallengeMethod("S256");
            }
            if (!"S256".equals(request.getCodeChallengeMethod())) {
                throw buildRedirectException(OAuthError.INVALID_REQUEST,
                        "Only S256 code_challenge_method is supported",
                        request);
            }
        }

        List<String> allowedGrants = JsonUtils.fromJson(client.getAllowedGrantTypes());
        if (!allowedGrants.contains("authorization_code")) {
            throw buildRedirectException(OAuthError.UNAUTHORIZED_CLIENT,
                    "Client is not authorized for authorization_code grant",
                    request);
        }

        log.debug("Authorization request validated for client '{}'", client.getClientId());
        return client;
    }

    /**
     * Checks if the user has already consented to the requested scopes.
     * Used by the controller to decide whether to show the consent screen
     * or skip directly to code generation.
     */
    public boolean hasExistingConsent(Long userId, String clientId, String scope) {
        return consentService.hasConsent(userId, clientId, scope);
    }

    /**
     * Records the user's consent and generates the authorization code.
     * Called after the user approves on the consent screen, or when
     * existing consent covers the requested scopes.
     */
    public String approveAndGenerateCode(AuthorizationRequest request, Long userId) {
        // Save or update consent
        consentService.saveConsent(userId, request.getClientId(), request.getScope());

        // Generate the code
        return generateAuthorizationCode(request, userId);
    }

    public String generateAuthorizationCode(AuthorizationRequest request, Long userId) {
        String rawCode = HashUtils.generateRandomToken();

        AuthorizationCode authCode = new AuthorizationCode();
        authCode.setCodeHash(HashUtils.sha256(rawCode));
        authCode.setClientId(request.getClientId());
        authCode.setUserId(userId);
        authCode.setRedirectUri(request.getRedirectUri());
        authCode.setScope(request.getScope());
        authCode.setCodeChallenge(request.getCodeChallenge());
        authCode.setCodeChallengeMethod(request.getCodeChallengeMethod());
        authCode.setExpiresAt(Instant.now().plus(CODE_LIFETIME_MINUTES, ChronoUnit.MINUTES));

        authCodeRepository.save(authCode);

        log.debug("Authorization code generated for client '{}', user '{}'",
                request.getClientId(), userId);

        return rawCode;
    }

    public String buildAuthorizationResponse(String redirectUri, String code, String state) {
        StringBuilder response = new StringBuilder(redirectUri);

        response.append(redirectUri.contains("?") ? "&" : "?");
        response.append("code=").append(code);

        if (state != null && !state.isBlank()) {
            response.append("&state=").append(state);
        }

        return response.toString();
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