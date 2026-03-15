// controller/TokenController.java
package com.rackleet.authserver.controller;

import com.rackleet.authserver.dto.request.TokenRequest;
import com.rackleet.authserver.entity.OAuthClient;
import com.rackleet.authserver.exception.OAuthError;
import com.rackleet.authserver.exception.OAuthException;
import com.rackleet.authserver.service.ClientAuthenticationService;
import com.rackleet.authserver.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class TokenController {

    private final ClientAuthenticationService clientAuthenticationService;
    private final TokenService tokenService;

    /**
     * POST /oauth2/token
     * Handles all grant types. Client authentication happens first,
     * then dispatches to the appropriate handler.
     */
    @PostMapping("/oauth2/token")
    public ResponseEntity<Map<String, Object>> token(HttpServletRequest request) {

        OAuthClient client = clientAuthenticationService.authenticateClient(request);

        String grantType = request.getParameter("grant_type");
        if (grantType == null || grantType.isBlank()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST,
                    "grant_type is required", HttpStatus.BAD_REQUEST);
        }

        Map<String, Object> tokenResponse;

        switch (grantType) {
            case "authorization_code" -> {
                TokenRequest tokenRequest = extractAuthCodeRequest(request);
                tokenResponse = tokenService.exchangeAuthorizationCode(tokenRequest, client);
            }
            case "refresh_token" -> {
                TokenRequest tokenRequest = extractRefreshRequest(request);
                tokenResponse = tokenService.refreshAccessToken(tokenRequest, client);
            }
            // Phase 4: case "client_credentials" →
            // Phase 6: case "urn:ietf:params:oauth:grant-type:device_code" →
            default -> throw new OAuthException(
                    OAuthError.UNSUPPORTED_GRANT_TYPE,
                    "Unsupported grant_type: " + grantType,
                    HttpStatus.BAD_REQUEST);
        }

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .cacheControl(CacheControl.noStore())
                .header("Pragma", "no-cache")
                .body(tokenResponse);
    }

    /**
     * POST /oauth2/revoke (RFC 7009)
     *
     * Revokes an access token or refresh token.
     * Always returns 200 OK — even if the token is invalid or not found.
     * This prevents attackers from probing which tokens exist.
     */
    @PostMapping("/oauth2/revoke")
    public ResponseEntity<Void> revoke(HttpServletRequest request) {

        OAuthClient client = clientAuthenticationService.authenticateClient(request);

        String token = request.getParameter("token");
        if (token == null || token.isBlank()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST,
                    "token is required", HttpStatus.BAD_REQUEST);
        }

        // Optional hint to check that type first — just an optimization
        String tokenTypeHint = request.getParameter("token_type_hint");

        tokenService.revokeToken(token, tokenTypeHint, client);

        // Always 200 — spec requirement
        return ResponseEntity.ok().build();
    }

    /**
     * POST /oauth2/introspect (RFC 7662)
     *
     * Returns metadata about a token — whether it's active and its claims.
     * Called by resource servers to validate tokens.
     * The caller must be an authenticated client (the resource server
     * must be registered as a client).
     */
    @PostMapping("/oauth2/introspect")
    public ResponseEntity<Map<String, Object>> introspect(HttpServletRequest request) {

        // The resource server must authenticate as a client
        clientAuthenticationService.authenticateClient(request);

        String token = request.getParameter("token");
        if (token == null || token.isBlank()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST,
                    "token is required", HttpStatus.BAD_REQUEST);
        }

        String tokenTypeHint = request.getParameter("token_type_hint");

        Map<String, Object> result = tokenService.introspectToken(token, tokenTypeHint);

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .cacheControl(CacheControl.noStore())
                .header("Pragma", "no-cache")
                .body(result);
    }

    // ── Request Extractors ──────────────────────────────────────

    private TokenRequest extractAuthCodeRequest(HttpServletRequest request) {
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType("authorization_code");
        tokenRequest.setCode(request.getParameter("code"));
        tokenRequest.setRedirectUri(request.getParameter("redirect_uri"));
        tokenRequest.setCodeVerifier(request.getParameter("code_verifier"));
        return tokenRequest;
    }

    private TokenRequest extractRefreshRequest(HttpServletRequest request) {
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType("refresh_token");
        tokenRequest.setRefreshToken(request.getParameter("refresh_token"));
        tokenRequest.setScope(request.getParameter("scope"));
        return tokenRequest;
    }
}