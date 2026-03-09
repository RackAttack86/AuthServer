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
import org.springframework.web.bind.annotation.RequestBody;


@RestController
@RequiredArgsConstructor
public class TokenController {
    
    private final ClientAuthenticationService clientAuthService;
    private final TokenService tokenService;

    /**
     * Token endpoint - POST /oauth2/token
     * This is the back-channel endpoint where clients exchange
     * credentials for tokens.
     * 
     * Every request hits client authentication first, then dispatches
     * to the appropriate grant type handler.
     * 
     * Uses HttpServletRequest instead of @RequestBody because
     * the token endpoint accepts form-encoded parameters, not JSON
     * This is mandated by RFC 6749. @RequestBody expects JSON by default
     */
    @PostMapping("/oauth2/token")
    public ResponseEntity<Map<String, Object>> token(HttpServletRequest request) {
        

        // Step 1: Authenticate the client.
        // Checks Basic header, body params, or public client identification
        // Throws invalid_client if authentication fails.
        OAuthClient client = clientAuthService.authenticateClient(request);

        // Step 2: Extract the grant type
        String grantType = request.getParameter("grant_type");
        if (grantType == null || grantType.isBlank()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "grant_type is required", HttpStatus.BAD_REQUEST);
        }

        // Step 3: Dispatch to the appropriate grant handler
        Map<String, Object> tokenResponse;

        switch(grantType) {
            case "authorization_code" -> {
                TokenRequest tokenRequest = extractAuthCodeRequest(request);
                tokenResponse = tokenService.exchangeAuthorizationCode(tokenRequest, client);
            }

            // Phase 3: case "refresh_token" ->
            // Phase 4: case "client_credentials" ->
            // Phase 6: case "urn:ietf:params:oauth:grant-type:device_code" ->
            default -> throw new OAuthException(OAuthError.UNSUPPORTED_GRANT_TYPE, "Unsupported grant_type: " + grantType, HttpStatus.BAD_REQUEST);
        }

        // Step 4: Return the token response with required cache headers.
        // RFC 6749 - token responses MUST include these headers
        // to prevent tokens from being cached by browsers or proxies

        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .cacheControl(CacheControl.noStore())
            .header("Pragma", "no-cache") // HTTP/1.0 for backward compatibility
            .body(tokenResponse);
    }
    
    /**
     * Extracts authorization code grant parameters from the request.
     * Form-encoded POST body, not JSON - per the OAuth spec
     */
    private TokenRequest extractAuthCodeRequest(HttpServletRequest request) {
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType("authorization_code");
        tokenRequest.setCode(request.getParameter("code"));
        tokenRequest.setRedirectUri(request.getParameter("redirect_uri"));
        tokenRequest.setCodeVerifier(request.getParameter("code_verifier"));
        return tokenRequest;
    }
}
