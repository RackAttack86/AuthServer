package com.rackleet.authserver.dto.request;

import lombok.Data;

/**
 * Captures parameters from POST /oauth2/token.
 * 
 * The token endpoint handles multiple grant types, each with
 * different required parameters. We capture everything here
 * and let the service validate per grant type.
 * 
 * No @Valid annotations — same reason as AuthorizationRequest:
 * error handling depends on context, not a one-size-fits-all response.
 */

@Data
public class TokenRequest {
    
    // Required for all grants - determines which flow to execute
    private String grantType;

    // authorization_code grant fields
    private String code;
    private String redirectUri;
    private String codeVerifier; // PKCE

    private String refreshToken;
    private String scope;
}
