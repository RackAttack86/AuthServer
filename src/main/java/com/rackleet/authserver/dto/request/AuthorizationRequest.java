package com.rackleet.authserver.dto.request;

import lombok.Data;

@Data
public class AuthorizationRequest {
    
    private String responseType;

    private String clientId;

    private String redirectUri;

    private String scope;

    private String state;

    private String codeChallenge;

    private String codeChallengeMethod;
}
