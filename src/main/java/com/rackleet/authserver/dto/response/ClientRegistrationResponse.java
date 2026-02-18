package com.rackleet.authserver.dto.response;

import java.time.Instant;
import java.util.List;

import lombok.Data;

@Data
public class ClientRegistrationResponse {
    
    private String clientId;
    private String clientSecret; // PLAINTEXT -- returned exactly once, only on creation
    private String clientName;
    private String clientType;
    private List<String> redirectUris;
    private List<String> allowedGrantTypes;
    private List<String> allowedScopes;
    private String tokenEndpointAuthMethod;
    private boolean requirePkce;
    private int accessTokenTtlSeconds;
    private int refreshTokenTtlSeconds;
    private Instant createdAt;
}
