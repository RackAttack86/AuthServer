package com.rackleet.authserver.dto.request;

import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class ClientRegistrationRequest {

    @NotBlank(message = "client_name is required")
    private String clientName;

    @NotNull(message = "client_type is required")
    private String clientType; // "confidential" or "public"

    private List<String> redirectUris;

    @NotEmpty(message = "At least one grant type is required")
    private List<String> allowedGrantTypes;

    private List<String> allowedScopes;

    private String tokenEndpointAuthMethod; // defaults handled in service

    private Integer accessTokenTtlSeconds;

    private Integer refreshTokenTtlSeconds;
    
}
