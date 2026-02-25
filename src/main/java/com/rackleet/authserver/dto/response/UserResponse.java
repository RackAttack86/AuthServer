package com.rackleet.authserver.dto.response;

import lombok.Data;

import java.time.Instant;

@Data
public class UserResponse {
    
    private Long id;
    private String username;
    private String email;
    private boolean emailVerified;
    private Instant createdAt;

    // No passwordHash - never exposed
    // No isActive - internal state
}

/*
   Notice id is included here unlike in client DTOs. For users, the id is how other parts of the system reference them (consent records, token ownership). It's not a security-sensitive value the way a sequential client count would be — it becomes the sub (subject) claim in OIDC tokens.
 */