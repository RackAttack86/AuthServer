package com.rackleet.authserver.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "revoked_tokens")
@Getter
@Setter
@NoArgsConstructor
@ToString
@EqualsAndHashCode(of = {"id"})
public class RevokedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // The jti claim from the JWT - a UUID that uniquely
    // identifies each access token issued
    @Column(nullable = false, unique = true, length = 64)
    private String jti;

    // Stored for cleaning up after the jwt would have expired anyway
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at", nullable = false, updatable = false)
    private Instant revokedAt;

    @PrePersist
    protected void onCreate() {
        revokedAt = Instant.now();
    }
}
