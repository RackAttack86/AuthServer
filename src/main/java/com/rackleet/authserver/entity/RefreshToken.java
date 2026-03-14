package com.rackleet.authserver.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@ToString(exclude = {"tokenHash", "parentTokenHash"})
@EqualsAndHashCode(of = {"id"})
public class RefreshToken {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "token_hash", nullable = false, length = 64)
    private String tokenHash;

    @Column(name = "client_id", nullable = false, length = 36)
    private String clientId;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(columnDefinition = "TEXT")
    private String scope;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "is_revoked", nullable = false)
    private boolean isRevoked;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    // Links this token to its family for reuse detection.
    // First token in the chain will have null value.
    // All rotated tokens point to the original parent.
    @Column(name = "parent_token_hash", length = 64)
    private String parentTokenHash;

    @PrePersist
    protected void onCreate(){
        createdAt = Instant.now();
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
