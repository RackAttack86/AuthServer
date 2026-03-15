package com.rackleet.authserver.entity;

import java.time.Instant;
import java.util.Set;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "user_consents")
@Getter
@Setter
@ToString
@NoArgsConstructor
@EqualsAndHashCode(of = {"id"})
public class UserConsent {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "client_id", nullable = false, length = 36)
    private String clientId;

    // Space-delimited scopes the user has approved.
    // Compared as a set - order doesnt matter.
    @Column(name = "granted_scopes", nullable = false, columnDefinition = "TEXT")
    private String grantedScopes;

    @Column(name = "created_at", updatable = false, nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        updatedAt = Instant.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }

    /**
     * Checks if this consent covers all the requested scopes
     * Returns true if every requested scope is in the granted set
     * In the entity to keep it close to the data and make it reusable.
     * Its a pure function on the entitys own state, no dependencies
     */
    public boolean coversScopes(String requestedScopes) {
        if (requestedScopes == null || requestedScopes.isBlank()) {
             return true;
        }

        Set<String> granted = Set.of(grantedScopes.split(" "));
        Set<String> requested = Set.of(requestedScopes.split(" "));
        return granted.containsAll(requested);
    }
}
