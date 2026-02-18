package com.rackleet.authserver.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity
@Table(name = "oauth_clients")
@Getter
@Setter
@NoArgsConstructor
@ToString(exclude = {"clientSecretHash"}) // never log secrets
@EqualsAndHashCode(of = {"id"}) // identity by PK only
public class OAuthClient {

    @Id
    @GeneratedValue (strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false, unique = true, length = 36)
    private String clientId;

    @Column(name = "client_secret_hash", length = 72)
    private String clientSecretHash;

    @Column(name = "client_name", nullable = false)
    private String clientName;

    @Column(name = "client_type", nullable = false, length = 20)
    private String clientType;

    @Column(name = "redirect_uris", columnDefinition = "TEXT")
    private String redirectUris; // JSON array stored as string. TODO: Check if we want to use AttributeConverter instead.

    @Column(name = "allowed_grant_types", nullable = false, columnDefinition = "TEXT")
    private String allowedGrantTypes; // JSON array stored as string

    @Column(name = "allowed_scopes", columnDefinition = "TEXT")
    private String allowedScopes; // JSON array stored as string

    @Column(name = "token_endpoint_auth_method", nullable = false, length = 30)
    private String tokenEndpointAuthMethod;

    @Column(name = "require_pkce", nullable = false)
    private boolean requirePkce;

    @Column(name = "access_token_ttl_seconds", nullable = false)
    private int accessTokenTtlSeconds;

    @Column(name = "refresh_token_ttl_seconds", nullable = false)
    private int refreshTokenTtlSeconds;

    @Column(name = "is_active", nullable = false)
    private boolean active = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now(); // Instant is an absolute point in time (UTC)
        updatedAt = Instant.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }
    
}
