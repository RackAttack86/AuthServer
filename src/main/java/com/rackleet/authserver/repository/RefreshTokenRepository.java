package com.rackleet.authserver.repository;

import com.rackleet.authserver.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;


public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    // Used for reuse detection.
    List<RefreshToken> findByParentTokenHash(String parentTokenHash);

    // Revoke entire family in one query
    // More efficient than loading each entity and saving individually.
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.parentTokenHash = :parentHash AND rt.revoked = false")
    int revokeTokenFamily(@Param("parentHash") String parentTokenHash);

    // Find all active tokens for user/client pair
    // Used when revoking all tokens for a specific authorization
    List<RefreshToken> findByClientIdAndUserIdAndRevokedFalse(String clientId, Long userId);
}
