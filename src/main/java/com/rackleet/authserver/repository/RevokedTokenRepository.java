package com.rackleet.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rackleet.authserver.entity.RevokedToken;

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, Long>{

    // The one question this table answers:
    // Has this access token been revoked?
    boolean existsByJti(String jti);
    
}
