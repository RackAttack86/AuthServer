package com.rackleet.authserver.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rackleet.authserver.entity.OAuthClient;

public interface OAuthClientRepository extends JpaRepository<OAuthClient, Long> {

    Optional<OAuthClient> findByClientId(String clientId);

    boolean existsByClientId(String clientId);
    
}
