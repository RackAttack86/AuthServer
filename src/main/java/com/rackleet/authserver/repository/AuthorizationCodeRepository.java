package com.rackleet.authserver.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rackleet.authserver.entity.AuthorizationCode;

public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, Long> {

    Optional<AuthorizationCode> findByCodeHash(String codeHash);
    
}
