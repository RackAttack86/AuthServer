package com.rackleet.authserver.repository;

import com.rackleet.authserver.entity.Scope;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;


public interface ScopeRepository extends JpaRepository<Scope, Long> {
    
    Optional<Scope> findByName(String name);
    
    // Returns scopes granted when a client requests no specific scope
    List<Scope> findByIsDefaultTrue();

    // Look up multiple scopes by name - used to validate a set of
    // requested scopes in one query instead of individual lookups
    List<Scope> findByNameIn(List<String> names);
}
