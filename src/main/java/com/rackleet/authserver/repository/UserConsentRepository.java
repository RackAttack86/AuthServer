package com.rackleet.authserver.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rackleet.authserver.entity.UserConsent;

public interface UserConsentRepository extends JpaRepository<UserConsent, Long> {
    
    // The primary lookup: "has this user consented to this client?"
    // Returns at most one result due to the unique index on (user_id, client_id)
    Optional<UserConsent> findByUserIdAndClientId(Long userId, String clientId);

    // "Show me everything userId authorized" - for user consent management page
    List<UserConsent> findByUserId(Long userId);
}
