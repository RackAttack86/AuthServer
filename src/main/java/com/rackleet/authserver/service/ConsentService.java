package com.rackleet.authserver.service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.rackleet.authserver.entity.RefreshToken;
import com.rackleet.authserver.entity.Scope;
import com.rackleet.authserver.entity.UserConsent;
import com.rackleet.authserver.repository.RefreshTokenRepository;
import com.rackleet.authserver.repository.ScopeRepository;
import com.rackleet.authserver.repository.UserConsentRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class ConsentService {
    
    private final UserConsentRepository consentRepo;
    private final ScopeRepository scopeRepo;
    private final RefreshTokenRepository refreshTokenRepo;

    // Checks if the user already consented to all requested scopes for this client. Skip consent screen if true 
    public boolean hasConsent(Long userId, String clientId, String requestedScope) {
        Optional<UserConsent> existing = consentRepo.findByUserIdAndClientId(userId, clientId);

        if (existing.isEmpty()) {
            return false;
        }

        return existing.get().coversScopes(requestedScope);
    }

    // Stores or updates the users consent for a client
    @Transactional
    public void saveConsent(Long userId, String clientId, String scope) {
        Optional<UserConsent> existing = consentRepo.findByUserIdAndClientId(userId, clientId);

        if (existing.isPresent()) {
            // Merge new scopes with existing ones
            UserConsent consent = existing.get();
            Set<String> mergedScopes = new HashSet<>(Arrays.asList(consent.getGrantedScopes().split(" ")));

            mergedScopes.addAll(Arrays.asList(scope.split(" ")));
            consent.setGrantedScopes(String.join(" ", mergedScopes));
            consentRepo.save(consent);
            log.debug("Updated consent for userId '{}', clientId '{}' ", userId, clientId);
        } else {
            UserConsent consent = new UserConsent();
            consent.setUserId(userId);
            consent.setClientId(clientId);
            consent.setGrantedScopes(scope);
            consentRepo.save(consent);
            log.debug("Created consent for userId '{}', clientId '{}'", userId, clientId);
        }
    }

    // Returns all consents for a user
    public List<UserConsent> getUserConsents(Long userId) {
        return consentRepo.findByUserId(userId);
    }

    // Revokes consent for a specific client. Also revokes all associated refresh tokens.
    @Transactional
    public void revokeConsent(Long userId, String clientId) {
        // Revoke all active refresh tokens for this user/client
        List<RefreshToken> tokens = refreshTokenRepo.findByClientIdAndUserIdAndRevokedFalse(clientId, userId);
        for (RefreshToken token : tokens) {
            token.setRevoked(true);
            refreshTokenRepo.save(token);
        }
        log.debug("Revoked {} refresh tokens for userId '{}', clientId '{}'", userId, clientId);
    }

    // Looks up scope descriptions for the consent screen
    public Map<String, String> getScopeDescriptions(String scope) {
        if (scope == null || scope.isBlank()) {
            return Map.of();
        }

        List<String> scopeNames = Arrays.asList(scope.split(" "));
        List<Scope> scopes = scopeRepo.findByNameIn(scopeNames);

        return scopes.stream().collect(Collectors.toMap(Scope::getName, s -> s.getDescription() != null ? s.getDescription() : s.getName()));
    }

    // Returns the default scope to grant when the client doesnt request a specific scope
    public String getDefaultScopes() {
        List<Scope> defaults = scopeRepo.findByIsDefaultTrue();
        if (defaults.isEmpty()) {
            return null;
        }

        return defaults.stream().map(Scope::getName).collect(Collectors.joining(" "));
    }

    // Validates that all requested scopes exist in the db.
    // Returns a list of the invalid scopes or an empty list if all are valid
    public List<String> validateScopesExist(String scope) {
        if (scope == null || scope.isBlank()) {
            return List.of();
        }

        List<String> requested = Arrays.asList(scope.split(" "));
        List<Scope> found = scopeRepo.findByNameIn(requested);
        Set<String> foundNames = found.stream().map(Scope::getName).collect(Collectors.toSet());

        return requested.stream().filter(s -> !foundNames.contains(s)).collect(Collectors.toList()); 
    }
}
