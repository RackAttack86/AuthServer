package com.rackleet.authserver.service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.rackleet.authserver.entity.OAuthClient;
import com.rackleet.authserver.exception.OAuthError;
import com.rackleet.authserver.exception.OAuthException;
import com.rackleet.authserver.repository.OAuthClientRepository;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientAuthenticationService {
    
    private final OAuthClientRepository clientRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    /**
     * Authenticates a client from an incoming HTTP request.
     * Determines the authentication method from the request and
     * validates it matches the client's registered method.
     * 
     * @return the authenticated active OAuthClient entity
     * @throws OAuthException with invalid_client if authentication fails
     */ 
    public OAuthClient authenticateClient(HttpServletRequest request) {
        // Check for Basic auth header first
        String authHeader = request.getHeader("Authorization");
        boolean hasBasicHeader = authHeader != null && authHeader.toLowerCase().startsWith("basic ");

        // Check for client credentials in the form of the body
        String bodyClientId = request.getParameter("client_id");
        String bodyClientSecret = request.getParameter("client_secret");

        // Reject ambiguous requests - spec says don't combine methods
        if (hasBasicHeader && bodyClientSecret != null) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "Multiple client authentication methods detected. Use only one of: Basic header or body parameters.", HttpStatus.BAD_REQUEST);
        }

        if (hasBasicHeader) {
            return authenticateBasic(authHeader);
        }

        if (bodyClientSecret != null) {
            return authenticatePost(bodyClientId, bodyClientSecret);
        }

        if (bodyClientId != null) {
            return authenticateNone(bodyClientId);
        }

        throw invalidClientException("No client credentials provided");
    }

    // ── Basic authentication ────────────────────────────────────

    private OAuthClient authenticateBasic(String authHeader) {
        String base64Credentials = authHeader.substring("Basic ".length()).trim();
        
        String decoded;
        try {
            decoded = new String(
                Base64.getDecoder().decode(base64Credentials),
                StandardCharsets.UTF_8
            );
        } catch (IllegalArgumentException e) {
            throw invalidClientException("Malformed Basic credentials");
        }

        int colonIndex = decoded.indexOf(':');
        if (colonIndex < 0) {
            throw invalidClientException("Malformed Basic credentials: missing separator");
        }

        // URL decode both parts per RFC 6749 Section 2.3.1
        String clientId = urlDecode(decoded.substring(0, colonIndex));
        String clientSecret = urlDecode(decoded.substring(colonIndex + 1));

        OAuthClient client = lookupActiveClient(clientId);

        verifyAuthMethod(client, "client_secret_basic");
        verifySecret(client, clientSecret);

        log.debug("Client '{}' authenticated via client_secret_basic", clientId);
        return client;
    }

    // ── Post authentication ─────────────────────────────────────

    private OAuthClient authenticatePost(String clientId, String clientSecret) {
        if (clientId == null || clientId.isBlank()) {
            throw invalidClientException("client_id is required");
        }

        OAuthClient client = lookupActiveClient(clientId);
        verifyAuthMethod(client, "client_secret_post");
        verifySecret(client, clientSecret);

        log.debug("Client '{}' authenticated via client_secret_post", clientId);
        return client;
    }

    // ── No authentication (public clients) ──────────────────────

    private OAuthClient authenticateNone(String clientId) {
        if (clientId.isBlank()) {
            throw invalidClientException("client_id is required");
        }

        OAuthClient client = lookupActiveClient(clientId);

        verifyAuthMethod(client, "none");

        // No secret to verify - public client
        log.debug("Public client '{}' identified via auth method 'none'", clientId);
        return client;
    }

    // ── Helpers ──────────────────────────────────────────

    private OAuthClient lookupActiveClient(String clientId) {
        return clientRepository.findByClientId(clientId)
                .filter(OAuthClient::isActive)
                .orElseThrow(() -> invalidClientException(
                        "Client not found or inactive: " + clientId));
    }

    private void verifyAuthMethod(OAuthClient client, String expectedMethod) {
        if (!client.getTokenEndpointAuthMethod().equals(expectedMethod)) {
            throw invalidClientException(
                "Client registered for '" + client.getTokenEndpointAuthMethod() + "' but attempted '" + expectedMethod + "'");
        }
    }

    private void verifySecret(OAuthClient client, String rawSecret) {
        if (client.getClientSecretHash() == null) {
            throw invalidClientException("Client has no secret configured");
        }

        /** Critical Security Detail
         * Constant-time comparison. When you verify the secret, you must not short-circuit. A naive string comparison like storedHash.equals(providedHash) returns faster when the first characters don't match, which leaks timing information. 
         * An attacker can measure response times to guess the secret character by character.
         * bcrypt's built-in comparison is already constant-time.
         * BCryptPasswordEncoder.matches() handles this for you. Never compare secrets with equals().
         * BCrypt.matches() is constant time - safe against timing attacks
         */
        if (!passwordEncoder.matches(rawSecret, client.getClientSecretHash())) {
            throw invalidClientException("Invalid client secret");
        }
    }

    private String urlDecode(String value) {
        try {
            return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw invalidClientException("Failed to URL-decode client credentials");
        }
    }

    private OAuthException invalidClientException(String description) {
        return new OAuthException(OAuthError.INVALID_CLIENT, description, HttpStatus.UNAUTHORIZED);
    }
}
