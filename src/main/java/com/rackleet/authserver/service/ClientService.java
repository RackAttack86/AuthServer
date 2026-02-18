package com.rackleet.authserver.service;

import java.net.URI;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.rackleet.authserver.dto.request.ClientRegistrationRequest;
import com.rackleet.authserver.dto.response.ClientInfoResponse;
import com.rackleet.authserver.dto.response.ClientRegistrationResponse;
import com.rackleet.authserver.entity.OAuthClient;
import com.rackleet.authserver.exception.OAuthError;
import com.rackleet.authserver.exception.OAuthException;
import com.rackleet.authserver.repository.OAuthClientRepository;
import com.rackleet.authserver.util.JsonUtils;

@Service
public class ClientService {
    
    private static final Set<String> VALID_GRANT_TYPES = Set.of(
        "authorization_code",
        "client_credentials",
        "refresh_token",
        "device_code"
    );

    private static final Set<String> VALID_AUTH_METHODS = Set.of(
        "client_secret_basic",
        "client_secret_post",
        "none"
    );

    private final OAuthClientRepository clientRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public ClientService(OAuthClientRepository clientRepository, BCryptPasswordEncoder passwordEncoder) {
            this.clientRepository = clientRepository;
            this.passwordEncoder = passwordEncoder;
    }

    public ClientRegistrationResponse registerClient(ClientRegistrationRequest request) {
        // Validate client type
        if (!"confidential".equals(request.getClientType()) 
            && !"public".equals(request.getClientType())) {
        throw new OAuthException(OAuthError.INVALID_REQUEST, "client_type must be 'confidential' or 'public'", HttpStatus.BAD_REQUEST);
        }

        // Validate grant types
        for (String grantType : request.getAllowedGrantTypes()) {
            if (!VALID_GRANT_TYPES.contains(grantType)) {
                throw new OAuthException(OAuthError.INVALID_REQUEST, "Unsupported grant type: " + grantType, HttpStatus.BAD_REQUEST);
            }
        }

        // Determine and validate auth method
        String authMethod = resolveAuthMethod(request);

        // Validate redirect URIs
        if (request.getRedirectUris() != null) {
            for (String uri : request.getRedirectUris()) {
                validateRedirectUri(uri);
            }
        }

        // Enforce public client rules
        boolean requirePkce;
        if ("public".equals(request.getClientType())) {
            if (!"none".equals(authMethod)) {
                throw new OAuthException(OAuthError.INVALID_REQUEST, "Public clients must use token_endpoints_auth_method 'none'", HttpStatus.BAD_REQUEST);
            } 
            requirePkce = true; // always forced for public clients
        } else {
            requirePkce = false; // confidential clients can opt in
        }

        // Generate client_id and secret
        String clientId = UUID.randomUUID().toString();
        String rawSecret = null;
        String secretHash = null;

        if ("confidential".equals(request.getClientType())) {
            rawSecret = generateClientSecret();
            secretHash = passwordEncoder.encode(rawSecret);
        }

        // Build and save the entity
        OAuthClient client = new OAuthClient();
        client.setClientId(clientId);
        client.setClientSecretHash(secretHash);
        client.setClientName(request.getClientName());
        client.setClientType(request.getClientType());
        client.setRedirectUris(JsonUtils.toJson(request.getRedirectUris()));
        client.setAllowedGrantTypes(JsonUtils.toJson(request.getAllowedGrantTypes()));
        client.setAllowedScopes(JsonUtils.toJson(
                request.getAllowedScopes() != null ? request.getAllowedScopes() : List.of()));
        client.setTokenEndpointAuthMethod(authMethod);
        client.setRequirePkce(requirePkce);
        client.setAccessTokenTtlSeconds(
                request.getAccessTokenTtlSeconds() != null
                        ? request.getAccessTokenTtlSeconds()
                        : 3600);
        client.setRefreshTokenTtlSeconds(
                request.getRefreshTokenTtlSeconds() != null
                        ? request.getRefreshTokenTtlSeconds()
                        : 2592000);

        clientRepository.save(client);

        // Build response
        return buildRegistrationResponse(client, rawSecret);
    }

    public ClientInfoResponse getClient(String clientId) {
        OAuthClient client = findActiveClient(clientId);
        return buildInfoResponse(client);
    }

    public ClientInfoResponse updateClient(String clientId, ClientRegistrationRequest request) {
        OAuthClient client = findActiveClient(clientId);

        // Apply updates (validate same as registration)
        if (request.getClientName() != null) {
            client.setClientName(request.getClientName());
        }
        if (request.getRedirectUris() != null) {
            for (String uri : request.getRedirectUris()) {
                validateRedirectUri(uri);
            }
            client.setRedirectUris(JsonUtils.toJson(request.getRedirectUris()));
        }
        if (request.getAllowedGrantTypes() != null) {
            for (String grantType : request.getAllowedGrantTypes()) {
                if (!VALID_GRANT_TYPES.contains(grantType)) {
                    throw new OAuthException(OAuthError.INVALID_REQUEST, "Unsupported grant type: " + grantType, HttpStatus.BAD_REQUEST);
                }
            }
            client.setAllowedGrantTypes(JsonUtils.toJson(request.getAllowedGrantTypes()));
        }
        if (request.getAllowedScopes() != null) {
            client.setAllowedScopes(JsonUtils.toJson(request.getAllowedGrantTypes()));
        }
        if (request.getAllowedScopes() != null) {
            client.setAllowedScopes(JsonUtils.toJson(request.getAllowedScopes()));
        }
        if (request.getAccessTokenTtlSeconds() != null) {
            client.setAccessTokenTtlSeconds(request.getAccessTokenTtlSeconds());
        }
        if (request.getRefreshTokenTtlSeconds() != null) {
            client.setRefreshTokenTtlSeconds(request.getRefreshTokenTtlSeconds());
        }

        clientRepository.save(client);
        return buildInfoResponse(client);
    }

    public void deactivateClient(String clientId) {
        OAuthClient client = findActiveClient(clientId);
        client.setActive(false);
        clientRepository.save(client);
    }

    // --- Private Helpers ---
    private OAuthClient findActiveClient(String clientId) {
        return clientRepository.findByClientId(clientId)
            .filter(OAuthClient::isActive)
            .orElseThrow(() -> new OAuthException(OAuthError.INVALID_CLIENT,
                "Client not found: " + clientId,
                HttpStatus.NOT_FOUND));
    }

    private String resolveAuthMethod(ClientRegistrationRequest request) {
        String method = request.getTokenEndpointAuthMethod();
        if (method == null) {
            // Default per RFC 7591: client_secret_basic for confidential, none for public
            return "confidential".equals(request.getClientType())
                ? "client_secret_basic" : "none";
        }

        if(!VALID_AUTH_METHODS.contains(method)) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "Unsupported token_endpoint_auth_method" + method, HttpStatus.BAD_REQUEST);
        }

        return method;
    }

    private String generateClientSecret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private void validateRedirectUri(String uri) {
        URI parsed;
        try {
            parsed = URI.create(uri);
        } catch (IllegalArgumentException e) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "Invalid redirect URI: " + uri, HttpStatus.BAD_REQUEST);
        }

        // Must be aboslute
        if (!parsed.isAbsolute()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "Redirect URI must be absolute: " + uri, HttpStatus.BAD_REQUEST);
        }

        // No fragments allowed (spec requirement)
        if (parsed.getFragment() != null) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "Redirect URI must not contain a fragment: " + uri, HttpStatus.BAD_REQUEST);
        }

        // HTTPS required for non-localhost
        String host = parsed.getHost();
        if(!"localhost".equals(host)
                && !"127.0.0.1".equals(host)
                && !"https".equals(parsed.getScheme())) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "Redirect URI must use HTTPS (except for localhost): " + uri, HttpStatus.BAD_REQUEST);
        }
    }

    private ClientRegistrationResponse buildRegistrationResponse(
            OAuthClient client, String rawSecret) {
        ClientRegistrationResponse response = new ClientRegistrationResponse();
        response.setClientId(client.getClientId());
        response.setClientSecret(rawSecret);  // may be null for public clients
        response.setClientName(client.getClientName());
        response.setClientType(client.getClientType());
        response.setRedirectUris(JsonUtils.fromJson(client.getRedirectUris()));
        response.setAllowedGrantTypes(JsonUtils.fromJson(client.getAllowedGrantTypes()));
        response.setAllowedScopes(JsonUtils.fromJson(client.getAllowedScopes()));
        response.setTokenEndpointAuthMethod(client.getTokenEndpointAuthMethod());
        response.setRequirePkce(client.isRequirePkce());
        response.setAccessTokenTtlSeconds(client.getAccessTokenTtlSeconds());
        response.setRefreshTokenTtlSeconds(client.getRefreshTokenTtlSeconds());
        response.setCreatedAt(client.getCreatedAt());
        return response;
    }

    private ClientInfoResponse buildInfoResponse(OAuthClient client) {
        ClientInfoResponse response = new ClientInfoResponse();
        response.setClientId(client.getClientId());
        response.setClientName(client.getClientName());
        response.setClientType(client.getClientType());
        response.setRedirectUris(JsonUtils.fromJson(client.getRedirectUris()));
        response.setAllowedGrantTypes(JsonUtils.fromJson(client.getAllowedGrantTypes()));
        response.setAllowedScopes(JsonUtils.fromJson(client.getAllowedScopes()));
        response.setTokenEndpointAuthMethod(client.getTokenEndpointAuthMethod());
        response.setRequirePkce(client.isRequirePkce());
        response.setAccessTokenTtlSeconds(client.getAccessTokenTtlSeconds());
        response.setRefreshTokenTtlSeconds(client.getRefreshTokenTtlSeconds());
        response.setCreatedAt(client.getCreatedAt());
        response.setUpdatedAt(client.getUpdatedAt());
        return response;
    }    
}
