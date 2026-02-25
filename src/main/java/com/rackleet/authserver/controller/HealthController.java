package com.rackleet.authserver.controller;

import org.springframework.web.bind.annotation.RestController;

import com.rackleet.authserver.entity.OAuthClient;
import com.rackleet.authserver.exception.OAuthError;
import com.rackleet.authserver.exception.OAuthException;
import com.rackleet.authserver.service.ClientAuthenticationService; 

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;


@RestController
@RequiredArgsConstructor
public class HealthController {

    private final ClientAuthenticationService clientAuthenticationService;

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "up");
    }

    @GetMapping("/test-error")
    public void testError() {
        throw new OAuthException(
                OAuthError.INVALID_CLIENT,
                "This is a test error",
                HttpStatus.UNAUTHORIZED);
    }

    // Temporary for testing. TODO: Remove this method after completed testing.
    @PostMapping("/test-client-auth")
    public Map<String, String> testClientAuth(HttpServletRequest request) {
        OAuthClient client = clientAuthenticationService.authenticateClient(request);
        return Map.of(
            "authenticated_client", client.getClientId(),
            "auth_method", client.getTokenEndpointAuthMethod()
        );
    }
    
}
