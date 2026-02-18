package com.rackleet.authserver.controller;

import org.springframework.web.bind.annotation.RestController;

import com.rackleet.authserver.exception.OAuthError;
import com.rackleet.authserver.exception.OAuthException;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;


@RestController
public class HealthController {
    
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "up");
    }

    @GetMapping("/test-error")
    public void testError() {
        throw new OAuthException(
            OAuthError.INVALID_CLIENT, "This is a test error", 
            HttpStatus.UNAUTHORIZED);
    }
    
    
}
