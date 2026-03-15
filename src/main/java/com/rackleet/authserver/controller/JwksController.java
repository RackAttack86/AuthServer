package com.rackleet.authserver.controller;

import com.nimbusds.jose.jwk.RSAKey;
import com.rackleet.authserver.crypto.KeyManager;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
@RequiredArgsConstructor
public class JwksController {
    
    private final KeyManager keyManager;

    @GetMapping("/oauth2/jwks")
    public ResponseEntity<Map<String, Object>> jwks() {

        // Get all public keys - private material already stripped by KeyManager
        Map<String, RSAKey> publicKeys = keyManager.getAllPublicKeys();

        // Convert each RSAKey into JSON
        // toJSONObject() produces the standard JWK format with
        // kty, use, kid, alg, n, e
        List<Map<String, Object>> keyList = publicKeys.values().stream()
            .map(RSAKey::toJSONObject)
            .collect(Collectors.toList());

        Map<String, Object> jwks = new LinkedHashMap<>();
        jwks.put("keys", keyList);

        // Cache for 1 hour. Public keys change rarely
        // caching is safe and reduces load
        // Resource servers typically cache JWKS responses and only re-fetch
        // when they encounter a kid they dont recognize
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .cacheControl(CacheControl.maxAge(java.time.Duration.ofHours(1)))
            .body(jwks);
    }
}
