package com.rackleet.authserver.crypto;

import com.nimbusds.jose.jwk.RSAKey;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Slf4j
public class KeyManager {

    // All key pairs indexed by kid (Key ID).
    // ConcurrentHashMap for key rotation may add
    // keys while token signing and JWKS requests are reading.
    private final Map<String, RSAKey> keys = new ConcurrentHashMap<>();

    // The kid of the current signing key.
    // New tokens are always signed with this key.
    // Old keys stay in the map so existing tokens can still be verified
    private String currentKid;
    
    /**
     * Generates the initial signing key on application startup.
     * In production, we would load the keys from a database, file, or KMS.
     * For this project, generating on startup is fine but means all tokens become unverifiable when the server restarts.
     */
    @PostConstruct
    public void init() {
        generateNewKeyPair();
        log.info("RSA signing key generated with kid '{}'");
    }

    /**
     * Returns the current signing key (with private key) for creating JWTs
     * Only the token service should call this
     */
    public RSAKey getSigningKey() {
        return keys.get(currentKid);
    }

    /**
     * Returns a specific key by kid for signature verification
     * Resource servers send the kid from the JWT header to look up
     * the correct public key
     */
    public RSAKey getKeyById(String kid) {
        return keys.get(kid);
    }

    /**
     * Returns all public keys for the JWKS endpoint
     * Private key material is stripped - only public keys are exposed
     * This is what resource servers fetch to verify token signatures
     */
    public Map<String, RSAKey> getAllPublicKeys() {
        Map<String, RSAKey> publicKeys = new ConcurrentHashMap<>();
        for (Map.Entry<String, RSAKey> entry: keys.entrySet()) {
            // .toPublicJWK() strips the private key, leaving only the public components
            // (modulus n and exponent e)
            publicKeys.put(entry.getKey(), entry.getValue().toPublicJWK());
        }
        return publicKeys;
    }

    /**
     * Generates a new RSA key pair and makes it the current signing key
     * The old key stays in the map for verification of existing tokens
     * Called at startup and during key rotation
     */
    public String generateNewKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

            // 2048-bit is the minimum for RS256
            generator.initialize(2048);

            KeyPair keyPair = generator.generateKeyPair();

            // Generate a unique kid for resource server identification
            // Format: "key-{uuid}" for readability
            String kid = "key-" + UUID.randomUUID();

            // Build the Nimbus RSAKey with both public and private components
            // keyUse(KeyUse.SIGNATURE) marks it for signing, not encryption
            // algorithm(JWSAlgorithm.RS256) declares the intended algorithm
            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(kid)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                .build();

            keys.put(kid, rsaKey);
            currentKid = kid;

            return kid;
        } catch (NoSuchAlgorithmException e) {
            // RSA is guaranteed to be available in every JVM
            throw new RuntimeException("RSA not available", e);
        }
    }

    /**
     * Returns the current signing key's kid.
     * Used by the token service to set the kid header in JWTs
     */
    public String getCurrentKid() {
        return currentKid;
    }
}
