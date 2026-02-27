package com.rackleet.authserver.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class HashUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Generates a cryptographically random string suitable for
     * authorization codes, refresh tokens, and other bearer credentials.
     * 32 bytes = 256 bits of entropy, Base64url-encoded.
     */
    public static String generateRandomToke(){
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * SHA-256 hash, returned as a lowercase hex string.
     * Used for authorization codes and refresh tokens - credentials
     * that are high-entropy random strings (not user-chosen passwords),
     * so a fast hash is appropriate. Bcrypt would be overkill and
     * add unnecessary latency to every token exchange.
     */
    public static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Converts a byte array to a lowercase hex string.
     * SHA-256 produces 32 bytes -> 64 hex characters,
     * which matches the varchar(64) column size.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
    
}
