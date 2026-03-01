package com.rackleet.authserver.exception;

import lombok.Getter;

@Getter
public class OAuthRedirectException extends RuntimeException {
    
    private final OAuthError error;
    private final String errorDescription;
    private final String redirectUri;
    private final String state;

    public OAuthRedirectException(OAuthError error, String errorDescription, String redirectUri, String state) {
        super(errorDescription);
        this.error = error;
        this.errorDescription = errorDescription;
        this.redirectUri = redirectUri;
        this.state = state;
    }

    /**
     * Builds the full redirect URI with error parameters appended.
     * The client receives this and knows what went wrong.
     * 
     * Example output:
     * https://example.com/callback?error=invalid_scope
     * &error_description=Scope+not+allowed&state=abc123
     */
    public String buildRedirectUri() {
        StringBuilder uri = new StringBuilder(redirectUri);
        uri.append(redirectUri.contains("?") ? "&" : "?");
        uri.append("error=").append(error.getCode());

        if (errorDescription != null && !errorDescription.isBlank()) {
            uri.append("&error_description=").append(urlEncode(errorDescription));
        }

        if (state != null && !state.isBlank()) {
            uri.append("&state=").append(state);
        }

        return uri.toString();
    }

    private String urlEncode(String value) {
        try {
            return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
             return value;
        }
    }
}
