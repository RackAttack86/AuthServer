package com.rackleet.authserver.exception;

public enum OAuthError {
    INVALID_REQUEST("invalid_request"),
    INVALID_CLIENT("invalid_client"),
    INVALID_GRANT("invalid_grant"),
    UNAUTHORIZED_CLIENT("unauthorized_client"),
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),
    INVALID_SCOPE("invalid_scope"),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),
    ACCESS_DENIED("access_denied"),
    SERVER_ERROR("server_error"),
    // OIDC-specific (you'll use these in Phase 5)
    LOGIN_REQUIRED("login_required"),
    CONSENT_REQUIRED("consent_required"),
    INTERACTION_REQUIRED("interaction_required");

    private final String code;

    OAuthError(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
