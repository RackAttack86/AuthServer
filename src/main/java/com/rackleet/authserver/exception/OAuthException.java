package com.rackleet.authserver.exception;

import org.springframework.http.HttpStatus;

public class OAuthException extends RuntimeException{
    
    private final OAuthError error;
    private final String errorDescription;
    private final HttpStatus httpStatus;

    public OAuthException(OAuthError error, String errorDescription, HttpStatus httpStatus) {
        super(errorDescription);
        this.error = error;
        this.errorDescription = errorDescription;
        this.httpStatus = httpStatus;
    }

    public OAuthError getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
