package com.rackleet.authserver.exception;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<Map<String, String>> handleOAuthException(OAuthException ex) {
        Map<String, String> body = new LinkedHashMap<>(); // Linked hashmap preserves insertion order
        body.put("error", ex.getError().getCode());
        body.put("error_description", ex.getErrorDescription());
        return ResponseEntity.status(ex.getHttpStatus()).body(body);
    }
}
