package com.rackleet.authserver.exception;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(OAuthRedirectException.class)
    public ResponseEntity<Void> handleOAuthRedirectException(OAuthRedirectException ex) {
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(ex.buildRedirectUri()));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<Map<String, String>> handleOAuthException(OAuthException ex) {
        Map<String, String> body = new LinkedHashMap<>(); // Linked hashmap preserves insertion order
        body.put("error", ex.getError().getCode());
        body.put("error_description", ex.getErrorDescription());
        return ResponseEntity.status(ex.getHttpStatus()).body(body);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(
        MethodArgumentNotValidException ex) {
            String message = ex.getBindingResult().getFieldErrors().stream().map(fe -> fe.getField() + ": " + fe.getDefaultMessage()).collect(Collectors.joining(", "));

            Map<String, String> body = new LinkedHashMap<>();
            body.put("error", OAuthError.INVALID_REQUEST.getCode());
            body.put("error_description", message);
            return ResponseEntity.badRequest().body(body);
        }
}
