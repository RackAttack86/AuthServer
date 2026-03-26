package com.rackleet.authserver.controller;

import com.rackleet.authserver.dto.request.AuthorizationRequest;
import com.rackleet.authserver.entity.OAuthClient;
import com.rackleet.authserver.entity.User;
import com.rackleet.authserver.exception.OAuthError;
import com.rackleet.authserver.exception.OAuthRedirectException;
import com.rackleet.authserver.service.AuthorizationService;
import com.rackleet.authserver.service.ConsentService;
import com.rackleet.authserver.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthorizationController {

    private final AuthorizationService authorizationService;
    private final ConsentService consentService;
    private final UserService userService;

    @GetMapping("/oauth2/authorize")
    public ResponseEntity<String> authorize(
            @RequestParam(name = "response_type", required = false) String responseType,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "scope", required = false) String scope,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "code_challenge", required = false) String codeChallenge,
            @RequestParam(name = "code_challenge_method", required = false) String codeChallengeMethod) {

        AuthorizationRequest authRequest = buildAuthRequest(
                responseType, clientId, redirectUri, scope, state,
                codeChallenge, codeChallengeMethod);

        OAuthClient client = authorizationService.validateAuthorizationRequest(authRequest);

        // After validation, scope may have been updated with defaults
        String loginPage = buildLoginPage(authRequest, client.getClientName(), null);
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body(loginPage);
    }

    @PostMapping("/oauth2/authorize/login")
    public ResponseEntity<String> login(
            @RequestParam(name = "response_type") String responseType,
            @RequestParam(name = "client_id") String clientId,
            @RequestParam(name = "redirect_uri") String redirectUri,
            @RequestParam(name = "scope", required = false) String scope,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "code_challenge", required = false) String codeChallenge,
            @RequestParam(name = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(name = "username") String username,
            @RequestParam(name = "password") String password) {

        AuthorizationRequest authRequest = buildAuthRequest(
                responseType, clientId, redirectUri, scope, state,
                codeChallenge, codeChallengeMethod);

        OAuthClient client = authorizationService.validateAuthorizationRequest(authRequest);

        User user;
        try {
            user = userService.authenticateUser(username, password);
        } catch (Exception e) {
            String loginPage = buildLoginPage(authRequest, client.getClientName(),
                    "Invalid username or password");
            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_HTML)
                    .body(loginPage);
        }

        // Check if user has already consented to these scopes
        if (authorizationService.hasExistingConsent(
                user.getId(), client.getClientId(), authRequest.getScope())) {
            // Consent exists — skip the consent screen, generate code directly
            log.debug("Existing consent found for user '{}', client '{}'. Skipping consent screen.",
                    user.getUsername(), client.getClientId());

            String code = authorizationService.approveAndGenerateCode(authRequest, user.getId());
            String redirectLocation = authorizationService.buildAuthorizationResponse(
                    authRequest.getRedirectUri(), code, authRequest.getState());

            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI.create(redirectLocation));
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        }

        // No existing consent — show the consent screen with scope descriptions
        String consentPage = buildConsentPage(authRequest, client.getClientName(),
                user.getUsername(), user.getId());
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body(consentPage);
    }

    @PostMapping("/oauth2/authorize/consent")
    public ResponseEntity<Void> consent(
            @RequestParam(name = "response_type") String responseType,
            @RequestParam(name = "client_id") String clientId,
            @RequestParam(name = "redirect_uri") String redirectUri,
            @RequestParam(name = "scope", required = false) String scope,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "code_challenge", required = false) String codeChallenge,
            @RequestParam(name = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(name = "user_id") Long userId,
            @RequestParam(name = "decision") String decision) {

        AuthorizationRequest authRequest = buildAuthRequest(
                responseType, clientId, redirectUri, scope, state,
                codeChallenge, codeChallengeMethod);

        authorizationService.validateAuthorizationRequest(authRequest);

        if (!"approve".equals(decision)) {
            throw new OAuthRedirectException(
                    OAuthError.ACCESS_DENIED,
                    "The resource owner denied the request",
                    redirectUri,
                    state);
        }

        // User approved — save consent and generate code
        String code = authorizationService.approveAndGenerateCode(authRequest, userId);

        String redirectLocation = authorizationService.buildAuthorizationResponse(
                redirectUri, code, state);

        log.debug("Authorization code issued, redirecting to client");

        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(redirectLocation));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    // ── Helper to reduce duplication ────────────────────────────

    private AuthorizationRequest buildAuthRequest(
            String responseType, String clientId, String redirectUri,
            String scope, String state, String codeChallenge,
            String codeChallengeMethod) {
        AuthorizationRequest request = new AuthorizationRequest();
        request.setResponseType(responseType);
        request.setClientId(clientId);
        request.setRedirectUri(redirectUri);
        request.setScope(scope);
        request.setState(state);
        request.setCodeChallenge(codeChallenge);
        request.setCodeChallengeMethod(codeChallengeMethod);
        return request;
    }

    // ── HTML page builders ──────────────────────────────────────

    private String buildLoginPage(AuthorizationRequest request,
            String clientName, String errorMessage) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>Login</title></head><body>");
        html.append("<h2>Sign in</h2>");
        html.append("<p><strong>").append(escapeHtml(clientName))
                .append("</strong> is requesting access to your account.</p>");

        if (errorMessage != null) {
            html.append("<p style='color:red;'>").append(escapeHtml(errorMessage)).append("</p>");
        }

        html.append("<form method='POST' action='/oauth2/authorize/login'>");

        appendHiddenFields(html, request);

        html.append("<label>Username: <input type='text' name='username' required/></label><br/><br/>");
        html.append("<label>Password: <input type='password' name='password' required/></label><br/><br/>");
        html.append("<button type='submit'>Sign In</button>");
        html.append("</form></body></html>");

        return html.toString();
    }

    private String buildConsentPage(AuthorizationRequest request,
            String clientName, String username, Long userId) {
        // Look up human-readable descriptions for each scope
        Map<String, String> scopeDescriptions = consentService
                .getScopeDescriptions(request.getScope());

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>Authorize</title></head><body>");
        html.append("<h2>Authorize Application</h2>");
        html.append("<p>Signed in as <strong>").append(escapeHtml(username)).append("</strong></p>");
        html.append("<p><strong>").append(escapeHtml(clientName))
                .append("</strong> is requesting the following permissions:</p>");

        if (request.getScope() != null && !request.getScope().isBlank()) {
            html.append("<ul>");
            for (String scope : request.getScope().split(" ")) {
                String description = scopeDescriptions.getOrDefault(scope, scope);
                html.append("<li><strong>").append(escapeHtml(scope))
                        .append("</strong> — ").append(escapeHtml(description))
                        .append("</li>");
            }
            html.append("</ul>");
        }

        html.append("<form method='POST' action='/oauth2/authorize/consent'>");

        appendHiddenFields(html, request);
        appendHiddenField(html, "user_id", String.valueOf(userId));

        html.append("<button type='submit' name='decision' value='approve'>Approve</button> ");
        html.append("<button type='submit' name='decision' value='deny'>Deny</button>");
        html.append("</form></body></html>");

        return html.toString();
    }

    private void appendHiddenFields(StringBuilder html, AuthorizationRequest request) {
        appendHiddenField(html, "response_type", request.getResponseType());
        appendHiddenField(html, "client_id", request.getClientId());
        appendHiddenField(html, "redirect_uri", request.getRedirectUri());
        appendHiddenField(html, "scope", request.getScope());
        appendHiddenField(html, "state", request.getState());
        appendHiddenField(html, "code_challenge", request.getCodeChallenge());
        appendHiddenField(html, "code_challenge_method", request.getCodeChallengeMethod());
    }

    private void appendHiddenField(StringBuilder html, String name, String value) {
        if (value != null) {
            html.append("<input type='hidden' name='").append(escapeHtml(name))
                    .append("' value='").append(escapeHtml(value)).append("'/>");
        }
    }

    private String escapeHtml(String input) {
        if (input == null)
            return "";
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }
}