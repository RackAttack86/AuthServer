package com.rackleet.authserver.controller;

import com.rackleet.authserver.dto.request.AuthorizationRequest;
import com.rackleet.authserver.entity.OAuthClient;
import com.rackleet.authserver.entity.User;
import com.rackleet.authserver.exception.OAuthError;
import com.rackleet.authserver.exception.OAuthRedirectException;
import com.rackleet.authserver.service.AuthorizationService;
import com.rackleet.authserver.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;



@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthorizationController {
    
    private final AuthorizationService authorizationService;
    private final UserService userService;

    /**
     * Step 1: The entry point of the authorization code flow.
     * The client redirects the user's browser here with all the OAuth params.
     * 
     * If validation passes, shows the login form
     * Tier 1 errors (bad client/redirect) -> error page
     * Tier 2 errors (bad scope/response_type) -> redirect to client with error
     */
    @GetMapping("/oauth2/authorize")
    public ResponseEntity<String> authorize(
            @RequestParam(name = "response_type", required = false) String responseType,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "scope", required = false) String scope,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "code_challenge", required = false) String codeChallenge,
            @RequestParam(name = "code_challenge_method", required = false) String codeChallengeMethod) {
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setResponseType(responseType);
        authRequest.setClientId(clientId);
        authRequest.setRedirectUri(redirectUri);
        authRequest.setScope(scope);
        authRequest.setState(state);
        authRequest.setCodeChallenge(codeChallenge);
        authRequest.setCodeChallengeMethod(codeChallengeMethod);

        // Validates everything - throws Tier 1 or Tier 2 exceptions on failure
        OAuthClient client = authorizationService.validateAuthorizationRequest(authRequest);

        // Validation passed - show the login form with all params as hidden fields
        String loginPage = buildLoginPage(authRequest, client.getClientName(), null);
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(loginPage);
    }

    /**
     * Step 2: User submits the login form
     * Authenticates their credentials, then shows the consent form
     * 
     * If authentication fails, re-renders the login form with an error message
     */
    @PostMapping("/oauth2/authorize/login")
    public ResponseEntity<String> login(
        // The OAuth params carried forward as hidden form fields
            @RequestParam(name = "response_type") String responseType,
            @RequestParam(name = "client_id") String clientId,
            @RequestParam(name = "redirect_uri") String redirectUri,
            @RequestParam(name = "scope") String scope,
            @RequestParam(name = "state") String state,
            @RequestParam(name = "code_challenge") String codeChallenge,
            @RequestParam(name = "code_challenge_method") String codeChallengeMethod,
            // The user's credentials from the login form
            @RequestParam(name = "username") String username,
            @RequestParam(name = "password") String password) {
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setResponseType(responseType);
        authRequest.setClientId(clientId);
        authRequest.setRedirectUri(redirectUri);
        authRequest.setScope(scope);
        authRequest.setState(state);
        authRequest.setCodeChallenge(codeChallenge);
        authRequest.setCodeChallengeMethod(codeChallengeMethod);

        // Re-validate the OAuth params - never trust hidden form fields
        // A malicious user could modify them in the browser
        OAuthClient client = authorizationService.validateAuthorizationRequest(authRequest);

        // Authenticate the user
        User user;
        try {
            user = userService.authenticateUser(username, password);
        } catch (Exception e) {
            // Bad credentials - re-show login with error, do NOT redirect
            String loginPage = buildLoginPage(authRequest, client.getClientName(), "Invalid username or password");
            return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(loginPage);
        }

        // Authentication succeeded - show consent screen
        String consentPage = buildConsentPage(authRequest, client.getClientName(), user.getUsername(), user.getId());
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(consentPage);
    }
    
    /**
     * Step 3: User approves or denies consent
     * If approved, generates the authorization code and redirects to the client
     * If denied, redirects to the client with access_denied error
     */
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
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setResponseType(responseType);
        authRequest.setClientId(clientId);
        authRequest.setScope(scope);
        authRequest.setState(state);
        authRequest.setCodeChallenge(codeChallenge);
        authRequest.setCodeChallengeMethod(codeChallengeMethod);

        // Re-validate again - same reason as the login step
        authorizationService.validateAuthorizationRequest(authRequest);

        // User denied the request - redirect with access_denied error
        if (!"approve".equals(decision)) {
            throw new OAuthRedirectException(OAuthError.ACCESS_DENIED, "The resource owner denied the request", redirectUri, state);
        }

        // User approved - generate the authorization code
        String code = authorizationService.generateAuthorizationCode(authRequest, userId);

        // Build the redirect URI with code and state
        String redirectLocation = authorizationService.buildAuthorizationResponse(redirectUri, code, state);

        log.debug("Authorization code issued, redirecting to client");

        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(redirectLocation));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }
    
    // ---- HTML page builders -------------------

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

        // Carry the OAuth params through as hidden fields
        appendHiddenField(html, "response_type", request.getResponseType());
        appendHiddenField(html, "client_id", request.getClientId());
        appendHiddenField(html, "redirect_uri", request.getRedirectUri());
        appendHiddenField(html, "scope", request.getScope());
        appendHiddenField(html, "state", request.getState());
        appendHiddenField(html, "code_challenge", request.getCodeChallenge());
        appendHiddenField(html, "code_challenge_method", request.getCodeChallengeMethod());

        html.append("<label>Username: <input type='text' name='username' required/></label><br/><br/>");
        html.append("<label>Password: <input type='password' name='password' required/></label><br/><br/>");
        html.append("<button type='submit'>Sign In</button>");
        html.append("</form></body></html>");

        return html.toString();
    }

    private String buildConsentPage(AuthorizationRequest request,
                                    String clientName, String username, Long userId) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>Authorize</title></head><body>");
        html.append("<h2>Authorize Application</h2>");
        html.append("<p>Signed in as <strong>").append(escapeHtml(username)).append("</strong></p>");
        html.append("<p><strong>").append(escapeHtml(clientName))
            .append("</strong> is requesting the following permissions:</p>");

        // Show the requested scopes as a list
        if (request.getScope() != null && !request.getScope().isBlank()) {
            html.append("<ul>");
            for (String scope : request.getScope().split(" ")) {
                html.append("<li>").append(escapeHtml(scope)).append("</li>");
            }
            html.append("</ul>");
        }

        html.append("<form method='POST' action='/oauth2/authorize/consent'>");

        // Carry everything through again
        appendHiddenField(html, "response_type", request.getResponseType());
        appendHiddenField(html, "client_id", request.getClientId());
        appendHiddenField(html, "redirect_uri", request.getRedirectUri());
        appendHiddenField(html, "scope", request.getScope());
        appendHiddenField(html, "state", request.getState());
        appendHiddenField(html, "code_challenge", request.getCodeChallenge());
        appendHiddenField(html, "code_challenge_method", request.getCodeChallengeMethod());
        appendHiddenField(html, "user_id", String.valueOf(userId));

        html.append("<button type='submit' name='decision' value='approve'>Approve</button> ");
        html.append("<button type='submit' name='decision' value='deny'>Deny</button>");
        html.append("</form></body></html>");

        return html.toString();
    }

    /**
     * Appends a hidden form field, skipping null values.
     * These carry the OAuth parameters through the login/consent steps.
     */
    private void appendHiddenField(StringBuilder html, String name, String value) {
        if (value != null) {
            html.append("<input type='hidden' name='").append(escapeHtml(name))
                .append("' value='").append(escapeHtml(value)).append("'/>");
        }
    }

    /**
     * Basic HTML escaping to prevent XSS.
     * The client_name, scope values, and error messages could contain
     * malicious content — never insert them into HTML unescaped.
     */
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;");
    }
    
}
