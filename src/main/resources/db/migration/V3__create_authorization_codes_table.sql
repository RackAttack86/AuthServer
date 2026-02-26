-- V3__create_authorization_codes_table.sql
CREATE TABLE authorization_codes (
    id                    BIGSERIAL PRIMARY KEY,
    code_hash VARCHAR(64) NOT NULL,
    client_id VARCHAR(36) NOT NULL,
    user_id BIGINT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,

-- PKCE fields — stored at authorization time, verified at token time.
-- code_challenge is what the client sent initially.
-- code_verifier is what the client sends at the token endpoint.
-- We compare them to prove the same client that started the flow
-- is the one finishing it.
code_challenge VARCHAR(128),
code_challenge_method VARCHAR(10),

-- Authorization codes are short-lived: 10 minutes max per spec.
expires_at TIMESTAMP NOT NULL,

-- Single-use enforcement. Once exchanged, never accepted again.
-- If a used code is presented a second time, we must revoke all
-- tokens issued from it (spec requirement, security critical).
is_used               BOOLEAN       NOT NULL DEFAULT FALSE,

    created_at            TIMESTAMP     NOT NULL DEFAULT NOW()
);

-- We look up codes by hash on every token exchange request
CREATE INDEX idx_authorization_codes_code_hash ON authorization_codes (code_hash);

-- Clean up expired codes periodically
CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes (expires_at);