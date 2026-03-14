-- V4__create_refresh_tokens_table.sql

CREATE TABLE refresh_tokens (
    id                BIGSERIAL     PRIMARY KEY,

-- SHA-256 hash of the token value.
-- Same pattern as authorization codes: we never store plaintext.
token_hash VARCHAR(64) NOT NULL,

-- Which client and user this token belongs to
client_id VARCHAR(36) NOT NULL,
user_id BIGINT NOT NULL,

-- The scopes granted with this token.
-- When refreshing, scope can be maintained or narrowed, never expanded.
scope TEXT,
expires_at TIMESTAMP NOT NULL,
is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
created_at TIMESTAMP NOT NULL DEFAULT NOW(),

-- Tracks the token family for rotation and reuse detection.
-- When a refresh token is rotated, the new token points back
-- to the original. If a revoked token from this family is
-- presented, we revoke ALL tokens in the family.
parent_token_hash VARCHAR(64) );

-- Primary lookup: hash the incoming token, find the row
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens (token_hash);

-- For reuse detection: find all tokens in a family
CREATE INDEX idx_refresh_tokens_parent ON refresh_tokens (parent_token_hash);

-- For cleanup: find expired tokens
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);