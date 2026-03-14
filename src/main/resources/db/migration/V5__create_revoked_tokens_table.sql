-- V5__create_revoked_tokens_table.sql

-- Tracks revoked JWT access tokens by their jti (JWT ID) claim.
--
-- JWTs are stateless — once issued, they're valid until expiration.
-- The only way to "revoke" a JWT before expiration is to maintain
-- a server-side list of revoked token IDs and check it during
-- introspection or resource server validation.
--
-- This table only needs to hold entries until the JWT expires.
-- After expiration, the token is invalid regardless, so the
-- entry can be cleaned up.

CREATE TABLE revoked_tokens (
    id              BIGSERIAL     PRIMARY KEY,

-- The jti (JWT ID) claim from the access token.
-- This is the UUID we embed in every JWT.
jti VARCHAR(36) NOT NULL,

-- When the original JWT expires.
-- Once this time passes, the entry is useless and can be deleted.
-- Keeps the table from growing unbounded.
expires_at      TIMESTAMP     NOT NULL,

    revoked_at      TIMESTAMP     NOT NULL DEFAULT NOW()
);

-- Every introspection request checks this table
CREATE UNIQUE INDEX idx_revoked_tokens_jti ON revoked_tokens (jti);

-- For periodic cleanup of expired entries
CREATE INDEX idx_revoked_tokens_expires_at ON revoked_tokens (expires_at);