-- V6__create_scopes_table.sql

CREATE TABLE scopes ( id BIGSERIAL PRIMARY KEY,

-- The scope string used in OAuth requests.
-- Convention: "resource:action" for fine-grained permissions.
-- Examples: "openid", "profile", "email", "users:read", "users:write"
name VARCHAR(100) NOT NULL,

-- Human-readable description shown on the consent screen.
-- "View your basic profile information"
-- "Read your email address"
description VARCHAR(500),

-- If true, this scope is granted when the client requests no scope.
-- Typically only "openid" or a basic read scope would be default.
is_default  BOOLEAN       NOT NULL DEFAULT FALSE,

    created_at  TIMESTAMP     NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_scopes_name ON scopes (name);

-- Seed the standard scopes we've been using.
-- These are the OIDC standard scopes plus some resource scopes
-- for testing with the resource server in Phase 7.
INSERT INTO
    scopes (name, description, is_default)
VALUES (
        'openid',
        'Verify your identity',
        true
    ),
    (
        'profile',
        'View your basic profile information',
        false
    ),
    (
        'email',
        'View your email address',
        false
    ),
    (
        'read:resources',
        'Read resources on your behalf',
        false
    ),
    (
        'write:resources',
        'Create and modify resources on your behalf',
        false
    );