CREATE TABLE oauth_clients (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(36) NOT NULL,
    client_secret_hash VARCHAR(72), -- bcrypt output is 60 chars, leave room
    client_name VARCHAR(255) NOT NULL,
    client_type VARCHAR(20) NOT NULL, -- 'confidential' or 'public'
    redirect_uris TEXT, -- JSON array of URIs
    allowed_grant_types TEXT NOT NULL, -- JSON array
    allowed_scopes TEXT, -- JSON array
    token_endpoint_auth_method VARCHAR(30) NOT NULL DEFAULT 'client_secret_basic',
    require_pkce BOOLEAN NOT NULL DEFAULT FALSE,
    access_token_ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    refresh_token_ttl_seconds INTEGER NOT NULL DEFAULT 2592000,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_oauth_clients_client_id ON oauth_clients (client_id);