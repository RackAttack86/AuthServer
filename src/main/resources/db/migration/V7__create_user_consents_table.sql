-- V7__create_user_consents_table.sql

-- Tracks which users have approved which clients for which scopes.
-- When a user approves a client on the consent screen, we store the
-- decision here. On subsequent authorization requests for the same
-- client and scopes, we skip the consent screen.


CREATE TABLE user_consents (
    id              BIGSERIAL     PRIMARY KEY,

    user_id         BIGINT        NOT NULL,
    client_id       VARCHAR(36)   NOT NULL,

-- Space-delimited scopes the user approved.
-- If the client requests the same or fewer scopes next time,
-- we skip the consent screen. If new scopes are added,
-- we show consent again for the new ones.
granted_scopes  TEXT          NOT NULL,

    created_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP     NOT NULL DEFAULT NOW()
);

-- Primary lookup: "has this user consented to this client?"
-- Unique constraint ensures one consent record per user/client pair.
CREATE UNIQUE INDEX idx_user_consents_user_client ON user_consents (user_id, client_id);