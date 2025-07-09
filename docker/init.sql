-- init.sql

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    guid Varchar(40) NOT NULL UNIQUE,
    hashed_refresh_token Varchar(120) NOT NULL,
    expires_at TIMESTAMP,
    last_ip varchar(64)
);

CREATE TABLE IF NOT EXISTS user_tokens(
    id SERIAL PRIMARY KEY,
    GUID VARCHAR(40) NOT NULL,
    hashed_refresh_token VARCHAR(120) NOT NULL,
    hashed_access_token VARCHAR(120) NOT NULL
);