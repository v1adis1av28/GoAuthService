-- init.sql

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    guid Varchar(255) NOT NULL UNIQUE,
    hashed_refresh_token Varchar(255) NOT NULL,
    expires_at TIMESTAMP
);