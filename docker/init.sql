-- init.sql

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    guid Varchar(40) NOT NULL UNIQUE,
    hashed_refresh_token Varchar(120) NOT NULL,
    expires_at TIMESTAMP,
    last_ip varchar(64)
);