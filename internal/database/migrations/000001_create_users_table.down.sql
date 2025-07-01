CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    guid UUID NOT NULL UNIQUE,
    hashed_refresh_token TEXT NOT NULL
);
