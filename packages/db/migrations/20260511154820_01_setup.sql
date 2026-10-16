-- Add migration script here

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- CREATE USER TABLE
CREATE TABLE users 
(
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  username VARCHAR(16) NOT NULL UNIQUE,
  password TEXT NOT NULL,
  name VARCHAR(32) NOT NULL,
  
  email_hash TEXT NOT NULL,
  email_encrypted BYTEA NOT NULL,
  contact_hash TEXT,
  contact_encrypted BYTEA,

  revoked_at timestamptz,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);


-- CREATE OAUTHIDENTITY TABLE
CREATE TYPE auth_provider AS ENUM ('gmail');

CREATE TABLE oauth_identity 
(
  user_id UUID NOT NULL,
  provider auth_provider NOT NULL DEFAULT 'gmail',
  is_verified BOOLEAN,
  image TEXT,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT fk_users_id
  FOREIGN KEY (user_id)
  REFERENCES users(id)
  ON DELETE CASCADE
);


-- CREATE REFRESH TABLE
CREATE TABLE refresh_token 
(
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  replaces_by_token_id TEXT NULL,
  user_agent TEXT,
  created_by_ip TEXT NOT NULL,
  last_used_ip TEXT NOT NULL,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT fk_users
  FOREIGN KEY (user_id)
  REFERENCES users(id)
  ON DELETE CASCADE
);


-- CREATE PROFILE TABLE
/* 
CREATE TABLE profile 
(
  user_id UUID NOT NULL REFERENCES users (id),
  -- space_id UUID NOT NULL REFERENCES space(id),
  display_name VARCHAR(16) NOT NULL,
  bio TEXT,
  -- character ENUM(),
  public_key TEXT NOT NULL,
  -- status ENUM(),
  -- audio_status ENUM(),
  -- video_status ENUM(),

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
*/

