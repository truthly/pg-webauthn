CREATE TYPE webauthn.credential_type AS ENUM (
  'public-key'
);

COMMENT ON TYPE webauthn.credential_type IS 'https://www.w3.org/TR/webauthn-2/#enum-credentialType';
