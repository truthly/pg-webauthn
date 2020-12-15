CREATE TYPE webauthn.attestation_conveyance_preference AS ENUM (
  'none',
  'indirect',
  'direct',
  'enterprise'
);

COMMENT ON TYPE webauthn.attestation_conveyance_preference IS 'https://www.w3.org/TR/webauthn-2/#enum-attestation-convey';
