ALTER TABLE webauthn.credential_challenges ADD COLUMN require_resident_key boolean NOT NULL DEFAULT FALSE;
