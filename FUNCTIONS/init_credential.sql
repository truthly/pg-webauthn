CREATE OR REPLACE FUNCTION webauthn.init_credential(
  challenge bytea,
  user_name text,
  user_id bytea,
  user_display_name text,
  relying_party_name text,
  relying_party_id text DEFAULT NULL,
  require_resident_key boolean DEFAULT FALSE,
  user_verification webauthn.user_verification_requirement DEFAULT 'preferred',
  attestation webauthn.attestation_conveyance_preference DEFAULT 'none',
  timeout interval DEFAULT '5 minutes'::interval,
  challenge_at timestamptz DEFAULT now()
)
RETURNS jsonb
LANGUAGE sql
AS $$
INSERT INTO webauthn.credential_challenges
       (challenge, user_name, user_id, user_display_name, relying_party_name, relying_party_id, require_resident_key, user_verification, attestation, timeout, challenge_at)
VALUES (challenge, user_name, user_id, user_display_name, relying_party_name, relying_party_id, require_resident_key, user_verification, attestation, timeout, challenge_at)
RETURNING webauthn.get_credential_creation_options(challenge)
$$;
