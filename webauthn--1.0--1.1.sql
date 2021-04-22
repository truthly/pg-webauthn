-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION webauthn" to load this file. \quit
CREATE OR REPLACE FUNCTION webauthn.get_credential_creation_options(challenge bytea)
RETURNS jsonb
LANGUAGE sql
AS $$
SELECT
jsonb_build_object(
  'publicKey', jsonb_build_object(
    'rp', jsonb_strip_nulls(jsonb_build_object(
      'name', relying_party_name,
      'id', relying_party_id
    )),
    'user', jsonb_build_object(
      'name', user_name,
      'displayName', user_display_name,
      'id', webauthn.base64url_encode(user_id)
    ),
    'challenge', webauthn.base64url_encode(challenge),
    'pubKeyCredParams', jsonb_build_array(
      jsonb_build_object(
        'type', 'public-key',
        'alg', -7
      )
    ),
    'authenticatorSelection', jsonb_build_object(
      'requireResidentKey', require_resident_key,
      'userVerification', user_verification
    ),
    'timeout', (extract(epoch from timeout)*1000)::bigint,
    'attestation', attestation
  )
)
FROM webauthn.credential_challenges
WHERE credential_challenges.challenge = get_credential_creation_options.challenge
$$;
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
ALTER TABLE webauthn.credential_challenges ADD COLUMN require_resident_key boolean NOT NULL DEFAULT FALSE;
COMMENT ON COLUMN webauthn.credential_challenges.require_resident_key IS 'https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey';
