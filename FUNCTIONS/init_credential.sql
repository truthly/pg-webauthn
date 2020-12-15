CREATE OR REPLACE FUNCTION webauthn.init_credential(
  challenge bytea,
  user_name text,
  user_id bytea,
  user_display_name text,
  relying_party_name text,
  relying_party_id text DEFAULT NULL,
  user_verification webauthn.user_verification_requirement DEFAULT 'preferred',
  attestation webauthn.attestation_conveyance_preference DEFAULT 'none',
  timeout interval DEFAULT '5 minutes'::interval,
  challenge_at timestamptz DEFAULT now()
)
RETURNS jsonb
LANGUAGE sql
AS $$
INSERT INTO webauthn.credential_challenges
       (challenge, user_name, user_id, user_display_name, relying_party_name, relying_party_id, user_verification, attestation, timeout, challenge_at)
VALUES (challenge, user_name, user_id, user_display_name, relying_party_name, relying_party_id, user_verification, attestation, timeout, challenge_at)
RETURNING
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
      'requireResidentKey', false,
      'userVerification', user_verification
    ),
    'timeout', (extract(epoch from timeout)*1000)::bigint,
    'attestation', attestation
  )
)
$$;
