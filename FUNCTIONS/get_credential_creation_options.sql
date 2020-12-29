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
