CREATE OR REPLACE FUNCTION webauthn.init_credential(username text)
RETURNS jsonb
LANGUAGE sql
AS $$
WITH new_challenge AS (
  INSERT INTO webauthn.challenges (username, challenge, relaying_party)
  VALUES (username, gen_random_bytes(32), webauthn.relaying_party())
  RETURNING challenge, relaying_party
)
SELECT jsonb_build_object(
  'publicKey', jsonb_build_object(
    'challenge', encode(challenge,'base64'),
    'rp', jsonb_build_object(
      'name', relaying_party,
      'id', relaying_party
    ),
    'user', jsonb_build_object(
      'name', username,
      'displayName', username,
      'id', encode(username::bytea,'base64')
    ),
    'pubKeyCredParams', jsonb_build_array(
      jsonb_build_object(
        'type', 'public-key',
        'alg', -7
      )
    ),
    'authenticatorSelection', jsonb_build_object(
      'requireResidentKey', false,
      'userVerification', 'discouraged'
    ),
    'timeout', 60000,
    'extensions', jsonb_build_object(
      'txAuthSimple', ''
    ),
    'attestation', 'none'
  )
) FROM new_challenge
$$;
