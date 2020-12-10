CREATE OR REPLACE FUNCTION webauthn.init_credential(
  challenge bytea,
  relying_party_name text,
  relying_party_id text,
  user_name text,
  user_id bytea,
  user_display_name text,
  timeout interval
)
RETURNS jsonb
LANGUAGE sql
AS $$
-- https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions
WITH new_challenge AS (
  INSERT INTO webauthn.credential_challenges (challenge, relying_party_name, relying_party_id, user_name, user_id, user_display_name, timeout)
  VALUES (challenge, relying_party_name, relying_party_id, user_name, user_id, user_display_name, timeout)
  RETURNING TRUE
)
SELECT jsonb_build_object(
  'publicKey', jsonb_build_object(
    'rp', jsonb_build_object(
      'name', relying_party_name,
      'id', relying_party_id
    ),
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
      'userVerification', 'discouraged'
    ),
    'timeout', (extract(epoch from timeout)*1000)::bigint, -- milliseconds
    'extensions', jsonb_build_object(
      'txAuthSimple', ''
    ),
    'attestation', 'none'
  )
) FROM new_challenge
$$;
