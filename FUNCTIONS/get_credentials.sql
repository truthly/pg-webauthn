CREATE OR REPLACE FUNCTION webauthn.get_credentials(
  challenge bytea,
  relying_party_id text,
  user_name text,
  timeout interval
)
RETURNS jsonb
LANGUAGE sql
AS $$
WITH new_challenge AS (
  INSERT INTO webauthn.assertion_challenges (challenge, relying_party_id, user_name, timeout)
  VALUES (challenge, relying_party_id, user_name, timeout)
  RETURNING challenge
)
SELECT jsonb_build_object(
  'publicKey', jsonb_build_object(
    'userVerification', 'required',
    'extensions', jsonb_build_object(
      'txAuthSimple', ''
    ),
    'allowCredentials', jsonb_agg(
      jsonb_build_object(
        'type', 'public-key',
        'id', webauthn.base64url_encode(credentials.credential_id)
      )
    ORDER BY credentials.credential_id),
    'timeout', (extract(epoch from get_credentials.timeout)*1000)::bigint, -- milliseconds
    'challenge', webauthn.base64url_encode(new_challenge.challenge),
    'rpId', get_credentials.relying_party_id
  )
)
FROM new_challenge
JOIN webauthn.credential_challenges ON credential_challenges.relying_party_id = get_credentials.relying_party_id
                                   AND credential_challenges.user_name         = get_credentials.user_name
JOIN webauthn.credentials ON credentials.challenge = credential_challenges.challenge
GROUP BY new_challenge.challenge, get_credentials.relying_party_id, get_credentials.timeout
$$;
