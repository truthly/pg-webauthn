CREATE OR REPLACE FUNCTION webauthn.get_credentials(username text, relaying_party text)
RETURNS jsonb
LANGUAGE sql
AS $$
WITH new_challenge AS (
  INSERT INTO webauthn.challenges (username, relaying_party)
  VALUES (username, relaying_party)
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
        'id', encode(credentials.credential_raw_id,'base64')
      )
    ORDER BY credentials.credential_id DESC),
    'timeout', 60000,
    'challenge', encode(new_challenge.challenge,'base64'),
    'rpId', relaying_party
  )
)
FROM new_challenge
JOIN webauthn.challenges ON challenges.username       = get_credentials.username
                        AND challenges.relaying_party = get_credentials.relaying_party
JOIN webauthn.credentials ON credentials.challenge_id = challenges.challenge_id
GROUP BY new_challenge.challenge, relaying_party
$$;
