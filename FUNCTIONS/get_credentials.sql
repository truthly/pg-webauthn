CREATE OR REPLACE FUNCTION webauthn.get_credentials(username text)
RETURNS jsonb
LANGUAGE sql
AS $$
WITH new_challenge AS (
  INSERT INTO webauthn.challenges (username, relaying_party)
  VALUES (username, webauthn.relaying_party())
  RETURNING challenge, relaying_party
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
    'rpId', new_challenge.relaying_party
  )
)
FROM new_challenge
JOIN webauthn.challenges ON challenges.username       = get_credentials.username
                        AND challenges.relaying_party = new_challenge.relaying_party
JOIN webauthn.credentials ON credentials.challenge_id = challenges.challenge_id
GROUP BY new_challenge.challenge, new_challenge.relaying_party
$$;
