CREATE OR REPLACE FUNCTION webauthn.get_credentials(
  challenge bytea,
  user_name text DEFAULT NULL,
  user_verification webauthn.user_verification_requirement DEFAULT 'preferred',
  timeout interval DEFAULT '5 minutes'::interval,
  relying_party_id text DEFAULT NULL,
  challenge_at timestamptz DEFAULT now()
)
RETURNS jsonb
LANGUAGE sql
AS $$
WITH store_assertion_challenge AS (
  INSERT INTO webauthn.assertion_challenges
         (challenge, user_name, user_verification, timeout, relying_party_id, challenge_at)
  VALUES (challenge, user_name, user_verification, timeout, relying_party_id, challenge_at)
  RETURNING TRUE
)
SELECT jsonb_build_object(
  'publicKey', jsonb_strip_nulls(jsonb_build_object(
    'userVerification', get_credentials.user_verification,
    'allowCredentials', jsonb_agg(
      jsonb_build_object(
        'type', credentials.credential_type,
        'id', webauthn.base64url_encode(credentials.credential_id)
      )
    ORDER BY credentials.credential_id),
    'timeout', (extract(epoch from get_credentials.timeout)*1000)::bigint,
    'challenge', webauthn.base64url_encode(get_credentials.challenge),
    'rpId', get_credentials.relying_party_id
  ))
)
FROM store_assertion_challenge
LEFT JOIN webauthn.credentials ON credentials.user_name = get_credentials.user_name
GROUP BY get_credentials.challenge,
         get_credentials.relying_party_id,
         get_credentials.timeout,
         get_credentials.user_verification
$$;
