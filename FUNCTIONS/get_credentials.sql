CREATE OR REPLACE FUNCTION webauthn.get_credentials(
  challenge bytea,
  user_name text,
  user_verification webauthn.user_verification_requirement DEFAULT 'preferred',
  timeout interval DEFAULT '5 minutes'::interval,
  relying_party_id text DEFAULT NULL,
  challenge_at timestamptz DEFAULT now(),
  tx_auth_simple text DEFAULT NULL,
  tx_auth_generic_content_type text DEFAULT NULL,
  tx_auth_generic_content bytea DEFAULT NULL
)
RETURNS jsonb
LANGUAGE sql
AS $$
WITH store_assertion_challenge AS (
  INSERT INTO webauthn.assertion_challenges
         (challenge, user_name, user_verification, timeout, relying_party_id, challenge_at, tx_auth_simple, tx_auth_generic_content_type, tx_auth_generic_content)
  VALUES (challenge, user_name, user_verification, timeout, relying_party_id, challenge_at, tx_auth_simple, tx_auth_generic_content_type, tx_auth_generic_content)
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
  )) ||
  jsonb_strip_nulls(
    jsonb_build_object(
      'extensions',
      NULLIF(
        jsonb_strip_nulls(jsonb_build_object(
          'txAuthSimple',
          get_credentials.tx_auth_simple
        )) ||
        jsonb_strip_nulls(jsonb_build_object(
            'txAuthGeneric',
            NULLIF(jsonb_strip_nulls(
              jsonb_build_object(
                'contentType',
                get_credentials.tx_auth_generic_content_type,
                'content',
                webauthn.base64url_encode(get_credentials.tx_auth_generic_content)
              )
            ), '{}')
        )),
        '{}'
      )
    )
  )
)
FROM store_assertion_challenge
CROSS JOIN webauthn.credentials
WHERE credentials.user_name = get_credentials.user_name
GROUP BY get_credentials.challenge,
         get_credentials.relying_party_id,
         get_credentials.timeout,
         get_credentials.user_verification,
         get_credentials.tx_auth_simple,
         get_credentials.tx_auth_generic_content_type,
         get_credentials.tx_auth_generic_content
$$;
