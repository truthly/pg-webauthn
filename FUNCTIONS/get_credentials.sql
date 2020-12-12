CREATE OR REPLACE FUNCTION webauthn.get_credentials(
  challenge bytea,
  relying_party_id text,
  user_name text,
  timeout interval,
  user_verification webauthn.user_verification_requirement DEFAULT 'preferred',
  tx_auth_simple text DEFAULT NULL,
  tx_auth_generic_content_type text DEFAULT NULL,
  tx_auth_generic_content bytea DEFAULT NULL
)
RETURNS jsonb
LANGUAGE sql
AS $$
WITH store_challenge AS (
  INSERT INTO webauthn.assertion_challenges
         (challenge, relying_party_id, user_name, timeout, user_verification, tx_auth_simple, tx_auth_generic_content_type, tx_auth_generic_content)
  VALUES (challenge, relying_party_id, user_name, timeout, user_verification, tx_auth_simple, tx_auth_generic_content_type, tx_auth_generic_content)
  RETURNING *
)
SELECT jsonb_build_object(
  'publicKey', jsonb_build_object(
    'userVerification', store_challenge.user_verification,
    'allowCredentials', jsonb_agg(
      jsonb_build_object(
        'type', credentials.credential_type,
        'id', webauthn.base64url_encode(credentials.credential_id)
      )
    ORDER BY credentials.credential_id),
    'timeout', (extract(epoch from store_challenge.timeout)*1000)::bigint, -- milliseconds
    'challenge', webauthn.base64url_encode(store_challenge.challenge),
    'rpId', store_challenge.relying_party_id
  ) ||
  jsonb_strip_nulls(
    jsonb_build_object(
      'extensions',
      NULLIF(
        jsonb_strip_nulls(jsonb_build_object(
          'txAuthSimple',
          store_challenge.tx_auth_simple
        )) ||
        jsonb_strip_nulls(jsonb_build_object(
            'txAuthGeneric',
            NULLIF(jsonb_strip_nulls(
              jsonb_build_object(
                'contentType',
                store_challenge.tx_auth_generic_content_type,
                'content',
                webauthn.base64url_encode(store_challenge.tx_auth_generic_content)
              )
            ), '{}')
        )),
        '{}'
      )
    )
  )
)
FROM store_challenge
JOIN webauthn.credential_challenges ON credential_challenges.relying_party_id = store_challenge.relying_party_id
                                   AND credential_challenges.user_name        = store_challenge.user_name
JOIN webauthn.credentials ON credentials.challenge = credential_challenges.challenge
GROUP BY store_challenge.challenge,
         store_challenge.relying_party_id,
         store_challenge.timeout,
         store_challenge.user_verification,
         store_challenge.tx_auth_simple,
         store_challenge.tx_auth_generic_content_type,
         store_challenge.tx_auth_generic_content
$$;
