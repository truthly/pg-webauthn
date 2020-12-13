CREATE OR REPLACE FUNCTION webauthn.init_credential(
  challenge bytea,
  relying_party_name text,
  relying_party_id text,
  user_name text,
  user_id bytea,
  user_display_name text,
  timeout interval,
  user_verification webauthn.user_verification_requirement DEFAULT 'preferred',
  tx_auth_simple text DEFAULT NULL,
  tx_auth_generic_content_type text DEFAULT NULL,
  tx_auth_generic_content bytea DEFAULT NULL,
  challenge_at timestamptz DEFAULT now()
)
RETURNS jsonb
LANGUAGE sql
AS $$
INSERT INTO webauthn.credential_challenges
       (challenge, relying_party_name, relying_party_id, user_name, user_id, user_display_name, timeout, user_verification, tx_auth_simple, tx_auth_generic_content_type, tx_auth_generic_content, challenge_at)
VALUES (challenge, relying_party_name, relying_party_id, user_name, user_id, user_display_name, timeout, user_verification, tx_auth_simple, tx_auth_generic_content_type, tx_auth_generic_content, challenge_at)
RETURNING
jsonb_build_object(
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
      'userVerification', user_verification
    ),
    'timeout', (extract(epoch from timeout)*1000)::bigint,
    'attestation', 'none'
  ) ||
  jsonb_strip_nulls(
    jsonb_build_object(
      'extensions',
      NULLIF(
        jsonb_strip_nulls(jsonb_build_object(
          'txAuthSimple',
          tx_auth_simple
        )) ||
        jsonb_strip_nulls(jsonb_build_object(
            'txAuthGeneric',
            NULLIF(jsonb_strip_nulls(
              jsonb_build_object(
                'contentType',
                tx_auth_generic_content_type,
                'content',
                webauthn.base64url_encode(tx_auth_generic_content)
              )
            ), '{}')
        )),
        '{}'
      )
    )
  )
)
$$;
