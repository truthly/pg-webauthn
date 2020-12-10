CREATE OR REPLACE FUNCTION webauthn.verify_assertion(
  credential_id text,
  credential_type text,
  authenticator_data text,
  client_data_json text,
  signature text,
  user_handle text,
  relying_party_id text
)
RETURNS boolean
LANGUAGE sql
AS $$
WITH
decoded_input AS (
  SELECT
    webauthn.base64url_decode(credential_id) AS credential_id,
    credential_type,
    webauthn.base64url_decode(authenticator_data) AS authenticator_data,
    webauthn.base64url_decode(client_data_json) AS client_data_json,
    webauthn.base64url_decode(signature) AS signature,
    webauthn.base64url_decode(user_handle) AS user_id
),
consume_challenge AS (
  UPDATE webauthn.assertion_challenges SET
    consumed_at = now()
  WHERE assertion_challenges.challenge = webauthn.base64url_decode(webauthn.from_utf8(webauthn.base64url_decode(client_data_json))::jsonb->>'challenge')
  AND assertion_challenges.relying_party_id = verify_assertion.relying_party_id
  AND assertion_challenges.consumed_at IS NULL
  RETURNING challenge
)
INSERT INTO webauthn.assertions (credential_id, challenge, authenticator_data, client_data_json, signature)
SELECT
  credentials.credential_id,
  consume_challenge.challenge,
  decoded_input.authenticator_data,
  decoded_input.client_data_json,
  decoded_input.signature
FROM consume_challenge
CROSS JOIN decoded_input
JOIN webauthn.credentials ON credentials.credential_id = decoded_input.credential_id
                         AND credentials.credential_type = decoded_input.credential_type
JOIN webauthn.credential_challenges ON credential_challenges.challenge = credentials.challenge
                                   AND credential_challenges.user_id = decoded_input.user_id
WHERE ecdsa_verify(
  public_key := credentials.public_key,
  input_data := substring(decoded_input.authenticator_data,1,37) || digest(decoded_input.client_data_json,'sha256'),
  signature := webauthn.decode_asn1_der_signature(decoded_input.signature),
  hash_func := 'sha256',
  curve_name := 'secp256r1'
)
RETURNING TRUE
$$;
