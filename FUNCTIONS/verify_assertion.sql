CREATE OR REPLACE FUNCTION webauthn.verify_assertion(credential_raw_id text, credential_type text, authenticator_data text, client_data_json text, signature text, user_handle text)
RETURNS boolean
LANGUAGE sql
AS $$
WITH
input AS (
  SELECT
    decode(credential_raw_id,'base64') AS credential_raw_id,
    credential_type,
    decode(authenticator_data,'base64') AS authenticator_data,
    decode(client_data_json,'base64') AS client_data_json,
    decode(signature,'base64') AS signature,
    decode(user_handle,'base64') AS user_handle
),
consume_challenge AS (
  UPDATE webauthn.challenges SET
    consumed_at = now()
  WHERE challenges.challenge = webauthn.base64_url_decode(webauthn.from_utf8(decode(client_data_json,'base64'))::jsonb->>'challenge')
  AND challenges.relaying_party = webauthn.relaying_party()
  AND challenges.consumed_at IS NULL
  RETURNING challenge_id
)
INSERT INTO webauthn.assertions (credential_id, challenge_id, authenticator_data, client_data_json, signature, user_handle, verified)
SELECT
  credentials.credential_id,
  consume_challenge.challenge_id,
  input.authenticator_data,
  input.client_data_json,
  input.signature,
  input.user_handle,
  COALESCE(ecdsa_verify(
    public_key := credentials.public_key,
    input_data := substring(input.authenticator_data,1,37) || digest(input.client_data_json,'sha256'),
    signature := webauthn.decode_asn1_der_signature(input.signature),
    hash_func := 'sha256',
    curve_name := 'secp256r1'
  ),FALSE)
FROM consume_challenge
CROSS JOIN input
JOIN webauthn.credentials ON credentials.credential_raw_id = input.credential_raw_id
                         AND credentials.credential_type = input.credential_type
RETURNING assertions.verified
$$;
