CREATE OR REPLACE FUNCTION webauthn.make_credential(username text, challenge text, credential_raw_id text, credential_type text, attestation_object text, client_data_json text)
RETURNS boolean
LANGUAGE sql
AS $$
WITH
consume_challenge AS (
  UPDATE webauthn.challenges SET
    consumed_at = now()
  WHERE challenges.username = make_credential.username
  AND challenges.relaying_party = webauthn.relaying_party()
  AND challenges.challenge = decode(make_credential.challenge,'base64')
  AND challenges.challenge = webauthn.base64_url_decode(webauthn.from_utf8(decode(client_data_json,'base64'))::jsonb->>'challenge')
  AND challenges.consumed_at IS NULL
  RETURNING challenge_id
)
INSERT INTO webauthn.credentials (challenge_id,credential_raw_id,credential_type,attestation_object,client_data_json)
SELECT
  consume_challenge.challenge_id,
  decode(credential_raw_id,'base64'),
  credential_type,
  decode(attestation_object,'base64'),
  decode(client_data_json,'base64')
FROM consume_challenge
RETURNING TRUE
$$;
