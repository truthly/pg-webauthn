CREATE OR REPLACE FUNCTION webauthn.make_credential(
  credential_id text,
  credential_type text,
  attestation_object text,
  client_data_json text,
  relying_party_id text
)
RETURNS boolean
LANGUAGE sql
AS $$
WITH
consume_challenge AS (
  UPDATE webauthn.credential_challenges SET
    consumed_at = now()
  WHERE credential_challenges.relying_party_id = make_credential.relying_party_id
  AND credential_challenges.challenge = webauthn.base64url_decode(webauthn.from_utf8(webauthn.base64url_decode(client_data_json))::jsonb->>'challenge')
  AND credential_challenges.consumed_at IS NULL
  AND credential_challenges.created_at + credential_challenges.timeout > now()
  RETURNING challenge
)
INSERT INTO webauthn.credentials (credential_id,challenge,credential_type,attestation_object,client_data_json)
SELECT
  webauthn.base64url_decode(credential_id),
  consume_challenge.challenge,
  credential_type,
  webauthn.base64url_decode(attestation_object),
  webauthn.base64url_decode(client_data_json)
FROM consume_challenge
RETURNING TRUE
$$;
