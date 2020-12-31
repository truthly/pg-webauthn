CREATE OR REPLACE FUNCTION webauthn.store_credential(
  OUT user_id bytea,
  credential_id text,
  credential_type webauthn.credential_type,
  attestation_object text,
  client_data_json text,
  credential_at timestamptz DEFAULT now()
)
RETURNS bytea
LANGUAGE sql
AS $$
INSERT INTO webauthn.credentials (credential_id, credential_type, attestation_object, client_data_json, challenge, user_name, user_id, credential_at)
SELECT
  webauthn.base64url_decode(store_credential.credential_id),
  store_credential.credential_type,
  webauthn.base64url_decode(store_credential.attestation_object),
  webauthn.base64url_decode(store_credential.client_data_json),
  credential_challenges.challenge,
  credential_challenges.user_name,
  credential_challenges.user_id,
  store_credential.credential_at
FROM webauthn.credential_challenges
WHERE credential_challenges.challenge = webauthn.base64url_decode(webauthn.from_utf8(webauthn.base64url_decode(store_credential.client_data_json))::jsonb->>'challenge')
RETURNING credentials.user_id
$$;
