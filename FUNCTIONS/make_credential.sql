CREATE OR REPLACE FUNCTION webauthn.make_credential(
  OUT user_id bytea,
  credential_id text,
  credential_type webauthn.credential_type,
  attestation_object text,
  client_data_json text,
  relying_party_id text,
  credential_at timestamptz DEFAULT now()
)
RETURNS bytea
LANGUAGE sql
AS $$
INSERT INTO webauthn.credentials (credential_id, challenge, credential_type, attestation_object, client_data_json, user_id, credential_at)
SELECT
  webauthn.base64url_decode(make_credential.credential_id),
  credential_challenges.challenge,
  make_credential.credential_type,
  webauthn.base64url_decode(make_credential.attestation_object),
  webauthn.base64url_decode(make_credential.client_data_json),
  credential_challenges.user_id,
  make_credential.credential_at
FROM webauthn.credential_challenges
WHERE credential_challenges.relying_party_id = make_credential.relying_party_id
AND credential_challenges.challenge = webauthn.base64url_decode(webauthn.from_utf8(webauthn.base64url_decode(make_credential.client_data_json))::jsonb->>'challenge')
RETURNING credentials.user_id
$$;
