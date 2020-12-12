CREATE OR REPLACE FUNCTION webauthn.make_credential(
  OUT user_id bytea,
  credential_id text,
  credential_type webauthn.credential_type,
  attestation_object text,
  client_data_json text,
  relying_party_id text
)
RETURNS bytea
LANGUAGE sql
AS $$
INSERT INTO webauthn.credentials (credential_id, challenge, credential_type, attestation_object, client_data_json, user_id, user_verification)
SELECT
  webauthn.base64url_decode(credential_id),
  challenge,
  credential_type,
  webauthn.base64url_decode(attestation_object),
  webauthn.base64url_decode(client_data_json),
  user_id,
  user_verification
FROM webauthn.credential_challenges
WHERE credential_challenges.relying_party_id = make_credential.relying_party_id
AND challenge = webauthn.base64url_decode(webauthn.from_utf8(webauthn.base64url_decode(client_data_json))::jsonb->>'challenge')
AND ((webauthn.parse_attestation_object(webauthn.base64url_decode(attestation_object))).user_verified OR credential_challenges.user_verification <> 'required')
AND created_at + timeout > now()
RETURNING credentials.user_id
$$;
