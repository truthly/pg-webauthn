CREATE OR REPLACE FUNCTION webauthn.verify_assertion(
  OUT user_id bytea,
  credential_id text,
  credential_type webauthn.credential_type,
  authenticator_data text,
  client_data_json text,
  signature text,
  user_handle text,
  relying_party_id text,
  verified_at timestamptz DEFAULT now()
)
RETURNS bytea
LANGUAGE sql
AS $$
WITH
decoded_input AS (
  SELECT
    webauthn.base64url_decode(credential_id) AS credential_id,
    credential_type,
    webauthn.base64url_decode(authenticator_data) AS authenticator_data,
    webauthn.base64url_decode(client_data_json) AS client_data_json,
    webauthn.base64url_decode(webauthn.from_utf8(webauthn.base64url_decode(client_data_json))::jsonb->>'challenge') AS challenge,
    webauthn.base64url_decode(signature) AS signature,
    webauthn.base64url_decode(NULLIF(user_handle,'')) AS user_handle,
    relying_party_id,
    verified_at
)
INSERT INTO webauthn.assertions (signature, credential_id, challenge, authenticator_data, client_data_json, user_id, user_handle, verified_at)
SELECT
  decoded_input.signature,
  credentials.credential_id,
  decoded_input.challenge,
  decoded_input.authenticator_data,
  decoded_input.client_data_json,
  credentials.user_id,
  decoded_input.user_handle,
  decoded_input.verified_at
FROM webauthn.assertion_challenges
JOIN decoded_input ON decoded_input.challenge        = assertion_challenges.challenge
                  AND decoded_input.relying_party_id = assertion_challenges.relying_party_id
JOIN webauthn.credentials ON credentials.credential_id   = decoded_input.credential_id
                         AND credentials.credential_type = decoded_input.credential_type
RETURNING assertions.user_id
$$;
