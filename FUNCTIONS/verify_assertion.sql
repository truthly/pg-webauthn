CREATE OR REPLACE FUNCTION webauthn.verify_assertion(
  OUT user_id bytea,
  credential_id text,
  credential_type webauthn.credential_type,
  authenticator_data text,
  client_data_json text,
  signature text,
  user_handle text,
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
    verified_at
)
INSERT INTO webauthn.assertions (signature, credential_id, challenge, authenticator_data, client_data_json, user_id, user_handle, verified_at)
SELECT
  decoded_input.signature,
  credentials.credential_id,
  assertion_challenges.challenge,
  decoded_input.authenticator_data,
  decoded_input.client_data_json,
  credentials.user_id,
  decoded_input.user_handle,
  decoded_input.verified_at
FROM decoded_input
JOIN webauthn.assertion_challenges ON assertion_challenges.challenge = decoded_input.challenge
JOIN webauthn.credentials ON credentials.credential_id   = decoded_input.credential_id
                         AND credentials.credential_type = decoded_input.credential_type
                         AND credentials.user_name       = assertion_challenges.user_name
RETURNING assertions.user_id
$$;
