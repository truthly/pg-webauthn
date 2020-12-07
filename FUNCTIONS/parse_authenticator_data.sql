CREATE OR REPLACE FUNCTION webauthn.parse_authenticator_data(
OUT rp_id_hash bytea,
OUT user_presence boolean,
OUT user_verification boolean,
OUT attested_credential_data boolean,
OUT extension_data boolean,
OUT sign_count bigint,
authenticator_data bytea
)
RETURNS record
IMMUTABLE
LANGUAGE sql
AS $$
-- https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse/authenticatorData
-- https://github.com/fido-alliance/webauthn-demo/blob/master/utils.js#L304
SELECT
  substring(authenticator_data,1,32),
  (get_byte(authenticator_data,32)&1)::boolean,
  (get_byte(authenticator_data,32)>>2&1)::boolean,
  (get_byte(authenticator_data,32)>>6&1)::boolean,
  (get_byte(authenticator_data,32)>>7&1)::boolean,
  (get_byte(authenticator_data,33)<<24)::bigint +
  (get_byte(authenticator_data,34)<<16)::bigint +
  (get_byte(authenticator_data,35)<<8)::bigint +
  get_byte(authenticator_data,36)::bigint
$$;
