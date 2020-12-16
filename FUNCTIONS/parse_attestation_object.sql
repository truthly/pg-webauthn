CREATE OR REPLACE FUNCTION webauthn.parse_attestation_object(
  OUT rp_id_hash bytea,
  OUT user_present boolean,
  OUT user_verified boolean,
  OUT attested_credential_data_included boolean,
  OUT extension_data_included boolean,
  OUT sign_count bigint,
  OUT aaguid bytea,
  OUT credential_id bytea,
  OUT credential_public_key bytea,
  attestation_object bytea
)
RETURNS record
IMMUTABLE
LANGUAGE sql
AS $$
-- https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse/authenticatorData
-- https://github.com/fido-alliance/webauthn-demo/blob/master/utils.js#L183
SELECT
  parse_authenticator_data.*,
  substring(authenticator_data,38,16),
  substring(authenticator_data,56,(get_byte(authenticator_data,53)<<8) + get_byte(authenticator_data,54)),
  substring(authenticator_data,56+(get_byte(authenticator_data,53)<<8) + get_byte(authenticator_data,54))
FROM decode(webauthn.cbor_to_json(attestation_object)->0->>'authData','base64') AS authenticator_data
CROSS JOIN webauthn.parse_authenticator_data(authenticator_data)
$$;
