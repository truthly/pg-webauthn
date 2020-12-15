CREATE TABLE webauthn.assertions (
signature bytea NOT NULL,
challenge bytea NOT NULL REFERENCES webauthn.assertion_challenges,
credential_id bytea NOT NULL REFERENCES webauthn.credentials,
authenticator_data bytea NOT NULL,
rp_id_hash bytea NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).rp_id_hash) STORED,
user_present boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).user_present) STORED,
user_verified boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).user_verified) STORED,
attested_credential_data_included boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).attested_credential_data_included) STORED,
extension_data_included boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).extension_data_included) STORED,
sign_count bigint NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).sign_count) STORED,
client_data_json bytea NOT NULL,
origin text NOT NULL GENERATED ALWAYS AS (webauthn.from_utf8(client_data_json)::jsonb->>'origin') STORED,
cross_origin boolean GENERATED ALWAYS AS ((webauthn.from_utf8(client_data_json)::jsonb->'crossOrigin')::boolean) STORED,
user_id bytea NOT NULL,
user_handle bytea,
verified_at timestamptz NOT NULL,
PRIMARY KEY (signature),
UNIQUE (challenge),
CONSTRAINT client_data_json_type CHECK ('webauthn.get' = webauthn.from_utf8(client_data_json)::jsonb->>'type'),
CONSTRAINT client_data_json_challenge CHECK (challenge = webauthn.base64url_decode(webauthn.from_utf8(client_data_json)::jsonb->>'challenge')),
CONSTRAINT user_handle_equal_or_null CHECK (user_handle = user_id),
CONSTRAINT user_verified_or_not_required CHECK (user_verified OR webauthn.assertion_challenge_user_verification(challenge) <> 'required'),
CONSTRAINT verified_before_timeout CHECK (verified_at < webauthn.assertion_challenge_expiration(challenge)),
CONSTRAINT verified_signature CHECK (COALESCE(public.ecdsa_verify(
  public_key := webauthn.credential_public_key(credential_id),
  input_data := substring(authenticator_data,1,37) || public.digest(client_data_json,'sha256'),
  signature := webauthn.decode_asn1_der_signature(signature),
  hash_func := 'sha256',
  curve_name := 'secp256r1'),FALSE))
);

SELECT pg_catalog.pg_extension_config_dump('assertions', '');

COMMENT ON TABLE webauthn.assertions IS 'Used by webauthn.verify_assertion() to store verified assertions.';

COMMENT ON COLUMN webauthn.assertions.signature IS 'https://www.w3.org/TR/webauthn-2/#assertion-signature';
COMMENT ON COLUMN webauthn.assertions.challenge IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-challenge';
COMMENT ON COLUMN webauthn.assertions.credential_id IS 'https://www.w3.org/TR/webauthn-2/#credential-id';
COMMENT ON COLUMN webauthn.assertions.authenticator_data IS 'https://www.w3.org/TR/webauthn-2/#authenticator-data';
COMMENT ON COLUMN webauthn.assertions.rp_id_hash IS 'https://www.w3.org/TR/webauthn-2/#rpidhash';
COMMENT ON COLUMN webauthn.assertions.user_present IS 'https://www.w3.org/TR/webauthn-2/#concept-user-present';
COMMENT ON COLUMN webauthn.assertions.user_verified IS 'https://www.w3.org/TR/webauthn-2/#concept-user-verified';
COMMENT ON COLUMN webauthn.assertions.attested_credential_data_included IS 'https://www.w3.org/TR/webauthn-2/#flags';
COMMENT ON COLUMN webauthn.assertions.extension_data_included IS 'https://www.w3.org/TR/webauthn-2/#flags';
COMMENT ON COLUMN webauthn.assertions.sign_count IS 'https://www.w3.org/TR/webauthn-2/#signcount';
COMMENT ON COLUMN webauthn.assertions.client_data_json IS 'https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson';
COMMENT ON COLUMN webauthn.assertions.origin IS 'https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-origin';
COMMENT ON COLUMN webauthn.assertions.cross_origin IS 'https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-crossorigin';
COMMENT ON COLUMN webauthn.assertions.user_id IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id';
COMMENT ON COLUMN webauthn.assertions.user_handle IS 'https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-userhandle';
COMMENT ON COLUMN webauthn.assertions.verified_at IS 'Timestamp of when the assertion was verified by webauthn.verify_assertion()';
