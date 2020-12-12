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
verified_at timestamptz NOT NULL DEFAULT now(),
PRIMARY KEY (signature),
UNIQUE (challenge),
CHECK (webauthn.from_utf8(client_data_json)::jsonb->>'type' = 'webauthn.get'),
CHECK (webauthn.base64url_decode(webauthn.from_utf8(client_data_json)::jsonb->>'challenge') = challenge)
);

SELECT pg_catalog.pg_extension_config_dump('assertions', '');

COMMENT ON TABLE webauthn.assertions IS 'Used by webauthn.verify_assertion() to store the verified assertion.';

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
COMMENT ON COLUMN webauthn.assertions.verified_at IS 'Timestamp of when the assertion was verified by webauthn.verify_assertion()';
