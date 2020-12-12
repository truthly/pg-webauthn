CREATE TABLE webauthn.credentials (
credential_id bytea NOT NULL,
challenge bytea NOT NULL REFERENCES webauthn.credential_challenges,
credential_type webauthn.credential_type NOT NULL,
attestation_object bytea NOT NULL,
rp_id_hash bytea NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).rp_id_hash) STORED,
user_present boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).user_present) STORED,
user_verified boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).user_verified) STORED,
attested_credential_data_included boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).attested_credential_data_included) STORED,
extension_data_included boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).extension_data_included) STORED,
sign_count bigint NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).sign_count) STORED,
aaguid bytea NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).aaguid) STORED,
public_key bytea NOT NULL GENERATED ALWAYS AS (webauthn.cose_ecdha_to_pkcs((webauthn.parse_attestation_object(attestation_object)).credential_public_key)) STORED,
client_data_json bytea NOT NULL,
origin text NOT NULL GENERATED ALWAYS AS (webauthn.from_utf8(client_data_json)::jsonb->>'origin') STORED,
cross_origin boolean GENERATED ALWAYS AS ((webauthn.from_utf8(client_data_json)::jsonb->'crossOrigin')::boolean) STORED,
user_id bytea NOT NULL,
user_verification webauthn.user_verification_requirement NOT NULL,
created_at timestamptz NOT NULL DEFAULT now(),
PRIMARY KEY (credential_id),
UNIQUE (challenge),
CHECK (credential_id = (webauthn.parse_attestation_object(attestation_object)).credential_id),
CHECK (webauthn.from_utf8(client_data_json)::jsonb->>'type' = 'webauthn.create')
);

SELECT pg_catalog.pg_extension_config_dump('credentials', '');

COMMENT ON TABLE webauthn.credentials IS 'Used by webauthn.make_credential() to store the credential created by the WebAuthn Authenticator during registration, and then used by webauthn.get_credentials() and webauthn.verify_assertion() during authentication.';

COMMENT ON COLUMN webauthn.credentials.challenge IS 'https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-challenge';
COMMENT ON COLUMN webauthn.credentials.credential_type IS 'https://www.w3.org/TR/webauthn-2/#enum-credentialType';
COMMENT ON COLUMN webauthn.credentials.attestation_object IS 'https://www.w3.org/TR/webauthn-2/#attestation-object';
COMMENT ON COLUMN webauthn.credentials.rp_id_hash IS 'https://www.w3.org/TR/webauthn-2/#rpidhash';
COMMENT ON COLUMN webauthn.credentials.user_present IS 'https://www.w3.org/TR/webauthn-2/#concept-user-present';
COMMENT ON COLUMN webauthn.credentials.user_verified IS 'https://www.w3.org/TR/webauthn-2/#concept-user-verified';
COMMENT ON COLUMN webauthn.credentials.attested_credential_data_included IS 'https://www.w3.org/TR/webauthn-2/#flags';
COMMENT ON COLUMN webauthn.credentials.extension_data_included IS 'https://www.w3.org/TR/webauthn-2/#flags';
COMMENT ON COLUMN webauthn.credentials.sign_count IS 'https://www.w3.org/TR/webauthn-2/#signcount';
COMMENT ON COLUMN webauthn.credentials.aaguid IS 'https://www.w3.org/TR/webauthn-2/#aaguid';
COMMENT ON COLUMN webauthn.credentials.public_key IS 'https://www.w3.org/TR/webauthn-2/#credentialpublickey';
COMMENT ON COLUMN webauthn.credentials.client_data_json IS 'https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson';
COMMENT ON COLUMN webauthn.credentials.origin IS 'https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-origin';
COMMENT ON COLUMN webauthn.credentials.cross_origin IS 'https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-crossorigin';
COMMENT ON COLUMN webauthn.credentials.user_id IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id';
COMMENT ON COLUMN webauthn.credentials.user_verification IS 'https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification';
COMMENT ON COLUMN webauthn.credentials.created_at IS 'Timestamp of when the credential was created by webauthn.make_credential()';
