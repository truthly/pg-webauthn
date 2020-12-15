CREATE TABLE webauthn.credentials (
credential_id bytea NOT NULL,
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
challenge bytea NOT NULL,
user_name text NOT NULL,
user_id bytea NOT NULL,
credential_at timestamptz NOT NULL,
PRIMARY KEY (credential_id),
UNIQUE (challenge),
CONSTRAINT client_data_json_type CHECK ('webauthn.create' = webauthn.from_utf8(client_data_json)::jsonb->>'type'),
CONSTRAINT client_data_json_challenge CHECK (challenge = webauthn.base64url_decode(webauthn.from_utf8(client_data_json)::jsonb->>'challenge')),
CONSTRAINT attestation_object_credential_id CHECK (credential_id = (webauthn.parse_attestation_object(attestation_object)).credential_id),
CONSTRAINT user_verified_or_not_required CHECK (user_verified OR webauthn.credential_challenge_user_verification(challenge) <> 'required'),
CONSTRAINT credential_before_timeout CHECK (credential_at < webauthn.credential_challenge_expiration(challenge))
);

SELECT pg_catalog.pg_extension_config_dump('credentials', '');

--
-- Storing "user_name" and "user_id" in webauthn.credentials is a denormalization decision
-- to avoid having to JOIN webauthn.credential_challenges for every webauthn.get_credentials() call
-- to find credentials matching the input "user_name".
--
-- To ensure consistency between the tables, add a multi-column foreign key on these columns.
-- To add a foreign key, we first need a unique constraint on all three columns,
-- which would otherwise be meaningless since we already have a unique constraint on "challenge" on its own.
--
-- Using "user_name" as the first column in this multi-key unique index is intentional,
-- even though "challenge" would be more selective,
-- since this avoids the need for a separate index on the "user_name" column
-- to ensure webauthn.get_credentials() can quickly find any rows matching a "user_name".
--

ALTER TABLE webauthn.credentials ADD UNIQUE (user_name, user_id, challenge);
ALTER TABLE webauthn.credential_challenges ADD UNIQUE (user_name, user_id, challenge);
ALTER TABLE webauthn.credentials ADD FOREIGN KEY (user_name, user_id, challenge) REFERENCES webauthn.credential_challenges (user_name, user_id, challenge);

COMMENT ON TABLE webauthn.credentials IS 'Used by webauthn.make_credential() to store credentials.';

COMMENT ON COLUMN webauthn.credentials.credential_id IS 'https://www.w3.org/TR/webauthn-2/#credential-id';
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
COMMENT ON COLUMN webauthn.credentials.credential_at IS 'Timestamp of when the credential was created by webauthn.make_credential()';
