CREATE TABLE webauthn.credentials (
credential_id bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
challenge_id bigint NOT NULL REFERENCES webauthn.challenges,
credential_raw_id bytea NOT NULL,
credential_type text NOT NULL,
attestation_object bytea NOT NULL,
rp_id_hash bytea NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).rp_id_hash) STORED,
user_presence boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).user_presence) STORED,
user_verification boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).user_verification) STORED,
attested_credential_data boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).attested_credential_data) STORED,
extension_data boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).extension_data) STORED,
sign_count bigint NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).sign_count) STORED,
aaguid bytea NOT NULL GENERATED ALWAYS AS ((webauthn.parse_attestation_object(attestation_object)).aaguid) STORED,
public_key bytea NOT NULL GENERATED ALWAYS AS (webauthn.cose_ecdha_to_pkcs((webauthn.parse_attestation_object(attestation_object)).credential_public_key)) STORED,
client_data_json bytea NOT NULL,
origin text NOT NULL GENERATED ALWAYS AS (webauthn.from_utf8(client_data_json)::jsonb->>'origin') STORED,
cross_origin boolean GENERATED ALWAYS AS ((webauthn.from_utf8(client_data_json)::jsonb->'crossOrigin')::boolean) STORED,
remote_ip inet DEFAULT current_setting('request.header.X-Forwarded-For', TRUE)::inet,
created_at timestamptz NOT NULL DEFAULT now(),
PRIMARY KEY (credential_id),
UNIQUE (credential_raw_id),
UNIQUE (challenge_id),
CHECK (credential_raw_id = (webauthn.parse_attestation_object(attestation_object)).credential_id),
CHECK (webauthn.from_utf8(client_data_json)::jsonb->>'type' = 'webauthn.create')
);

SELECT pg_catalog.pg_extension_config_dump('credentials', '');
