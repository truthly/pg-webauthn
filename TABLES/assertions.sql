CREATE TABLE webauthn.assertions (
signature bytea NOT NULL,
challenge bytea NOT NULL REFERENCES webauthn.assertion_challenges,
credential_id bytea NOT NULL REFERENCES webauthn.credentials,
authenticator_data bytea NOT NULL,
rp_id_hash bytea NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).rp_id_hash) STORED,
user_presence boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).user_presence) STORED,
user_verification boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).user_verification) STORED,
attested_credential_data boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).attested_credential_data) STORED,
extension_data boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).extension_data) STORED,
sign_count bigint NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).sign_count) STORED,
client_data_json bytea NOT NULL,
origin text NOT NULL GENERATED ALWAYS AS (webauthn.from_utf8(client_data_json)::jsonb->>'origin') STORED,
cross_origin boolean GENERATED ALWAYS AS ((webauthn.from_utf8(client_data_json)::jsonb->'crossOrigin')::boolean) STORED,
created_at timestamptz NOT NULL DEFAULT now(),
user_id bytea NOT NULL,
PRIMARY KEY (signature),
UNIQUE (challenge),
CHECK (webauthn.from_utf8(client_data_json)::jsonb->>'type' = 'webauthn.get')
);

SELECT pg_catalog.pg_extension_config_dump('assertions', '');
