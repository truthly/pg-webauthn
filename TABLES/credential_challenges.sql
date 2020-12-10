CREATE TABLE webauthn.credential_challenges (
challenge bytea NOT NULL,
relying_party_name text NOT NULL,
relying_party_id text NOT NULL,
user_name text NOT NULL,
user_id bytea NOT NULL,
user_display_name text NOT NULL,
timeout interval NOT NULL,
created_at timestamptz NOT NULL DEFAULT now(),
consumed_at timestamptz,
PRIMARY KEY (challenge),
CHECK(timeout >= '0'::interval)
);

SELECT pg_catalog.pg_extension_config_dump('credential_challenges', '');

CREATE INDEX ON webauthn.credential_challenges(relying_party_id, user_name);
