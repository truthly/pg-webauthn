CREATE TABLE webauthn.assertion_challenges (
challenge bytea NOT NULL,
relying_party_id text NOT NULL,
user_name text NOT NULL,
timeout interval NOT NULL,
created_at timestamptz NOT NULL DEFAULT now(),
consumed_at timestamptz,
PRIMARY KEY (challenge),
CHECK(timeout >= '0'::interval)
);

SELECT pg_catalog.pg_extension_config_dump('assertion_challenges', '');
