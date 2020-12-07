CREATE TABLE webauthn.challenges (
challenge_id bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
relaying_party text NOT NULL,
username text NOT NULL,
challenge bytea NOT NULL DEFAULT gen_random_bytes(32),
remote_ip inet DEFAULT current_setting('request.header.X-Forwarded-For', TRUE)::inet,
created_at timestamptz NOT NULL DEFAULT now(),
consumed_at timestamptz,
PRIMARY KEY (challenge_id),
UNIQUE (challenge)
);

SELECT pg_catalog.pg_extension_config_dump('challenges', '');

CREATE INDEX ON webauthn.challenges(username);
CREATE INDEX ON webauthn.challenges(challenge);
