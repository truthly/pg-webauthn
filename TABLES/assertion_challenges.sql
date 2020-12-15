CREATE TABLE webauthn.assertion_challenges (
challenge bytea NOT NULL,
user_name text NOT NULL,
user_verification webauthn.user_verification_requirement NOT NULL,
timeout interval NOT NULL,
relying_party_id text,
challenge_at timestamptz NOT NULL,
PRIMARY KEY (challenge),
CONSTRAINT reasonable_timeout CHECK (timeout BETWEEN '30000 ms' AND '600000 ms')
);

SELECT pg_catalog.pg_extension_config_dump('assertion_challenges', '');

COMMENT ON TABLE webauthn.assertion_challenges IS 'Used by webauthn.get_credentials() to store assertion challenges.';

COMMENT ON COLUMN webauthn.assertion_challenges.challenge IS 'https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-challenge';
COMMENT ON COLUMN webauthn.assertion_challenges.relying_party_id IS 'https://www.w3.org/TR/webauthn-2/#relying-party-identifier';
COMMENT ON COLUMN webauthn.assertion_challenges.user_name IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user';
COMMENT ON COLUMN webauthn.assertion_challenges.timeout IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-timeout';
COMMENT ON COLUMN webauthn.assertion_challenges.challenge_at IS 'Timestamp of when the challenge was created by webauthn.get_credentials()';
