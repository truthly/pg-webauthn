CREATE TABLE webauthn.credential_challenges (
challenge bytea NOT NULL,
user_name text NOT NULL,
user_id bytea NOT NULL,
user_display_name text NOT NULL,
relying_party_name text NOT NULL,
relying_party_id text,
user_verification webauthn.user_verification_requirement NOT NULL,
timeout interval NOT NULL,
challenge_at timestamptz NOT NULL,
tx_auth_simple text,
tx_auth_generic_content_type text,
tx_auth_generic_content bytea,
PRIMARY KEY (challenge),
CONSTRAINT reasonable_timeout CHECK (timeout BETWEEN '30000 ms' AND '600000 ms'),
CONSTRAINT tx_auth_generic_content_both_set_or_none CHECK ((tx_auth_generic_content_type IS NULL) = (tx_auth_generic_content IS NULL))
);

SELECT pg_catalog.pg_extension_config_dump('credential_challenges', '');

COMMENT ON TABLE webauthn.credential_challenges IS 'Used by webauthn.init_credential() to store credential challenges.';

COMMENT ON COLUMN webauthn.credential_challenges.challenge IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-challenge';
COMMENT ON COLUMN webauthn.credential_challenges.user_name IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user';
COMMENT ON COLUMN webauthn.credential_challenges.user_id IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id';
COMMENT ON COLUMN webauthn.credential_challenges.user_display_name IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname';
COMMENT ON COLUMN webauthn.credential_challenges.user_verification IS 'https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification';
COMMENT ON COLUMN webauthn.credential_challenges.timeout IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout';
COMMENT ON COLUMN webauthn.credential_challenges.relying_party_name IS 'https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params';
COMMENT ON COLUMN webauthn.credential_challenges.relying_party_id IS 'https://www.w3.org/TR/webauthn-2/#relying-party-identifier';
COMMENT ON COLUMN webauthn.credential_challenges.challenge_at IS 'Timestamp of when the challenge was created by webauthn.init_credential()';
COMMENT ON COLUMN webauthn.credential_challenges.tx_auth_simple IS 'https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions/extensions';
COMMENT ON COLUMN webauthn.credential_challenges.tx_auth_generic_content_type IS 'https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions/extensions';
COMMENT ON COLUMN webauthn.credential_challenges.tx_auth_generic_content IS 'https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions/extensions';
