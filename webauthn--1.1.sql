-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION webauthn" to load this file. \quit
CREATE OR REPLACE FUNCTION webauthn.raise_error(error_message text, debug json, dummy_return_value anyelement)
RETURNS anyelement
LANGUAGE plpgsql
AS $$
BEGIN
RAISE '% %', error_message, debug;
-- Will not return, since error will be raised,
-- but necessary to be able to use the function in place
-- where a value of given type is expected.
RETURN dummy_return_value;
END;
$$;
CREATE TYPE webauthn.credential_type AS ENUM (
  'public-key'
);

COMMENT ON TYPE webauthn.credential_type IS 'https://www.w3.org/TR/webauthn-2/#enum-credentialType';
CREATE TYPE webauthn.user_verification_requirement AS ENUM (
  'required',
  'preferred',
  'discouraged'
);

COMMENT ON TYPE webauthn.user_verification_requirement IS 'https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement';
CREATE TYPE webauthn.attestation_conveyance_preference AS ENUM (
  'none',
  'indirect',
  'direct',
  'enterprise'
);

COMMENT ON TYPE webauthn.attestation_conveyance_preference IS 'https://www.w3.org/TR/webauthn-2/#enum-attestation-convey';
CREATE OR REPLACE FUNCTION webauthn.base64url_decode(text)
RETURNS bytea
IMMUTABLE
LANGUAGE sql AS $$
SELECT decode(rpad(translate($1,'-_','+/'),length($1) + (4 - length($1) % 4) % 4, '='),'base64')
$$;
CREATE OR REPLACE FUNCTION webauthn.base64url_encode(bytea)
RETURNS text
IMMUTABLE
LANGUAGE sql AS $$
SELECT translate(trim(trailing '=' from replace(encode($1,'base64'),E'\n','')),'+/','-_')
$$;
CREATE OR REPLACE FUNCTION webauthn.cose_ecdha_to_pkcs(cose_public_key bytea)
RETURNS bytea
IMMUTABLE
LANGUAGE sql
AS $$
-- https://github.com/fido-alliance/webauthn-demo/blob/master/utils.js#L105
-- \x04 tag byte not prepended since not wanted by pg-ecdsa
SELECT decode(cose_struct->0->>'-2','base64') || decode(cose_struct->0->>'-3','base64')
FROM cbor.to_jsonb_array(cbor := cose_public_key, encode_binary_format := 'base64') AS cose_struct
$$;
CREATE OR REPLACE FUNCTION webauthn.decode_asn1_der_signature(asn1der bytea)
RETURNS bytea
IMMUTABLE
LANGUAGE sql
AS $$
SELECT integer1||integer2
FROM get_byte(asn1der,3) AS Q1(len1)
JOIN LATERAL get_byte(asn1der,5+len1) AS Q2(len2) ON TRUE
JOIN LATERAL substring(asn1der from 5 for len1) AS Q3(integer1_zeropadded) ON TRUE
JOIN LATERAL substring(integer1_zeropadded from length(integer1_zeropadded)-31 for 32) AS Q4(integer1) ON TRUE
JOIN LATERAL substring(asn1der from 5+len1+2 for len2) AS Q5(integer2_zeropadded) ON TRUE
JOIN LATERAL substring(integer2_zeropadded from length(integer2_zeropadded)-31 for 32) AS Q6(integer2) ON TRUE
WHERE get_byte(asn1der,0) = 48 /* 0x30 SEQUENCE */
AND get_byte(asn1der,1) = length(asn1der)-2
AND get_byte(asn1der,2) = 2 /* 0x02 INTEGER */
AND get_byte(asn1der,5+len1-1) = 2 /* 0x02 INTEGER */
AND length(integer1||integer2) = 64
$$;
CREATE OR REPLACE FUNCTION webauthn.from_utf8(string bytea)
RETURNS text
IMMUTABLE
LANGUAGE sql
AS $$
-- IMMUTABLE wrapper-function for convert_from() since it's not IMMUTABLE
-- See: https://www.postgresql.org/message-id/87ftxia3l4.fsf%40news-spur.riddles.org.uk
-- Should be safe, since "server_encoding can't be changed except at db creation time."
SELECT convert_from(string, 'utf8')
$$;
CREATE OR REPLACE FUNCTION webauthn.parse_authenticator_data(
  OUT rp_id_hash bytea,
  OUT user_present boolean,
  OUT user_verified boolean,
  OUT attested_credential_data_included boolean,
  OUT extension_data_included boolean,
  OUT sign_count bigint,
  authenticator_data bytea
)
RETURNS record
IMMUTABLE
LANGUAGE sql
AS $$
-- https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse/authenticatorData
-- https://github.com/fido-alliance/webauthn-demo/blob/master/utils.js#L304
SELECT
  substring(authenticator_data,1,32),
  (get_byte(authenticator_data,32)&1)::boolean,
  (get_byte(authenticator_data,32)>>2&1)::boolean,
  (get_byte(authenticator_data,32)>>6&1)::boolean,
  (get_byte(authenticator_data,32)>>7&1)::boolean,
  (get_byte(authenticator_data,33)<<24)::bigint +
  (get_byte(authenticator_data,34)<<16)::bigint +
  (get_byte(authenticator_data,35)<<8)::bigint +
  get_byte(authenticator_data,36)::bigint
$$;
CREATE OR REPLACE FUNCTION webauthn.parse_attestation_object(
  OUT rp_id_hash bytea,
  OUT user_present boolean,
  OUT user_verified boolean,
  OUT attested_credential_data_included boolean,
  OUT extension_data_included boolean,
  OUT sign_count bigint,
  OUT aaguid bytea,
  OUT credential_id bytea,
  OUT credential_public_key bytea,
  attestation_object bytea
)
RETURNS record
IMMUTABLE
LANGUAGE sql
AS $$
-- https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse/authenticatorData
-- https://github.com/fido-alliance/webauthn-demo/blob/master/utils.js#L183
SELECT
  parse_authenticator_data.*,
  substring(authenticator_data,38,16),
  substring(authenticator_data,56,(get_byte(authenticator_data,53)<<8) + get_byte(authenticator_data,54)),
  substring(authenticator_data,56+(get_byte(authenticator_data,53)<<8) + get_byte(authenticator_data,54))
FROM decode(cbor.to_jsonb(cbor := attestation_object, encode_binary_format := 'base64')->>'authData','base64') AS authenticator_data
CROSS JOIN webauthn.parse_authenticator_data(authenticator_data)
$$;
CREATE TABLE webauthn.credential_challenges (
challenge bytea NOT NULL,
user_name text NOT NULL,
user_id bytea NOT NULL,
user_display_name text NOT NULL,
relying_party_name text NOT NULL,
relying_party_id text,
user_verification webauthn.user_verification_requirement NOT NULL,
attestation webauthn.attestation_conveyance_preference NOT NULL,
timeout interval NOT NULL,
challenge_at timestamptz NOT NULL,
require_resident_key boolean NOT NULL DEFAULT FALSE,
PRIMARY KEY (challenge),
CONSTRAINT reasonable_timeout CHECK (timeout BETWEEN '30000 ms' AND '600000 ms')
);

SELECT pg_catalog.pg_extension_config_dump('credential_challenges', '');

COMMENT ON TABLE webauthn.credential_challenges IS 'Used by webauthn.init_credential() to store credential challenges.';

COMMENT ON COLUMN webauthn.credential_challenges.challenge IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-challenge';
COMMENT ON COLUMN webauthn.credential_challenges.user_name IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user';
COMMENT ON COLUMN webauthn.credential_challenges.user_id IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id';
COMMENT ON COLUMN webauthn.credential_challenges.user_display_name IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname';
COMMENT ON COLUMN webauthn.credential_challenges.user_verification IS 'https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification';
COMMENT ON COLUMN webauthn.credential_challenges.attestation IS 'https://www.w3.org/TR/webauthn-2/#enum-attestation-convey';
COMMENT ON COLUMN webauthn.credential_challenges.timeout IS 'https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout';
COMMENT ON COLUMN webauthn.credential_challenges.relying_party_name IS 'https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params';
COMMENT ON COLUMN webauthn.credential_challenges.relying_party_id IS 'https://www.w3.org/TR/webauthn-2/#relying-party-identifier';
COMMENT ON COLUMN webauthn.credential_challenges.challenge_at IS 'Timestamp of when the challenge was created by webauthn.init_credential()';
COMMENT ON COLUMN webauthn.credential_challenges.require_resident_key IS 'https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey';
CREATE OR REPLACE FUNCTION webauthn.credential_challenge_user_verification(challenge bytea)
RETURNS webauthn.user_verification_requirement
STABLE
LANGUAGE sql AS $$
SELECT user_verification FROM webauthn.credential_challenges WHERE challenge = $1
$$;
CREATE OR REPLACE FUNCTION webauthn.credential_challenge_expiration(challenge bytea)
RETURNS timestamptz
STABLE
LANGUAGE sql AS $$
SELECT challenge_at + timeout FROM webauthn.credential_challenges WHERE challenge = $1
$$;
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
CREATE TABLE webauthn.assertion_challenges (
challenge bytea NOT NULL,
user_name text,
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
CREATE OR REPLACE FUNCTION webauthn.assertion_challenge_user_verification(challenge bytea)
RETURNS webauthn.user_verification_requirement
STABLE
LANGUAGE sql AS $$
SELECT user_verification FROM webauthn.assertion_challenges WHERE challenge = $1
$$;
CREATE OR REPLACE FUNCTION webauthn.assertion_challenge_expiration(challenge bytea)
RETURNS timestamptz
STABLE
LANGUAGE sql AS $$
SELECT challenge_at + timeout FROM webauthn.assertion_challenges WHERE challenge = $1
$$;
CREATE OR REPLACE FUNCTION webauthn.credential_public_key(credential_id bytea)
RETURNS bytea
STABLE
LANGUAGE sql AS $$
SELECT public_key FROM webauthn.credentials WHERE credential_id = $1
$$;
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
user_handle bytea,
verified_at timestamptz NOT NULL,
PRIMARY KEY (signature),
UNIQUE (challenge),
CONSTRAINT client_data_json_type CHECK ('webauthn.get' = webauthn.from_utf8(client_data_json)::jsonb->>'type'),
CONSTRAINT client_data_json_challenge CHECK (challenge = webauthn.base64url_decode(webauthn.from_utf8(client_data_json)::jsonb->>'challenge')),
CONSTRAINT user_handle_equal_or_null CHECK (user_handle = user_id),
CONSTRAINT user_verified_or_not_required CHECK (user_verified OR webauthn.assertion_challenge_user_verification(challenge) <> 'required'),
CONSTRAINT verified_before_timeout CHECK (verified_at < webauthn.assertion_challenge_expiration(challenge)),
CONSTRAINT verified_signature CHECK (COALESCE(public.ecdsa_verify(
  public_key := webauthn.credential_public_key(credential_id),
  input_data := substring(authenticator_data,1,37) || public.digest(client_data_json,'sha256'),
  signature := webauthn.decode_asn1_der_signature(signature),
  hash_func := 'sha256',
  curve_name := 'secp256r1'),FALSE))
);

SELECT pg_catalog.pg_extension_config_dump('assertions', '');

COMMENT ON TABLE webauthn.assertions IS 'Used by webauthn.verify_assertion() to store verified assertions.';

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
COMMENT ON COLUMN webauthn.assertions.user_handle IS 'https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-userhandle';
COMMENT ON COLUMN webauthn.assertions.verified_at IS 'Timestamp of when the assertion was verified by webauthn.verify_assertion()';
CREATE OR REPLACE FUNCTION webauthn.get_credential_creation_options(challenge bytea)
RETURNS jsonb
LANGUAGE sql
AS $$
SELECT
jsonb_build_object(
  'publicKey', jsonb_build_object(
    'rp', jsonb_strip_nulls(jsonb_build_object(
      'name', relying_party_name,
      'id', relying_party_id
    )),
    'user', jsonb_build_object(
      'name', user_name,
      'displayName', user_display_name,
      'id', webauthn.base64url_encode(user_id)
    ),
    'challenge', webauthn.base64url_encode(challenge),
    'pubKeyCredParams', jsonb_build_array(
      jsonb_build_object(
        'type', 'public-key',
        'alg', -7
      )
    ),
    'authenticatorSelection', jsonb_build_object(
      'requireResidentKey', require_resident_key,
      'userVerification', user_verification
    ),
    'timeout', (extract(epoch from timeout)*1000)::bigint,
    'attestation', attestation
  )
)
FROM webauthn.credential_challenges
WHERE credential_challenges.challenge = get_credential_creation_options.challenge
$$;
CREATE OR REPLACE FUNCTION webauthn.init_credential(
  challenge bytea,
  user_name text,
  user_id bytea,
  user_display_name text,
  relying_party_name text,
  relying_party_id text DEFAULT NULL,
  require_resident_key boolean DEFAULT FALSE,
  user_verification webauthn.user_verification_requirement DEFAULT 'preferred',
  attestation webauthn.attestation_conveyance_preference DEFAULT 'none',
  timeout interval DEFAULT '5 minutes'::interval,
  challenge_at timestamptz DEFAULT now()
)
RETURNS jsonb
LANGUAGE sql
AS $$
INSERT INTO webauthn.credential_challenges
       (challenge, user_name, user_id, user_display_name, relying_party_name, relying_party_id, require_resident_key, user_verification, attestation, timeout, challenge_at)
VALUES (challenge, user_name, user_id, user_display_name, relying_party_name, relying_party_id, require_resident_key, user_verification, attestation, timeout, challenge_at)
RETURNING webauthn.get_credential_creation_options(challenge)
$$;
CREATE OR REPLACE FUNCTION webauthn.make_credential(
  OUT user_id bytea,
  credential_id text,
  credential_type webauthn.credential_type,
  attestation_object text,
  client_data_json text,
  credential_at timestamptz DEFAULT now()
)
RETURNS bytea
LANGUAGE sql
AS $$
INSERT INTO webauthn.credentials (credential_id, credential_type, attestation_object, client_data_json, challenge, user_name, user_id, credential_at)
SELECT
  webauthn.base64url_decode(make_credential.credential_id),
  make_credential.credential_type,
  webauthn.base64url_decode(make_credential.attestation_object),
  webauthn.base64url_decode(make_credential.client_data_json),
  credential_challenges.challenge,
  credential_challenges.user_name,
  credential_challenges.user_id,
  make_credential.credential_at
FROM webauthn.credential_challenges
WHERE credential_challenges.challenge = webauthn.base64url_decode(webauthn.from_utf8(webauthn.base64url_decode(make_credential.client_data_json))::jsonb->>'challenge')
RETURNING credentials.user_id
$$;
CREATE OR REPLACE FUNCTION webauthn.get_credentials(
  challenge bytea,
  user_name text DEFAULT NULL,
  user_verification webauthn.user_verification_requirement DEFAULT 'preferred',
  timeout interval DEFAULT '5 minutes'::interval,
  relying_party_id text DEFAULT NULL,
  challenge_at timestamptz DEFAULT now()
)
RETURNS jsonb
LANGUAGE sql
AS $$
WITH store_assertion_challenge AS (
  INSERT INTO webauthn.assertion_challenges
         (challenge, user_name, user_verification, timeout, relying_party_id, challenge_at)
  VALUES (challenge, user_name, user_verification, timeout, relying_party_id, challenge_at)
  RETURNING TRUE
)
SELECT jsonb_strip_nulls(jsonb_build_object(
  'publicKey', jsonb_build_object(
    'userVerification', get_credentials.user_verification,
    'allowCredentials', COALESCE(jsonb_agg(
      jsonb_build_object(
        'type', credentials.credential_type,
        'id', webauthn.base64url_encode(credentials.credential_id)
      )
    ORDER BY credentials.credential_id),jsonb_build_array()),
    'timeout', (extract(epoch from get_credentials.timeout)*1000)::bigint,
    'challenge', webauthn.base64url_encode(get_credentials.challenge),
    'rpId', get_credentials.relying_party_id
  )
))
FROM webauthn.credentials
WHERE credentials.user_name = get_credentials.user_name
$$;
CREATE OR REPLACE FUNCTION webauthn.verify_assertion(
  OUT user_id bytea,
  credential_id text,
  credential_type webauthn.credential_type,
  authenticator_data text,
  client_data_json text,
  signature text,
  user_handle text,
  verified_at timestamptz DEFAULT now()
)
RETURNS bytea
LANGUAGE sql
AS $$
WITH
decoded_input AS (
  SELECT
    webauthn.base64url_decode(credential_id) AS credential_id,
    credential_type,
    webauthn.base64url_decode(authenticator_data) AS authenticator_data,
    webauthn.base64url_decode(client_data_json) AS client_data_json,
    webauthn.base64url_decode(webauthn.from_utf8(webauthn.base64url_decode(client_data_json))::jsonb->>'challenge') AS challenge,
    webauthn.base64url_decode(signature) AS signature,
    webauthn.base64url_decode(NULLIF(user_handle,'')) AS user_handle,
    verified_at
)
INSERT INTO webauthn.assertions (signature, credential_id, challenge, authenticator_data, client_data_json, user_id, user_handle, verified_at)
SELECT
  decoded_input.signature,
  credentials.credential_id,
  assertion_challenges.challenge,
  decoded_input.authenticator_data,
  decoded_input.client_data_json,
  credentials.user_id,
  decoded_input.user_handle,
  decoded_input.verified_at
FROM decoded_input
JOIN webauthn.assertion_challenges ON assertion_challenges.challenge = decoded_input.challenge
JOIN webauthn.credentials ON  credentials.credential_id   = decoded_input.credential_id
                         AND  credentials.credential_type = decoded_input.credential_type
                         AND (credentials.user_name      <> assertion_challenges.user_name) IS NOT TRUE
RETURNING assertions.user_id
$$;
CREATE OR REPLACE FUNCTION webauthn.generate_test()
RETURNS text
LANGUAGE sql
AS $$
-- 
-- Script to generate a new test file from real data in tables
--
-- Usage:
-- psql -t -A -c "SELECT webauthn.generate_test()" > sql/[new test name].sql
--
SELECT format($SQL$BEGIN;

CREATE EXTENSION IF NOT EXISTS webauthn CASCADE;

SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '%1$s'::bytea,
  user_name := %2$s,
  user_id := '%3$s'::bytea,
  user_display_name := %4$s,
  relying_party_name := %5$s,
  relying_party_id := %6$s,
  user_verification := '%7$s',
  attestation := '%8$s',
  timeout := '%9$s',
  challenge_at := '%10$s'
));

SELECT * FROM webauthn.make_credential(
  credential_id := '%11$s',
  credential_type := '%12$s',
  attestation_object := '%13$s',
  client_data_json := '%14$s',
  credential_at := '%15$s'
);

SELECT jsonb_pretty(webauthn.get_credentials(
  challenge := '%16$s'::bytea,
  user_name := %17$s,
  user_verification := '%18$s',
  timeout := '%19$s',
  relying_party_id := %20$s,
  challenge_at := '%21$s'
));

SELECT * FROM webauthn.verify_assertion(
  credential_id := '%22$s',
  credential_type := '%23$s',
  authenticator_data := '%24$s',
  client_data_json := '%25$s',
  signature := '%26$s',
  user_handle := %27$s,
  verified_at := '%28$s'
);

ROLLBACK;$SQL$,
credential_challenges.challenge,
quote_literal(credential_challenges.user_name),
credential_challenges.user_id,
quote_literal(credential_challenges.user_display_name),
quote_literal(credential_challenges.relying_party_name),
quote_nullable(credential_challenges.relying_party_id),
credential_challenges.user_verification,
credential_challenges.attestation,
credential_challenges.timeout,
credential_challenges.challenge_at,
webauthn.base64url_encode(credentials.credential_id),
credentials.credential_type,
webauthn.base64url_encode(credentials.attestation_object),
webauthn.base64url_encode(credentials.client_data_json),
credentials.credential_at,
assertion_challenges.challenge,
quote_literal(assertion_challenges.user_name),
assertion_challenges.user_verification,
assertion_challenges.timeout,
quote_nullable(assertion_challenges.relying_party_id),
assertion_challenges.challenge_at,
webauthn.base64url_encode(assertions.credential_id),
credentials.credential_type,
webauthn.base64url_encode(assertions.authenticator_data),
webauthn.base64url_encode(assertions.client_data_json),
webauthn.base64url_encode(assertions.signature),
quote_nullable(webauthn.base64url_encode(assertions.user_handle)),
assertions.verified_at
)
FROM webauthn.credential_challenges
JOIN webauthn.credentials ON credentials.challenge = credential_challenges.challenge
JOIN webauthn.assertions ON assertions.credential_id = credentials.credential_id
JOIN webauthn.assertion_challenges ON assertion_challenges.challenge = assertions.challenge
ORDER BY credential_challenges.challenge_at, assertion_challenges.challenge_at
$$;
