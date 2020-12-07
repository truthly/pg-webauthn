-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION webauthn" to load this file. \quit
CREATE OR REPLACE FUNCTION webauthn.base64_url_decode(text)
RETURNS bytea
IMMUTABLE
LANGUAGE sql AS $$
SELECT decode(rpad(translate($1,'-_','+/'),length($1) + (4 - length($1) % 4) % 4, '='),'base64')
$$;
CREATE OR REPLACE FUNCTION webauthn.decode_cbor(cbor bytea)
RETURNS TABLE (
  item integer,
  map_item_count integer,
  text_string text,
  bytes bytea,
  integer_value integer
)
IMMUTABLE
LANGUAGE sql
AS $$
/*
Only a few major types / additional type value combinations implemented,
the bare minimum to decode the WebAuthn "attestationObject".

https://github.com/fido-alliance/webauthn-demo/blob/master/utils.js#L200
*/
WITH RECURSIVE x AS (
  SELECT
    decode_cbor.cbor,
    0::integer AS item,
    NULL::integer AS map_item_count,
    NULL::text COLLATE "default" AS text_string,
    NULL::bytea AS bytes,
    NULL::integer AS integer_value
  UNION ALL
  SELECT
    substring(x.cbor,byte_offset) AS cbor,
    item+1 AS item,
    CASE WHEN major_type_value = 5 AND additional_type_value <= 23
         THEN additional_type_value
    END AS map_item_count,
    CASE WHEN major_type_value = 3 AND additional_type_value <= 23
         THEN convert_from(substring(x.cbor,2,additional_type_value),'utf8')
    END::text COLLATE "default" AS text_string,
    CASE WHEN major_type_value = 2 AND additional_type_value <= 23
         THEN substring(x.cbor,2,additional_type_value)
         WHEN major_type_value = 2 AND additional_type_value = 24
         THEN substring(x.cbor,3,get_byte(x.cbor,1))
    END AS bytes,
    CASE WHEN major_type_value = 0 AND additional_type_value <= 23
         THEN additional_type_value
         WHEN major_type_value = 1 AND additional_type_value <= 23
         THEN -1-additional_type_value
    END AS integer_value
  FROM x
  JOIN LATERAL (VALUES(
    (get_byte(x.cbor,0)>>5)&'111'::bit(3)::integer,
    get_byte(x.cbor,0)&'11111'::bit(5)::integer
  )) AS data_item_header(major_type_value,additional_type_value) ON TRUE
  JOIN LATERAL (VALUES(CASE
    WHEN major_type_value IN (2,3) AND additional_type_value <= 23 THEN 2+additional_type_value
    WHEN major_type_value = 5 THEN 2
    WHEN major_type_value = 2 AND additional_type_value = 24 THEN 3+get_byte(x.cbor,1)
    WHEN major_type_value = 0 AND additional_type_value <= 23 THEN 2
    WHEN major_type_value = 1 AND additional_type_value <= 23 THEN 2
  END)) AS next_item(byte_offset) ON TRUE
  WHERE length(x.cbor) > 0
)
SELECT
  item,
  map_item_count,
  text_string,
  bytes,
  integer_value
FROM x
WHERE item > 0
ORDER BY item
$$;
CREATE OR REPLACE FUNCTION webauthn.cbor_to_json(cbor bytea)
RETURNS jsonb
IMMUTABLE
LANGUAGE sql
AS $$
WITH
items AS (
  SELECT * FROM webauthn.decode_cbor(cbor)
),
maps AS (
  SELECT
    map.item,
    COALESCE(jsonb_object_agg(
      COALESCE(keys.text_string,keys.integer_value::text),
      COALESCE(values.text_string,encode(values.bytes,'base64'))
    ) FILTER (WHERE values.integer_value IS NULL),jsonb_build_object())
    ||
    COALESCE(jsonb_object_agg(
      COALESCE(keys.text_string,keys.integer_value::text),
      values.integer_value
    ) FILTER (WHERE values.integer_value IS NOT NULL),jsonb_build_object())
    AS key_value_pairs
  FROM items AS map
  JOIN generate_series(1,map.map_item_count) AS map_index ON TRUE
  JOIN items AS keys ON keys.item = map.item+map_index*2-1
  JOIN items AS values ON values.item = map.item+map_index*2
  WHERE map.map_item_count > 0
  GROUP BY map.item
)
SELECT jsonb_agg(key_value_pairs) FROM maps
$$;
CREATE OR REPLACE FUNCTION webauthn.cose_ecdha_to_pkcs(cose_public_key bytea)
RETURNS bytea
IMMUTABLE
LANGUAGE sql
AS $$
-- https://github.com/fido-alliance/webauthn-demo/blob/master/utils.js#L105
-- \x04 tag byte not prepended since not wanted by pg-ecdsa
SELECT decode(cose_struct->0->>'-2','base64') || decode(cose_struct->0->>'-3','base64')
FROM webauthn.cbor_to_json(cose_public_key) AS cose_struct
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
OUT user_presence boolean,
OUT user_verification boolean,
OUT attested_credential_data boolean,
OUT extension_data boolean,
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
OUT user_presence boolean,
OUT user_verification boolean,
OUT attested_credential_data boolean,
OUT extension_data boolean,
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
FROM decode(webauthn.cbor_to_json(attestation_object)->0->>'authData','base64') AS authenticator_data
CROSS JOIN webauthn.parse_authenticator_data(authenticator_data)
$$;
CREATE OR REPLACE FUNCTION webauthn.relaying_party()
RETURNS text
STABLE
LANGUAGE sql
AS $$
SELECT token FROM (
  SELECT token, COUNT(*) OVER ()
  FROM ts_debug(current_setting('request.header.origin', TRUE))
  WHERE alias IN ('host','asciiword')
) AS X WHERE COUNT = 1
$$;
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
cross_origin boolean GENERATED ALWAYS AS ((webauthn.from_utf8(client_data_json)::jsonb->>'crossOrigin')::boolean) STORED,
remote_ip inet DEFAULT current_setting('request.header.X-Forwarded-For', TRUE)::inet,
created_at timestamptz NOT NULL DEFAULT now(),
PRIMARY KEY (credential_id),
UNIQUE (credential_raw_id),
UNIQUE (challenge_id),
CHECK (credential_raw_id = (webauthn.parse_attestation_object(attestation_object)).credential_id),
CHECK (webauthn.from_utf8(client_data_json)::jsonb->>'type' = 'webauthn.create')
);

SELECT pg_catalog.pg_extension_config_dump('credentials', '');
CREATE TABLE webauthn.assertions (
assertion_id bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
challenge_id bigint NOT NULL REFERENCES webauthn.challenges,
credential_id bigint NOT NULL REFERENCES webauthn.credentials,
authenticator_data bytea NOT NULL,
rp_id_hash bytea NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).rp_id_hash) STORED,
user_presence boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).user_presence) STORED,
user_verification boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).user_verification) STORED,
attested_credential_data boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).attested_credential_data) STORED,
extension_data boolean NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).extension_data) STORED,
sign_count bigint NOT NULL GENERATED ALWAYS AS ((webauthn.parse_authenticator_data(authenticator_data)).sign_count) STORED,
client_data_json bytea NOT NULL,
origin text NOT NULL GENERATED ALWAYS AS (webauthn.from_utf8(client_data_json)::jsonb->>'origin') STORED,
cross_origin boolean GENERATED ALWAYS AS ((webauthn.from_utf8(client_data_json)::jsonb->>'crossOrigin')::boolean) STORED,
signature bytea NOT NULL,
user_handle bytea NOT NULL,
verified boolean NOT NULL,
remote_ip inet DEFAULT current_setting('request.header.X-Forwarded-For', TRUE)::inet,
created_at timestamptz NOT NULL DEFAULT now(),
PRIMARY KEY (assertion_id),
UNIQUE (challenge_id),
CHECK (webauthn.from_utf8(client_data_json)::jsonb->>'type' = 'webauthn.get')
);

SELECT pg_catalog.pg_extension_config_dump('assertions', '');
CREATE OR REPLACE FUNCTION webauthn.init_credential(username text)
RETURNS jsonb
LANGUAGE sql
AS $$
WITH new_challenge AS (
  INSERT INTO webauthn.challenges (username, challenge, relaying_party)
  VALUES (username, gen_random_bytes(32), webauthn.relaying_party())
  RETURNING challenge, relaying_party
)
SELECT jsonb_build_object(
  'publicKey', jsonb_build_object(
    'challenge', encode(challenge,'base64'),
    'rp', jsonb_build_object(
      'name', relaying_party,
      'id', relaying_party
    ),
    'user', jsonb_build_object(
      'name', username,
      'displayName', username,
      'id', encode(username::bytea,'base64')
    ),
    'pubKeyCredParams', jsonb_build_array(
      jsonb_build_object(
        'type', 'public-key',
        'alg', -7
      )
    ),
    'authenticatorSelection', jsonb_build_object(
      'requireResidentKey', false,
      'userVerification', 'discouraged'
    ),
    'timeout', 60000,
    'extensions', jsonb_build_object(
      'txAuthSimple', ''
    ),
    'attestation', 'none'
  )
) FROM new_challenge
$$;
CREATE OR REPLACE FUNCTION webauthn.make_credential(username text, challenge text, credential_raw_id text, credential_type text, attestation_object text, client_data_json text)
RETURNS boolean
LANGUAGE sql
AS $$
WITH
consume_challenge AS (
  UPDATE webauthn.challenges SET
    consumed_at = now()
  WHERE challenges.username = make_credential.username
  AND challenges.relaying_party = webauthn.relaying_party()
  AND challenges.challenge = decode(make_credential.challenge,'base64')
  AND challenges.challenge = webauthn.base64_url_decode(webauthn.from_utf8(decode(client_data_json,'base64'))::jsonb->>'challenge')
  AND challenges.consumed_at IS NULL
  RETURNING challenge_id
)
INSERT INTO webauthn.credentials (challenge_id,credential_raw_id,credential_type,attestation_object,client_data_json)
SELECT
  consume_challenge.challenge_id,
  decode(credential_raw_id,'base64'),
  credential_type,
  decode(attestation_object,'base64'),
  decode(client_data_json,'base64')
FROM consume_challenge
RETURNING TRUE
$$;
CREATE OR REPLACE FUNCTION webauthn.get_credentials(username text)
RETURNS jsonb
LANGUAGE sql
AS $$
WITH new_challenge AS (
  INSERT INTO webauthn.challenges (username, relaying_party)
  VALUES (username, webauthn.relaying_party())
  RETURNING challenge, relaying_party
)
SELECT jsonb_build_object(
  'publicKey', jsonb_build_object(
    'userVerification', 'required',
    'extensions', jsonb_build_object(
      'txAuthSimple', ''
    ),
    'allowCredentials', jsonb_agg(
      jsonb_build_object(
        'type', 'public-key',
        'id', encode(credentials.credential_raw_id,'base64')
      )
    ORDER BY credentials.credential_id DESC),
    'timeout', 60000,
    'challenge', encode(new_challenge.challenge,'base64'),
    'rpId', new_challenge.relaying_party
  )
)
FROM new_challenge
JOIN webauthn.challenges ON challenges.username       = get_credentials.username
                        AND challenges.relaying_party = new_challenge.relaying_party
JOIN webauthn.credentials ON credentials.challenge_id = challenges.challenge_id
GROUP BY new_challenge.challenge, new_challenge.relaying_party
$$;
CREATE OR REPLACE FUNCTION webauthn.verify_assertion(credential_raw_id text, credential_type text, authenticator_data text, client_data_json text, signature text, user_handle text)
RETURNS boolean
LANGUAGE sql
AS $$
WITH
input AS (
  SELECT
    decode(credential_raw_id,'base64') AS credential_raw_id,
    credential_type,
    decode(authenticator_data,'base64') AS authenticator_data,
    decode(client_data_json,'base64') AS client_data_json,
    decode(signature,'base64') AS signature,
    decode(user_handle,'base64') AS user_handle
),
consume_challenge AS (
  UPDATE webauthn.challenges SET
    consumed_at = now()
  WHERE challenges.challenge = webauthn.base64_url_decode(webauthn.from_utf8(decode(client_data_json,'base64'))::jsonb->>'challenge')
  AND challenges.relaying_party = webauthn.relaying_party()
  AND challenges.consumed_at IS NULL
  RETURNING challenge_id
)
INSERT INTO webauthn.assertions (credential_id, challenge_id, authenticator_data, client_data_json, signature, user_handle, verified)
SELECT
  credentials.credential_id,
  consume_challenge.challenge_id,
  input.authenticator_data,
  input.client_data_json,
  input.signature,
  input.user_handle,
  COALESCE(ecdsa_verify(
    public_key := credentials.public_key,
    input_data := substring(input.authenticator_data,1,37) || digest(input.client_data_json,'sha256'),
    signature := webauthn.decode_asn1_der_signature(input.signature),
    hash_func := 'sha256',
    curve_name := 'secp256r1'
  ),FALSE)
FROM consume_challenge
CROSS JOIN input
JOIN webauthn.credentials ON credentials.credential_raw_id = input.credential_raw_id
                         AND credentials.credential_type = input.credential_type
RETURNING assertions.verified
$$;
