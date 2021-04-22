-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION webauthn" to load this file. \quit
CREATE OR REPLACE FUNCTION webauthn.store_credential(
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
  webauthn.base64url_decode(store_credential.credential_id),
  store_credential.credential_type,
  webauthn.base64url_decode(store_credential.attestation_object),
  webauthn.base64url_decode(store_credential.client_data_json),
  credential_challenges.challenge,
  credential_challenges.user_name,
  credential_challenges.user_id,
  store_credential.credential_at
FROM webauthn.credential_challenges
WHERE credential_challenges.challenge = webauthn.base64url_decode(webauthn.from_utf8(webauthn.base64url_decode(store_credential.client_data_json))::jsonb->>'challenge')
RETURNING credentials.user_id
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

SELECT * FROM webauthn.store_credential(
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
ALTER TABLE webauthn.assertions DROP CONSTRAINT verified_signature;
ALTER TABLE webauthn.assertions
ADD CONSTRAINT verified_signature CHECK (COALESCE(public.ecdsa_verify(
  public_key := webauthn.credential_public_key(credential_id),
  input_data := substring(authenticator_data,1,37) || public.digest(client_data_json,'sha256'),
  signature := webauthn.decode_asn1_der_signature(signature),
  hash_func := 'sha256',
  curve_name := 'secp256r1'),FALSE));
