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

CREATE EXTENSION webauthn CASCADE;

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
