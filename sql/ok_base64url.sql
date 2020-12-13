BEGIN;

CREATE EXTENSION webauthn CASCADE;

SET search_path TO webauthn, public, pg_temp;

SELECT webauthn.base64url_decode(webauthn.base64url_encode(x)) = x FROM gen_random_bytes(1) AS x;
SELECT webauthn.base64url_decode(webauthn.base64url_encode(x)) = x FROM gen_random_bytes(10) AS x;
SELECT webauthn.base64url_decode(webauthn.base64url_encode(x)) = x FROM gen_random_bytes(100) AS x;
SELECT webauthn.base64url_decode(webauthn.base64url_encode(x)) = x FROM gen_random_bytes(1000) AS x;

ROLLBACK;
