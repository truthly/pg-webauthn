BEGIN;

CREATE EXTENSION IF NOT EXISTS webauthn CASCADE;

SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\xd4ef72bc4cd34733abb91602e4aa5cc4d446fae92aa3dbcf9e2c2052a5fc9857'::bytea,
  user_name := 'alex.p.mueller@example.com',
  user_id := '\xc172e425a2e82488bda49038fd66970a94cfa9f3bfa740d421f6040cdb3cb44f57cb3326ac4d0f7e16ed9afe66499ad8ded1f9ce29db45c8e48ba989da60e163'::bytea,
  user_display_name := 'Alex P. Müller',
  relying_party_name := 'ACME Corporation',
  relying_party_id := NULL,
  user_verification := 'discouraged',
  timeout := '29999 ms',
  challenge_at := '2020-12-15 08:30:09.384246+01'
));

ROLLBACK;
