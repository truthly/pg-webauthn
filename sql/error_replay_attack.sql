--
-- In this test we will simulate different "replay attacks",
-- by reusing values that are guaranteed to be unique
-- thanks to primary keys and unique constraints on columns.
--
-- We will use the SAVEPOINT ... ROLLBACK TO PostgreSQL feature,
-- to let errors happen that we want to test for,
-- but to roll back to the state before the error,
-- allowing the rest of the test to continue
-- which depends on the data produced so far.
-- Otherwise we would have to test all steps from start
-- in separate test files, which would be unnecessarily tedious.
--
-- See: https://www.postgresql.org/docs/current/sql-rollback-to.html
--

BEGIN;

CREATE EXTENSION IF NOT EXISTS webauthn CASCADE;

SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\x30d5843dc347fe7d9328675e964b7efded1f3112bb0f928e6fb147fc86c564ba'::bytea,
  user_name := 'alex.p.mueller@example.com',
  user_id := '\x927f90c2323748d1e2c24c39af7d240423f5d1d0fbed1d77ccfe372b2d67ab244f988bf5cf7c72f8b7f0fdcb359498a935c26f4b8fc1e2b564b54181a83468da'::bytea,
  user_display_name := 'Alex P. Müller',
  relying_party_name := 'ACME Corporation',
  relying_party_id := NULL,
  user_verification := 'discouraged',
  timeout := '00:05:00'::interval,
  challenge_at := '2020-12-15 08:08:56.596311+01'
));

SAVEPOINT init_credential;
SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\x30d5843dc347fe7d9328675e964b7efded1f3112bb0f928e6fb147fc86c564ba'::bytea,
  user_name := 'alex.p.mueller@example.com',
  user_id := '\x927f90c2323748d1e2c24c39af7d240423f5d1d0fbed1d77ccfe372b2d67ab244f988bf5cf7c72f8b7f0fdcb359498a935c26f4b8fc1e2b564b54181a83468da'::bytea,
  user_display_name := 'Alex P. Müller',
  relying_party_name := 'ACME Corporation',
  relying_party_id := NULL,
  user_verification := 'discouraged',
  timeout := '00:05:00'::interval,
  challenge_at := '2020-12-15 08:08:56.596311+01'
));
ROLLBACK TO init_credential;

SELECT * FROM webauthn.make_credential(
  credential_id := 'AXNBRMEOFaYGaROrEph1sOZ4kftILi9ry8vCw2fPQf712glIpQDRX-7HBQ2VmQVpRWU3A6Cu_XcKbnoC2SSy5_o0Z2qO7Owdnms8K0GsiqvWx3WtUPn0a8Ga6QWbkEvsUXOp9ikZ9v4DeYeTzzp0h2uAlx8ezayuqjB_uMQyB5kBVwRhkhZEmzQCl097',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBEUmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRV_YYQytzgACNbzGCmSLCyXx8FUDAI0Bc0FEwQ4VpgZpE6sSmHWw5niR-0guL2vLy8LDZ89B_vXaCUilANFf7scFDZWZBWlFZTcDoK79dwpuegLZJLLn-jRnao7s7B2eazwrQayKq9bHda1Q-fRrwZrpBZuQS-xRc6n2KRn2_gN5h5PPOnSHa4CXHx7NrK6qMH-4xDIHmQFXBGGSFkSbNAKXT3ulAQIDJiABIVggxMJIqQI-xxUSsJGR9HIbIZHKIiN-alA9B2SdzIzjzwkiWCCHOhTTOTy3-H2rNbbfs8jojm8AeaNYEfQCplT5aYjwtA',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTU5XRVBjTkhfbjJUS0dkZWxrdC1fZTBmTVJLN0Q1S09iN0ZIX0liRlpMbyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ',
  credential_at := '2020-12-15 08:09:00.20485+01'
);

SAVEPOINT make_credential;
SELECT * FROM webauthn.make_credential(
  credential_id := 'AXNBRMEOFaYGaROrEph1sOZ4kftILi9ry8vCw2fPQf712glIpQDRX-7HBQ2VmQVpRWU3A6Cu_XcKbnoC2SSy5_o0Z2qO7Owdnms8K0GsiqvWx3WtUPn0a8Ga6QWbkEvsUXOp9ikZ9v4DeYeTzzp0h2uAlx8ezayuqjB_uMQyB5kBVwRhkhZEmzQCl097',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBEUmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRV_YYQytzgACNbzGCmSLCyXx8FUDAI0Bc0FEwQ4VpgZpE6sSmHWw5niR-0guL2vLy8LDZ89B_vXaCUilANFf7scFDZWZBWlFZTcDoK79dwpuegLZJLLn-jRnao7s7B2eazwrQayKq9bHda1Q-fRrwZrpBZuQS-xRc6n2KRn2_gN5h5PPOnSHa4CXHx7NrK6qMH-4xDIHmQFXBGGSFkSbNAKXT3ulAQIDJiABIVggxMJIqQI-xxUSsJGR9HIbIZHKIiN-alA9B2SdzIzjzwkiWCCHOhTTOTy3-H2rNbbfs8jojm8AeaNYEfQCplT5aYjwtA',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTU5XRVBjTkhfbjJUS0dkZWxrdC1fZTBmTVJLN0Q1S09iN0ZIX0liRlpMbyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ',
  credential_at := '2020-12-15 08:09:00.20485+01'
);
ROLLBACK TO make_credential;

SELECT jsonb_pretty(webauthn.get_credentials(
  challenge := '\x014fc58eef9713a5c89e6094d5847faf39dd05efac8713a6024c5812e9178599'::bytea,
  user_name := 'alex.p.mueller@example.com',
  user_verification := 'discouraged',
  timeout := '00:05:00',
  relying_party_id := NULL,
  challenge_at := '2020-12-15 08:09:01.608713+01'
));

SAVEPOINT get_credentials;
SELECT jsonb_pretty(webauthn.get_credentials(
  challenge := '\x014fc58eef9713a5c89e6094d5847faf39dd05efac8713a6024c5812e9178599'::bytea,
  user_name := 'alex.p.mueller@example.com',
  user_verification := 'discouraged',
  timeout := '00:05:00',
  relying_party_id := NULL,
  challenge_at := '2020-12-15 08:09:01.608713+01'
));
ROLLBACK TO get_credentials;

SELECT * FROM webauthn.verify_assertion(
  credential_id := 'AXNBRMEOFaYGaROrEph1sOZ4kftILi9ry8vCw2fPQf712glIpQDRX-7HBQ2VmQVpRWU3A6Cu_XcKbnoC2SSy5_o0Z2qO7Owdnms8K0GsiqvWx3WtUPn0a8Ga6QWbkEvsUXOp9ikZ9v4DeYeTzzp0h2uAlx8ezayuqjB_uMQyB5kBVwRhkhZEmzQCl097',
  credential_type := 'public-key',
  authenticator_data := 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFX9hhDw',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVVfRmp1LVhFNlhJbm1DVTFZUl9yem5kQmUtc2h4T21Ba3hZRXVrWGhaayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  signature := 'MEYCIQCpphN2t04K-4uEft7Cm_xxcH1WuZuz3cSkGkMM7_bV-gIhAKwNJ9HYgZYpBJG-1xD6k9MRQU0J39HiqD7X_g9Wx_nU',
  user_handle := 'kn-QwjI3SNHiwkw5r30kBCP10dD77R13zP43Ky1nqyRPmIv1z3xy-Lfw_cs1lJipNcJvS4_B4rVktUGBqDRo2g',
  verified_at := '2020-12-15 08:09:03.3849+01'
);

SAVEPOINT verify_assertion;
SELECT * FROM webauthn.verify_assertion(
  credential_id := 'AXNBRMEOFaYGaROrEph1sOZ4kftILi9ry8vCw2fPQf712glIpQDRX-7HBQ2VmQVpRWU3A6Cu_XcKbnoC2SSy5_o0Z2qO7Owdnms8K0GsiqvWx3WtUPn0a8Ga6QWbkEvsUXOp9ikZ9v4DeYeTzzp0h2uAlx8ezayuqjB_uMQyB5kBVwRhkhZEmzQCl097',
  credential_type := 'public-key',
  authenticator_data := 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFX9hhDw',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVVfRmp1LVhFNlhJbm1DVTFZUl9yem5kQmUtc2h4T21Ba3hZRXVrWGhaayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  signature := 'MEYCIQCpphN2t04K-4uEft7Cm_xxcH1WuZuz3cSkGkMM7_bV-gIhAKwNJ9HYgZYpBJG-1xD6k9MRQU0J39HiqD7X_g9Wx_nU',
  user_handle := 'kn-QwjI3SNHiwkw5r30kBCP10dD77R13zP43Ky1nqyRPmIv1z3xy-Lfw_cs1lJipNcJvS4_B4rVktUGBqDRo2g',
  verified_at := '2020-12-15 08:09:03.3849+01'
);
ROLLBACK TO verify_assertion;

ROLLBACK;
