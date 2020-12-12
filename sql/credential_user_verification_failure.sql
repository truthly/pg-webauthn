BEGIN;

CREATE EXTENSION webauthn CASCADE;

SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\xdd9f0b3eed7683fd146fd4bad57148750948efcfde352671a47af0d1fb661296'::bytea,
  relying_party_name := 'Localhost'::text,
  relying_party_id := 'localhost'::text,
  user_name := 'test'::text,
  user_id := '\x26724ae177836743624b3801a0e7d3d363cb65d80a050930bceafe694feddb3265e96ed0ca26fc8bd6ba058fc91ac07e4fc34dd40c63cbaa2564246ef4495faa'::bytea,
  user_display_name := 'test'::text,
  timeout := '2 minutes'::interval,
  user_verification := 'required'
));

SELECT * FROM webauthn.make_credential(
  credential_id := '8Inm42Yv1OM4dsr83aFdG1mW4c1jrFEgRKH8WFFRbWJ_dj240A4DW_dyrukyzGcmUtf9NMiDU8PDt9DGzxxnQw',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQPCJ5uNmL9TjOHbK_N2hXRtZluHNY6xRIESh_FhRUW1if3Y9uNAOA1v3cq7pMsxnJlLX_TTIg1PDw7fQxs8cZ0OlAQIDJiABIVggnuXHyWYy5DWebYEgSF_H-ZHm0QtXXobEUBcouFlUIa8iWCD9aSRMdgEB58f9tblU_ZijuiHvj_66bH6WHkievyFU_g',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiM1o4TFB1MTJnXzBVYjlTNjFYRklkUWxJNzhfZU5TWnhwSHJ3MGZ0bUVwWSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ',
  relying_party_id := 'localhost'
);

/*
 * make_credential() MUST return NULL indicating failure
 * because user_verification is 'required'
 * but the user_verified flag in the attestation_object is FALSE.
 */

ROLLBACK;