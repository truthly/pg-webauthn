BEGIN;

CREATE EXTENSION IF NOT EXISTS webauthn CASCADE;

SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\x160cfbab84567e395818dcfa8715d09a96c06423897e43aa3f883133fffeff43'::bytea,
  user_name := 'Alice',
  user_id := '\x4cb878633f5ebdffc1e927ba1265787096d2b922fe8fd8884c6413ae42220cf569de10cd741b2868c1bbd56f47d68f007c8648a5f634d7702e09f28d9ec6c03f'::bytea,
  user_display_name := 'Alice',
  relying_party_name := 'localhost',
  relying_party_id := NULL,
  user_verification := 'discouraged',
  timeout := '00:05:00'::interval,
  challenge_at := '2020-12-15 07:16:31.480788+01'::timestamptz
));

SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\x3ff8b78974fd33cd48854e97faebe0a786624ebf018fa7c36f5aa41b3b58261d'::bytea,
  user_name := 'Bob',
  user_id := '\xa6162640d33501e08e66a9a5ba24c7d3ce2d3bd3df26bf355fbf7f59dc59cc625f95408825347dacba808d76abc0397f0f1c8836e64b03a00419b37d0a2922de'::bytea,
  user_display_name := 'Bob',
  relying_party_name := 'localhost',
  relying_party_id := NULL,
  user_verification := 'discouraged',
  timeout := '00:05:00'::interval,
  challenge_at := '2020-12-15 07:16:59.006273+01'::timestamptz
));

-- Alice
SELECT * FROM webauthn.store_credential(
  credential_id := 'bUbZdS9skR2dQBTgiQ1EBMxGxTkkkyCVytqnGpkeLF-FG-fjVMP50-aTEOu_kBvegtDz6IC2ISUJ7OPDnolN2w',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQG1G2XUvbJEdnUAU4IkNRATMRsU5JJMglcrapxqZHixfhRvn41TD-dPmkxDrv5Ab3oLQ8-iAtiElCezjw56JTdulAQIDJiABIVggQm7waBO4Gb1_EHHoPULS3qN2aM8RRP58alCkfvhc6iAiWCAd7SkDznHs8hlawekX26FwinCbr6JiR23Yu9X6NckfSQ',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRmd6N3E0UldmamxZR056Nmh4WFFtcGJBWkNPSmZrT3FQNGd4TV9fLV8wTSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  credential_at := '2020-12-15 07:16:33.660809+01'
);

-- Bob
SELECT * FROM webauthn.store_credential(
  credential_id := 'gEH1WKLdwQAZWOF6qQvYqsIoHXZWGFQWueQ8BgfnoAkKy6q8uhx1K21is34td03hb699SWet336gIw2KhmbDGw',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQIBB9Vii3cEAGVjheqkL2KrCKB12VhhUFrnkPAYH56AJCsuqvLocdSttYrN-LXdN4W-vfUlnrd9-oCMNioZmwxulAQIDJiABIVgg3gD_CNjxdR6Ur-2xfeqxzusT8FrXYZPI8Ce5Z7Hqk5QiWCDUfcMaNwWtL_0DAMJmSqhna4sNGRYAK2_h89Lg04oE9A',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUF9pM2lYVDlNODFJaFU2WC11dmdwNFppVHI4Qmo2ZkRiMXFrR3p0WUpoMCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  credential_at := '2020-12-15 07:17:01.542059+01'
);

SELECT jsonb_pretty(webauthn.get_credentials(
  challenge := '\x03cd8c3265e2bf5f2d501f93165a8a3df521105f32d90edd79587d5af4086647'::bytea,
  user_name := 'Alice',
  user_verification := 'discouraged',
  timeout := '00:05:00',
  relying_party_id := NULL,
  challenge_at := '2020-12-15 07:16:35.233386+01'
));

SELECT jsonb_pretty(webauthn.get_credentials(
  challenge := '\x61748759ce63ec2c4d51915e62835337b185cc1ac59cb8775a4b412f93c8178a'::bytea,
  user_name := 'Bob',
  user_verification := 'discouraged',
  timeout := '00:05:00',
  relying_party_id := NULL,
  challenge_at := '2020-12-15 07:17:02.700857+01'
));

--
-- Try to use Bob's credential_id but Alice's authenticator_data + client_data_json + signature
--
-- The challenge is extracted from client_data_json,
-- and will therefore match Alice's assertion_challenge,
-- but since the user_name for credential_id doesn't match,
-- no row will be found and NULL will be returned.
--
SELECT * FROM webauthn.verify_assertion(
  credential_id := 'gEH1WKLdwQAZWOF6qQvYqsIoHXZWGFQWueQ8BgfnoAkKy6q8uhx1K21is34td03hb699SWet336gIw2KhmbDGw',
  credential_type := 'public-key',
  authenticator_data := 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAg',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQTgyTU1tWGl2MTh0VUItVEZscUtQZlVoRUY4eTJRN2RlVmg5V3ZRSVprYyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  signature := 'MEUCIQD7T-_qAdadYWV-61kHWuB3j1ZGXpRmCYpYcBB7VZfOWgIgVlYZ3_kYtNEuE4u_J6ano653qExgp5o1-hTRHSkPMOo',
  user_handle := NULL,
  verified_at := '2020-12-15 07:16:36.355164+01'
);

ROLLBACK;
