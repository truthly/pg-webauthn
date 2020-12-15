BEGIN;

CREATE EXTENSION webauthn CASCADE;

SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\xd4ef72bc4cd34733abb91602e4aa5cc4d446fae92aa3dbcf9e2c2052a5fc9857'::bytea,
  user_name := 'alex.p.mueller@example.com',
  user_id := '\xc172e425a2e82488bda49038fd66970a94cfa9f3bfa740d421f6040cdb3cb44f57cb3326ac4d0f7e16ed9afe66499ad8ded1f9ce29db45c8e48ba989da60e163'::bytea,
  user_display_name := 'Alex P. Müller',
  relying_party_name := 'ACME Corporation',
  relying_party_id := NULL,
  user_verification := 'discouraged',
  timeout := '00:05:00',
  challenge_at := '2020-12-15 08:30:09.384246+01'
));

SELECT * FROM webauthn.make_credential(
  credential_id := 'TMvc9cgQ4S3H498Qez2ilQdkDS02s0sR7wXyiaKrUphXQRNqiP1pfzoBPsEey8wjHDUXh_A-91zqP_H0bkeohA',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEzL3PXIEOEtx-PfEHs9opUHZA0tNrNLEe8F8omiq1KYV0ETaoj9aX86AT7BHsvMIxw1F4fwPvdc6j_x9G5HqISlAQIDJiABIVggf6kt0GZu7nwT3be2JJsMj5-6Q2CFfE4V0vxjSitaH48iWCDbmYOzGUadNecZo7k-GsKShUzT_yrVCJhoGwoy_7y8ag',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMU85eXZFelRSek9ydVJZQzVLcGN4TlJHLXVrcW85dlBuaXdnVXFYOG1GYyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  credential_at := '2020-12-15 08:30:12.395851+01'
);

SELECT jsonb_pretty(webauthn.get_credentials(
  challenge := '\x6a19f4c245388de79290f5338196c51e19fc33273afb1891d4e90296bfe06d0b'::bytea,
  user_name := 'alex.p.mueller@example.com',
  user_verification := 'discouraged',
  timeout := '00:05:00',
  relying_party_id := NULL,
  challenge_at := '2020-12-15 08:30:13.733084+01'
));

SELECT * FROM webauthn.verify_assertion(
  credential_id := 'TMvc9cgQ4S3H498Qez2ilQdkDS02s0sR7wXyiaKrUphXQRNqiP1pfzoBPsEey8wjHDUXh_A-91zqP_H0bkeohA',
  credential_type := 'public-key',
  authenticator_data := 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYWhuMHdrVTRqZWVTa1BVemdaYkZIaG44TXljNi14aVIxT2tDbHJfZ2JRcyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  signature := 'MEQCIBD6sBMH8-7Vm8EWASZe-qtSS1DQF72c3-7E9hsByqjWAiBpxun42by9uk5UeMt1sIQzLVGwviwhcBsVfHyHq7mAVw',
  user_handle := NULL,
  verified_at := '2020-12-15 08:40:14.679551+01'
);

ROLLBACK;
