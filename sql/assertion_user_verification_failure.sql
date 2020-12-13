BEGIN;

CREATE EXTENSION webauthn CASCADE;

SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\x238d389206bf51fce7ed8b71972ca8d74a99771ffff7c3365d8d4f2129fb51e2'::bytea,
  relying_party_name := 'Localhost'::text,
  relying_party_id := 'localhost'::text,
  user_name := 'test'::text,
  user_id := '\xae1a891beac7d8235f44daccfa9cebdc7f85c894549a2cf15da2df0ae3c65f299d0e9b44be8db22879d846188f3beda17e21037c2b280ddccaac9cc89767f3cc'::bytea,
  user_display_name := 'test'::text,
  timeout := '2 minutes'::interval,
  user_verification := 'required',
  challenge_at := '2020-12-13 16:35:00+01'
));

SELECT * FROM webauthn.make_credential(
  credential_id := 'NJnNZhUPGJ_akprSCWU76d54aNWqbAPAW008_oAGLFJ8DA97dzgqmlw5AjO4tAYuJrKZ-VVnCCQuFHFcGul2DQ',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAwAAAAAAAAAAAAAAAAAAAAAAQDSZzWYVDxif2pKa0gllO-neeGjVqmwDwFtNPP6ABixSfAwPe3c4KppcOQIzuLQGLiaymflVZwgkLhRxXBrpdg2lAQIDJiABIVggE2ebqUbHwcyHus8XAayzIyYqbc3d42ug3hafythiXHsiWCAXTPrRHtV_vlkcR64JcGQhszaTIiXOkiGx56yC5qfoPg',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSTQwNGtnYV9VZnpuN1l0eGx5eW8xMHFaZHhfXzk4TTJYWTFQSVNuN1VlSSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  relying_party_id := 'localhost',
  credential_at := '2020-12-13 16:35:10+01'
);

SELECT jsonb_pretty(webauthn.get_credentials(
  challenge := '\x978f567dc9a10c4a42d1b8083e8c44f0bc4bd68675aa66d6accefe0e49d9d3c0'::bytea,
  relying_party_id := 'localhost',
  user_name := 'test',
  timeout := '2 minutes'::interval,
  user_verification := 'required',
  challenge_at := '2020-12-13 16:35:20+01'
));

SELECT * FROM webauthn.verify_assertion(
  credential_id := 'NJnNZhUPGJ_akprSCWU76d54aNWqbAPAW008_oAGLFJ8DA97dzgqmlw5AjO4tAYuJrKZ-VVnCCQuFHFcGul2DQ',
  credential_type := 'public-key',
  authenticator_data := 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAABA',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibDQ5V2ZjbWhERXBDMGJnSVBveEU4THhMMW9aMXFtYldyTTctRGtuWjA4QSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  signature := 'MEUCIQDJ4LWF8sn6W-MVDPZ31bQYyrMfw6FhJFIU3tT5K8U2OgIgT9VQipFTxkdJQfVNDOQdxJhBE_N1M5JyEG5vE5fP4dE',
  user_handle := '',
  relying_party_id := 'localhost',
  verified_at := '2020-12-13 16:35:30+01'
);

/*
 * verify_assertion() MUST throw:
 * ERROR:  new row for relation "assertions" violates check constraint "user_verification"
 * because user_verification is 'required'
 * but the user_verified flag in the authenticator_data is FALSE.
 */

ROLLBACK;