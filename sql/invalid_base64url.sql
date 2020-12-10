BEGIN;

CREATE EXTENSION webauthn CASCADE;

SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\xe78dda9b35db92903f8340e715cbc5bc0c9b5c1cf0320e7b7c679ddfb601f243'::bytea,
  relying_party_name := 'Localhost'::text,
  relying_party_id := 'localhost'::text,
  user_name := 'test'::text,
  user_id := '\x74657374'::bytea,
  user_display_name := 'test'::text,
  timeout := '2 minutes'::interval
));

SELECT * FROM webauthn.make_credential(
  credential_id := 'AUgfp5B5oOockGx4sAFOTlMQTDrIr7jk2GZ0s6dSEafmGZkdBLgFtN5L66QceA',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViySZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFX80iUq3OAAI1vMYKZIsLJfHwVQMALgFIH6eQeaDqHJBseLABTk5TEEw6yK-45NhmdLOnUhGn5hmZHQS4BbTeS-ukHHilAQIDJiABIVggq5dcFvA47Q1wjcY8u269gS1IwG-L9cbRIkkB5NpsHdIiWCAe50J8KlNFD_SNq6ajrh0nWhvU4bNED3rceNaGPLkPEQ',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNTQzYW16WGJrcEFfZzBEbkZjdkZ2QXliWEJ6d01nNTdmR2VkMzdZQjhrTSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  relying_party_id := 'localhost'
);

SELECT jsonb_pretty(webauthn.get_credentials(
  challenge := '\x4c3c85ab1ee2a50f94a09f8ebe065499691ba73385466e8df1757a9a8c093a04'::bytea,
  relying_party_id := 'localhost',
  user_name := 'test',
  timeout := '2 minutes'::interval
));

SELECT webauthn.verify_assertion(
  credential_id := 'AUgfp5B5oOockGx4sAFOTlMQTDrIr7jk2GZ0s6dSEafmGZkdBLgFtN5L66QceA',
  credential_type := 'public-key',
  authenticator_data := 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFX80ilw',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVER5RnF4N2lwUS1Vb0otT3ZnWlVtV2ticHpPRlJtNk44WFY2bW93Sk9nUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ',
  signature := 'this_is_an_invalid_base64url_value_but_of_expected_length_and_not_a_valid_signature!!!!!!!!!!!!',
  user_handle := 'dGVzdA',
  relying_party_id := 'localhost'
);

ROLLBACK;
