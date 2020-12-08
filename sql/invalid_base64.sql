BEGIN;

CREATE EXTENSION webauthn CASCADE;

SET search_path TO webauthn, public, pg_temp;

-- Emulate headers set by PostgREST
SELECT set_config('request.header.origin','http://localhost',FALSE);
SELECT set_config('request.header.X-Forwarded-For','127.0.0.1',FALSE);

-- Replace random challenge with null to make test output predictable
SELECT jsonb_pretty(jsonb_set(init_credential(username := 'test'), ARRAY['publicKey','challenge'], 'null'));

-- Override challenge with real challenge from observed logged traffic seen in Chrome -> Developer Tools -> Network
UPDATE challenges SET
  challenge = decode('543amzXbkpA/g0DnFcvFvAybXBzwMg57fGed37YB8kM=','base64')
WHERE challenge_id = (SELECT MAX(challenge_id) FROM challenges)
AND consumed_at IS NULL;

SELECT make_credential(
  username := 'test',
  challenge := '543amzXbkpA/g0DnFcvFvAybXBzwMg57fGed37YB8kM=',
  credential_raw_id := 'AUgfp5B5oOockGx4sAFOTlMQTDrIr7jk2GZ0s6dSEafmGZkdBLgFtN5L66QceA==',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViySZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFX80iUq3OAAI1vMYKZIsLJfHwVQMALgFIH6eQeaDqHJBseLABTk5TEEw6yK+45NhmdLOnUhGn5hmZHQS4BbTeS+ukHHilAQIDJiABIVggq5dcFvA47Q1wjcY8u269gS1IwG+L9cbRIkkB5NpsHdIiWCAe50J8KlNFD/SNq6ajrh0nWhvU4bNED3rceNaGPLkPEQ==',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNTQzYW16WGJrcEFfZzBEbkZjdkZ2QXliWEJ6d01nNTdmR2VkMzdZQjhrTSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9'
);

-- Replace random challenge with null to make test output predictable
SELECT jsonb_pretty(jsonb_set(get_credentials(username := 'test'), ARRAY['publicKey','challenge'], 'null'));

-- Override challenge with real challenge from observed logged traffic seen in Chrome -> Developer Tools -> Network
UPDATE challenges SET
  challenge = webauthn.base64_url_decode(webauthn.from_utf8(decode('eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVER5RnF4N2lwUS1Vb0otT3ZnWlVtV2ticHpPRlJtNk44WFY2bW93Sk9nUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==','base64'))::jsonb->>'challenge')
WHERE challenge_id = (SELECT MAX(challenge_id) FROM challenges)
AND consumed_at IS NULL;

SELECT verify_assertion(
  credential_raw_id := 'AUgfp5B5oOockGx4sAFOTlMQTDrIr7jk2GZ0s6dSEafmGZkdBLgFtN5L66QceA==',
  credential_type := 'public-key',
  authenticator_data := 'SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFX80ilw==',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVER5RnF4N2lwUS1Vb0otT3ZnWlVtV2ticHpPRlJtNk44WFY2bW93Sk9nUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==',
  signature := '????????????????????????????????????????????????????????????????????????????????????????????????',
  user_handle := 'dGVzdA=='
);

ROLLBACK;
