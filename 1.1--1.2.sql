DROP FUNCTION webauthn.make_credential(
  credential_id text,
  credential_type webauthn.credential_type,
  attestation_object text,
  client_data_json text,
  credential_at timestamptz
);
