ALTER TABLE webauthn.assertions DROP CONSTRAINT verified_signature;
ALTER TABLE webauthn.assertions
ADD CONSTRAINT verified_signature CHECK (COALESCE(public.ecdsa_verify(
  public_key := webauthn.credential_public_key(credential_id),
  input_data := substring(authenticator_data,1,37) || public.digest(client_data_json,'sha256'),
  signature := webauthn.decode_asn1_der_signature(signature),
  hash_func := 'sha256',
  curve_name := 'secp256r1'),FALSE));
