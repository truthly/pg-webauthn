CREATE OR REPLACE FUNCTION webauthn.credential_public_key(credential_id bytea)
RETURNS bytea
STABLE
LANGUAGE sql AS $$
SELECT public_key FROM webauthn.credentials WHERE credential_id = $1
$$;
