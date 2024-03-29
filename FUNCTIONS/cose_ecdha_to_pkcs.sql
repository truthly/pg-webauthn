CREATE OR REPLACE FUNCTION webauthn.cose_ecdha_to_pkcs(cose_public_key bytea)
RETURNS bytea
IMMUTABLE
LANGUAGE sql
AS $$
-- https://github.com/fido-alliance/webauthn-demo/blob/master/utils.js#L105
-- \x04 tag byte not prepended since not wanted by pg-ecdsa
SELECT decode(cose_struct->0->>'-2','base64') || decode(cose_struct->0->>'-3','base64')
FROM cbor.to_jsonb_array(cbor := cose_public_key, encode_binary_format := 'base64') AS cose_struct
$$;
