CREATE OR REPLACE FUNCTION webauthn.base64url_encode(bytea)
RETURNS text
IMMUTABLE
LANGUAGE sql AS $$
SELECT translate(trim(trailing '=' from replace(encode($1,'base64'),E'\n','')),'+/','-_')
$$;
