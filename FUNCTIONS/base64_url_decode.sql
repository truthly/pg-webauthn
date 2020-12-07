CREATE OR REPLACE FUNCTION webauthn.base64_url_decode(text)
RETURNS bytea
IMMUTABLE
LANGUAGE sql AS $$
SELECT decode(rpad(replace(replace($1,'-','+'),'_','/'),length($1) + (4 - length($1) % 4) % 4, '='),'base64')
$$;
