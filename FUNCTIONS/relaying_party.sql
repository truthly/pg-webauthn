CREATE OR REPLACE FUNCTION webauthn.relaying_party()
RETURNS text
STABLE
LANGUAGE sql
AS $$
SELECT token FROM ts_debug(current_setting('request.header.origin', TRUE)) WHERE alias IN ('host','asciiword')
$$;
