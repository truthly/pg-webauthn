CREATE OR REPLACE FUNCTION webauthn.relaying_party()
RETURNS text
STABLE
LANGUAGE sql
AS $$
SELECT token FROM (
  SELECT token, COUNT(*) OVER ()
  FROM ts_debug(current_setting('request.header.origin', TRUE))
  WHERE alias IN ('host','asciiword')
) AS X WHERE COUNT = 1
$$;
