CREATE OR REPLACE FUNCTION webauthn.from_utf8(string bytea)
RETURNS text
IMMUTABLE
LANGUAGE sql
AS $$
-- IMMUTABLE wrapper-function for convert_from() since it's not IMMUTABLE
-- See: https://www.postgresql.org/message-id/87ftxia3l4.fsf%40news-spur.riddles.org.uk
-- Should be safe, since "server_encoding can't be changed except at db creation time."
SELECT convert_from(string, 'utf8')
$$;
