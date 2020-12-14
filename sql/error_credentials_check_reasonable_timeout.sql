BEGIN;

CREATE EXTENSION webauthn CASCADE;

SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\xf1f49abe5e3dcff7a1f522252f4fb574df415dd087aae156114ac9b51fbf4129'::bytea,
  relying_party_name := 'Localhost'::text,
  relying_party_id := 'localhost'::text,
  user_name := 'test'::text,
  user_id := '\xb3368c7317791c5a98b81428cdf3e35012aa71e6090d04930b390049ead7c282064ee24e9dc7219b6d727cc85aad4dcc0f3134f8e62c6c896a48ac08aac3db1b'::bytea,
  user_display_name := 'test'::text,
  timeout := '29 seconds'::interval,
  challenge_at := '2020-12-13 16:35:00+01'
));

ROLLBACK;
