BEGIN;

CREATE EXTENSION webauthn CASCADE;

SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\xf1f49abe5e3dcff7a1f522252f4fb574df415dd087aae156114ac9b51fbf4129'::bytea,
  relying_party_name := 'Localhost'::text,
  relying_party_id := 'localhost'::text,
  user_name := 'test'::text,
  user_id := '\xb3368c7317791c5a98b81428cdf3e35012aa71e6090d04930b390049ead7c282064ee24e9dc7219b6d727cc85aad4dcc0f3134f8e62c6c896a48ac08aac3db1b'::bytea,
  user_display_name := 'test'::text,
  timeout := '2 minutes'::interval
));

SELECT * FROM webauthn.make_credential(
  credential_id := 'ASiVjgqKJgvSawjRv_bjFR6l9uOgpLJ9jaZbGkxytC3vQzq21tlSuPgAnvQF6B0BLK0dujjrqvK3oBktYP8FEdYOZz8LK8PjiyDGXiCrlSYDy58JILDNJIi-n7973HgHhYiDgN_iBCTfX9Y',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjvSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFX9SYD63OAAI1vMYKZIsLJfHwVQMAawEolY4KiiYL0msI0b_24xUepfbjoKSyfY2mWxpMcrQt70M6ttbZUrj4AJ70BegdASytHbo466ryt6AZLWD_BRHWDmc_CyvD44sgxl4gq5UmA8ufCSCwzSSIvp-_e9x4B4WIg4Df4gQk31_WpQECAyYgASFYIFYGLzqrkNKDty3WMhTXQzjWxIXZekODNhjBB8MjZHgpIlgg1wRbPHszTjstSPn7dPAqVDmO0krRy8rWpTjJDAeOFVY',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOGZTYXZsNDl6X2VoOVNJbEwwLTFkTjlCWGRDSHF1RldFVXJKdFItX1FTayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  relying_party_id := 'localhost'
);

SELECT jsonb_pretty(webauthn.get_credentials(
  challenge := '\xa5174d506a1c0a0e9cd9cd65dae1221582b17824cb9b8c91f032f43c1c09cd1f'::bytea,
  relying_party_id := 'localhost',
  user_name := 'test',
  timeout := '2 minutes'::interval
));

SELECT * FROM webauthn.verify_assertion(
  credential_id := 'ASiVjgqKJgvSawjRv_bjFR6l9uOgpLJ9jaZbGkxytC3vQzq21tlSuPgAnvQF6B0BLK0dujjrqvK3oBktYP8FEdYOZz8LK8PjiyDGXiCrlSYDy58JILDNJIi-n7973HgHhYiDgN_iBCTfX9Y',
  credential_type := 'public-key',
  authenticator_data := 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFX9SYFg',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicFJkTlVHb2NDZzZjMmMxbDJ1RWlGWUt4ZUNUTG00eVI4REwwUEJ3SnpSOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  signature := 'MEUCIBLCsANiAuhOPX2_GkzCPHhYPAL2xL1Ms22xFHiLDHJfAiEA_Ru_HfC51p-PjvU9VVV5lRKk_swZ9vKMJedQyhnsc4w',
  user_handle := 'szaMcxd5HFqYuBQozfPjUBKqceYJDQSTCzkASerXwoIGTuJOncchm21yfMharU3MDzE0-OYsbIlqSKwIqsPbGw',
  relying_party_id := 'localhost'
);

ROLLBACK;
