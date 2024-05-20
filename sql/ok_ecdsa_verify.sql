BEGIN;

CREATE EXTENSION IF NOT EXISTS webauthn CASCADE;

SELECT ecdsa_verify.ecdsa_verify(
  public_key := '\x56062f3aab90d283b72dd63214d74338d6c485d97a43833618c107c323647829d7045b3c7b334e3b2d48f9fb74f02a54398ed24ad1cbcad6a538c90c078e1556'::bytea,
  input_data := '\x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763055fd498169f5edb0642dde83ec8d9650e8d6e078bc6fa5cc3158714cf0f835a7f83750f69'::bytea,
  signature := '\x12c2b0036202e84e3d7dbf1a4cc23c78583c02f6c4bd4cb36db114788b0c725ffd1bbf1df0b9d69f8f8ef53d5555799512a4fecc19f6f28c25e750ca19ec738c'::bytea,
  hash_func := 'sha256',
  curve_name := 'secp256r1'
);

ROLLBACK;
