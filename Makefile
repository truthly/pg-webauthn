EXTENSION = webauthn
DATA = webauthn--1.0.sql
REGRESS = test
EXTRA_CLEAN = webauthn--1.0.sql

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

all: webauthn--1.0.sql

SQL_SRC = \
  FUNCTIONS/comaplain_header.sql \
  FUNCTIONS/base64_url_decode.sql \
  FUNCTIONS/decode_cbor.sql \
  FUNCTIONS/cbor_to_json.sql \
  FUNCTIONS/cose_ecdha_to_pkcs.sql \
  FUNCTIONS/decode_asn1_der_signature.sql \
  FUNCTIONS/from_utf8.sql \
  FUNCTIONS/parse_authenticator_data.sql \
  FUNCTIONS/parse_attestation_object.sql \
  FUNCTIONS/relaying_party.sql \
  TABLES/challenges.sql \
  TABLES/credentials.sql \
  TABLES/assertions.sql \
  FUNCTIONS/init_credential.sql \
  FUNCTIONS/make_credential.sql \
  FUNCTIONS/get_credentials.sql \
  FUNCTIONS/verify_assertion.sql

webauthn--1.0.sql: $(SQL_SRC)
	cat $^ > $@
