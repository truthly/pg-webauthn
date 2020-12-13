EXTENSION = webauthn
DATA = webauthn--1.0.sql
REGRESS = valid_signature invalid_signature invalid_base64url credential_user_verification_failure assertion_user_verification_failure base64url ecdsa_verify
EXTRA_CLEAN = webauthn--1.0.sql

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

all: webauthn--1.0.sql

SQL_SRC = \
  complain_header.sql \
	ENUMS/credential_type.sql \
	ENUMS/user_verification_requirement.sql \
  FUNCTIONS/base64url_decode.sql \
  FUNCTIONS/base64url_encode.sql \
  FUNCTIONS/decode_cbor.sql \
  FUNCTIONS/cbor_to_json.sql \
  FUNCTIONS/cose_ecdha_to_pkcs.sql \
  FUNCTIONS/decode_asn1_der_signature.sql \
  FUNCTIONS/from_utf8.sql \
  FUNCTIONS/parse_authenticator_data.sql \
  FUNCTIONS/parse_attestation_object.sql \
  TABLES/credential_challenges.sql \
  TABLES/credentials.sql \
  TABLES/assertion_challenges.sql \
  TABLES/assertions.sql \
  FUNCTIONS/init_credential.sql \
  FUNCTIONS/make_credential.sql \
  FUNCTIONS/get_credentials.sql \
  FUNCTIONS/verify_assertion.sql

webauthn--1.0.sql: $(SQL_SRC)
	cat $^ > $@
