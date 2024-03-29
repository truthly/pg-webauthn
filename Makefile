EXTENSION = webauthn
DATA = \
	webauthn--1.0.sql \
	webauthn--1.0--1.1.sql \
	webauthn--1.1.sql \
	webauthn--1.1--1.2.sql \
	webauthn--1.2.sql \
	webauthn--1.2--1.3.sql \
	webauthn--1.3.sql

REGRESS = ok \
	ok_user_handle \
	error_assertions_check_user_verified_or_not_required \
	error_assertions_check_reasonable_timeout \
	error_assertions_check_verified_before_timeout \
	error_assertions_check_verified_signature \
	error_assertions_check_user_handle_equal_or_null \
	error_credentials_check_credential_before_timeout \
	error_credentials_check_user_verified_or_not_required \
	error_credentials_check_reasonable_timeout \
	error_replay_attack \
	error_hijack_attack

EXTRA_CLEAN = webauthn--1.3.sql webauthn--1.2--1.3.sql

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

all: webauthn--1.3.sql webauthn--1.2--1.3.sql

SQL_SRC = \
  complain_header.sql \
	FUNCTIONS/raise_error.sql \
	ENUMS/credential_type.sql \
	ENUMS/user_verification_requirement.sql \
	ENUMS/attestation_conveyance_preference.sql \
  FUNCTIONS/base64url_decode.sql \
  FUNCTIONS/base64url_encode.sql \
  FUNCTIONS/cose_ecdha_to_pkcs.sql \
  FUNCTIONS/decode_asn1_der_signature.sql \
  FUNCTIONS/from_utf8.sql \
  FUNCTIONS/parse_authenticator_data.sql \
  FUNCTIONS/parse_attestation_object.sql \
  TABLES/credential_challenges.sql \
	FUNCTIONS/credential_challenge_user_verification.sql \
	FUNCTIONS/credential_challenge_expiration.sql \
  TABLES/credentials.sql \
  TABLES/assertion_challenges.sql \
	FUNCTIONS/assertion_challenge_user_verification.sql \
	FUNCTIONS/assertion_challenge_expiration.sql \
	FUNCTIONS/credential_public_key.sql \
  TABLES/assertions.sql \
	FUNCTIONS/get_credential_creation_options.sql \
  FUNCTIONS/init_credential.sql \
  FUNCTIONS/store_credential.sql \
  FUNCTIONS/get_credentials.sql \
  FUNCTIONS/verify_assertion.sql \
	FUNCTIONS/generate_test.sql

webauthn--1.3.sql: $(SQL_SRC)
	cat $^ > $@

SQL_SRC = \
  complain_header.sql \
  FUNCTIONS/store_credential.sql \
	FUNCTIONS/generate_test.sql \
  1.2--1.3.sql

webauthn--1.2--1.3.sql: $(SQL_SRC)
	cat $^ > $@
