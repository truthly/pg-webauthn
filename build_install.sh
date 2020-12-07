#!/bin/bash
INSTALL_FILE=webauthn--1.0.sql
cat > $INSTALL_FILE <<'_EOF'
-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION webauthn" to load this file. \quit
_EOF

SOURCE_FILES=(
  # Common helpers:
  "FUNCTIONS/base64_url_decode.sql"
  "FUNCTIONS/decode_cbor.sql"
  "FUNCTIONS/cbor_to_json.sql"
  "FUNCTIONS/cose_ecdha_to_pkcs.sql"
  "FUNCTIONS/decode_asn1_der_signature.sql"
  "FUNCTIONS/from_utf8.sql"
  "FUNCTIONS/parse_authenticator_data.sql"
  "FUNCTIONS/parse_attestation_object.sql"
  "FUNCTIONS/relaying_party.sql"
  # Data tables:
  "TABLES/challenges.sql"
  "TABLES/credentials.sql"
  "TABLES/assertions.sql"
  # API-functions:
  "FUNCTIONS/init_credential.sql"
  "FUNCTIONS/make_credential.sql"
  "FUNCTIONS/get_credentials.sql"
  "FUNCTIONS/verify_assertion.sql"
)
 
for FILE in ${SOURCE_FILES[@]}; do
   cat $FILE >> $INSTALL_FILE
done
