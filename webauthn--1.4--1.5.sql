-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION webauthn" to load this file. \quit
CREATE OR REPLACE FUNCTION webauthn.decode_asn1_der_signature(asn1der bytea)
RETURNS bytea
IMMUTABLE
BEGIN ATOMIC
SELECT integer1||integer2
FROM get_byte(asn1der,3) AS Q1(len1)
CROSS JOIN LATERAL get_byte(asn1der,5+len1) AS Q2(len2)
CROSS JOIN LATERAL substring(asn1der from 5 for len1) AS Q3(integer1_zeropadded)
CROSS JOIN LATERAL substring(decode(repeat('00',32),'hex')||integer1_zeropadded from len1+1 for 32) AS Q4(integer1)
CROSS JOIN LATERAL substring(asn1der from 5+len1+2 for len2) AS Q5(integer2_zeropadded)
CROSS JOIN LATERAL substring(decode(repeat('00',32),'hex')||integer2_zeropadded from len2+1 for 32) AS Q6(integer2)
WHERE get_byte(asn1der,0) = 48 /* 0x30 SEQUENCE */
AND get_byte(asn1der,1) = length(asn1der)-2
AND get_byte(asn1der,2) = 2 /* 0x02 INTEGER */
AND get_byte(asn1der,5+len1-1) = 2 /* 0x02 INTEGER */
AND length(integer1||integer2) = 64;
END;
