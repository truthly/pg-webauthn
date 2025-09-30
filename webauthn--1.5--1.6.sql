-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION webauthn" to load this file. \quit
CREATE OR REPLACE FUNCTION webauthn.decode_asn1_der_signature(asn1der bytea)
RETURNS bytea
IMMUTABLE
LANGUAGE plpgsql
AS $$
DECLARE
len1 integer;
len2 integer;
integer1_zeropadded bytea;
integer1 bytea;
integer2_zeropadded bytea;
integer2 bytea;
result bytea;
BEGIN
IF length(asn1der) <= 3 THEN
    RETURN NULL;
END IF;
len1 := get_byte(asn1der,3);
IF length(asn1der) <= 5+len1 THEN
    RETURN NULL;
END IF;
len2 := get_byte(asn1der,5+len1);
integer1_zeropadded := substring(asn1der from 5 for len1);
integer1 := substring(decode(repeat('00',32),'hex')||integer1_zeropadded from len1+1 for 32);
integer2_zeropadded := substring(asn1der from 5+len1+2 for len2);
integer2 := substring(decode(repeat('00',32),'hex')||integer2_zeropadded from len2+1 for 32);
result := integer1||integer2;

IF get_byte(asn1der,0) = 48
AND get_byte(asn1der,1) = length(asn1der)-2
AND get_byte(asn1der,2) = 2 /* 0x02 INTEGER */
AND get_byte(asn1der,5+len1-1) = 2 /* 0x02 INTEGER */
AND length(integer1||integer2) = 64
THEN
    RETURN result;
END IF;
END;
$$;
