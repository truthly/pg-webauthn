CREATE OR REPLACE FUNCTION webauthn.decode_asn1_der_signature(asn1der bytea)
RETURNS bytea
IMMUTABLE
LANGUAGE sql
AS $$
SELECT integer1||integer2
FROM (VALUES(get_byte(asn1der,3))) AS Q1(len1)
JOIN LATERAL (VALUES(get_byte(asn1der,5+len1))) AS Q2(len2) ON TRUE
JOIN LATERAL (VALUES(substring(asn1der from 5 for len1))) AS Q3(integer1_zeropadded) ON TRUE
JOIN LATERAL (VALUES(substring(integer1_zeropadded from length(integer1_zeropadded)-31 for 32))) AS Q4(integer1) ON TRUE
JOIN LATERAL (VALUES(substring(asn1der from 5+len1+2 for len2))) AS Q5(integer2_zeropadded) ON TRUE
JOIN LATERAL (VALUES(substring(integer2_zeropadded from length(integer2_zeropadded)-31 for 32))) AS Q6(integer2) ON TRUE
WHERE get_byte(asn1der,0) = 48 /* 0x30 SEQUENCE */
AND get_byte(asn1der,1) = length(asn1der)-2
AND get_byte(asn1der,2) = 2 /* 0x02 INTEGER */
AND get_byte(asn1der,5+len1-1) = 2 /* 0x02 INTEGER */
AND length(integer1||integer2) = 64
$$;
