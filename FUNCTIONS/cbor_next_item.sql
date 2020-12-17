CREATE OR REPLACE FUNCTION webauthn.cbor_next_item(cbor bytea)
RETURNS webauthn.cbor_next
IMMUTABLE
LANGUAGE sql
AS $$
SELECT
  CASE
    WHEN major_type = 0 AND additional_type <= 26 THEN ROW(substring(cbor,2+length_bytes), to_jsonb(data_value))::webauthn.cbor_next
    WHEN major_type = 1 AND additional_type <= 26 THEN ROW(substring(cbor,2+length_bytes), to_jsonb(-1-data_value))::webauthn.cbor_next
    WHEN major_type = 2 AND additional_type <= 26 THEN ROW(substring(cbor,2+length_bytes+data_value), to_jsonb(encode(substring(cbor,2+length_bytes,data_value),'base64')))::webauthn.cbor_next
    WHEN major_type = 3 AND additional_type <= 26 THEN ROW(substring(cbor,2+length_bytes+data_value), to_jsonb(convert_from(substring(cbor,2+length_bytes,data_value),'utf8')))::webauthn.cbor_next
    WHEN major_type = 4 AND additional_type <= 26 THEN webauthn.cbor_next_array(substring(cbor,2+length_bytes), data_value)
    WHEN major_type = 5 AND additional_type <= 26 THEN webauthn.cbor_next_map(substring(cbor,2+length_bytes), data_value)
    WHEN major_type = 7 AND additional_type  = 20 THEN ROW(substring(cbor,2+0), to_jsonb(false))::webauthn.cbor_next
    WHEN major_type = 7 AND additional_type  = 21 THEN ROW(substring(cbor,2+0), to_jsonb(true))::webauthn.cbor_next
    WHEN major_type = 7 AND additional_type  = 22 THEN ROW(substring(cbor,2+0), 'null'::jsonb)::webauthn.cbor_next
    ELSE webauthn.raise_error('Decoding of CBOR type not implemented',json_build_object(
    'major_type',major_type,
    'additional_type',additional_type
    ),NULL::webauthn.cbor_next)
  END
FROM (VALUES(
  (get_byte(cbor,0)>>5)&'111'::bit(3)::integer,
  get_byte(cbor,0)&'11111'::bit(5)::integer,
  get_byte(cbor,1),
  (get_byte(cbor,1)<<8) + get_byte(cbor,2),
  (get_byte(cbor,1)<<24) + (get_byte(cbor,2)<<16) + (get_byte(cbor,3)<<8) + get_byte(cbor,4)
  )) AS data_item_header(major_type, additional_type, uint8_t, uint16_t, uint32_t)
JOIN LATERAL (VALUES(
  CASE WHEN additional_type <= 23 THEN 0
       WHEN additional_type  = 24 THEN 1
       WHEN additional_type  = 25 THEN 2
       WHEN additional_type  = 26 THEN 4
  END,
  CASE WHEN additional_type <= 23 THEN additional_type
       WHEN additional_type  = 24 THEN uint8_t
       WHEN additional_type  = 25 THEN uint16_t
       WHEN additional_type  = 26 THEN uint32_t
  END
)) AS additional_type_meaning(length_bytes, data_value) ON TRUE
$$;
