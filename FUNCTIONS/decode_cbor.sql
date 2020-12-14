CREATE OR REPLACE FUNCTION webauthn.decode_cbor(cbor bytea)
RETURNS TABLE (
  item integer,
  map_item_count integer,
  text_string text,
  bytes bytea,
  integer_value integer
)
IMMUTABLE
LANGUAGE sql
AS $$
/*
Only a few major types / additional type value combinations implemented,
the bare minimum to decode the WebAuthn "attestationObject".

https://github.com/fido-alliance/webauthn-demo/blob/master/utils.js#L200
*/
WITH RECURSIVE x AS (
  SELECT
    decode_cbor.cbor,
    0::integer AS item,
    NULL::integer AS map_item_count,
    NULL::text COLLATE "default" AS text_string,
    NULL::bytea AS bytes,
    NULL::integer AS integer_value
  UNION ALL
  SELECT
    substring(x.cbor,byte_offset) AS cbor,
    item+1 AS item,
    CASE WHEN major_type_value = 5 AND additional_type_value <= 23
         THEN additional_type_value
    END AS map_item_count,
    CASE WHEN major_type_value = 3 AND additional_type_value <= 23
         THEN convert_from(substring(x.cbor,2,additional_type_value),'utf8')
    END::text COLLATE "default" AS text_string,
    CASE WHEN major_type_value = 2 AND additional_type_value <= 23
         THEN substring(x.cbor,2,additional_type_value)
         WHEN major_type_value = 2 AND additional_type_value = 24
         THEN substring(x.cbor,3,get_byte(x.cbor,1))
         WHEN major_type_value = 2 AND additional_type_value = 25
         THEN substring(x.cbor,4,get_byte(x.cbor,1)*256+get_byte(x.cbor,2))
    END AS bytes,
    CASE WHEN major_type_value = 0 AND additional_type_value <= 23
         THEN additional_type_value
         WHEN major_type_value = 1 AND additional_type_value <= 23
         THEN -1-additional_type_value
    END AS integer_value
  FROM x
  JOIN LATERAL (VALUES(
    (get_byte(x.cbor,0)>>5)&'111'::bit(3)::integer,
    get_byte(x.cbor,0)&'11111'::bit(5)::integer
  )) AS data_item_header(major_type_value,additional_type_value) ON TRUE
  JOIN LATERAL (VALUES(CASE
    WHEN major_type_value IN (2,3) AND additional_type_value <= 23 THEN 2+additional_type_value
    WHEN major_type_value = 5 AND additional_type_value <= 23 THEN 2
    WHEN major_type_value = 2 AND additional_type_value = 24 THEN 3+get_byte(x.cbor,1)
    WHEN major_type_value = 2 AND additional_type_value = 25 THEN 4+get_byte(x.cbor,1)*256+get_byte(x.cbor,2)
    WHEN major_type_value = 0 AND additional_type_value <= 23 THEN 2
    WHEN major_type_value = 1 AND additional_type_value <= 23 THEN 2
    ELSE webauthn.raise_error('Decoding of CBOR type not implemented',json_build_object(
      'item',item,
      'major_type_value',major_type_value,
      'additional_type_value',additional_type_value
    ),NULL::integer)
  END)) AS next_item(byte_offset) ON TRUE
  WHERE length(x.cbor) > 0
)
SELECT
  item,
  map_item_count,
  text_string,
  bytes,
  integer_value
FROM x
WHERE item > 0
ORDER BY item
$$;
