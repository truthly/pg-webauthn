CREATE OR REPLACE FUNCTION webauthn.cbor_next_array(
cbor bytea,
item_count integer
)
RETURNS webauthn.cbor_next
IMMUTABLE
LANGUAGE sql
AS $$
WITH RECURSIVE x AS (
  SELECT
    cbor_next_array.cbor AS remainder,
    cbor_next_array.item_count,
    jsonb_build_array() AS jsonb_array
  UNION ALL
  SELECT
    cbor_next_item.remainder,
    x.item_count-1,
    x.jsonb_array || cbor_next_item.item
  FROM x
  JOIN LATERAL webauthn.cbor_next_item(x.remainder) ON TRUE
  WHERE x.item_count > 0
)
SELECT ROW(x.remainder, x.jsonb_array) FROM x WHERE x.item_count = 0
$$;
