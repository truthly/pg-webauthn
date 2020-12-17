CREATE OR REPLACE FUNCTION webauthn.cbor_to_json(cbor bytea)
RETURNS jsonb
LANGUAGE sql
AS $$
WITH RECURSIVE x AS (
  SELECT
    0 AS i,
    cbor_next_item.remainder,
    jsonb_build_array(cbor_next_item.item) AS items
  FROM webauthn.cbor_next_item(cbor_to_json.cbor)
  UNION ALL
  SELECT
    x.i + 1,
    cbor_next_item.remainder,
    x.items || cbor_next_item.item
  FROM x
  JOIN LATERAL webauthn.cbor_next_item(x.remainder) ON TRUE
  WHERE length(x.remainder) > 0
)
SELECT x.items FROM x ORDER BY i DESC LIMIT 1
$$;
