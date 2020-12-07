CREATE OR REPLACE FUNCTION webauthn.cbor_to_json(cbor bytea)
RETURNS jsonb
IMMUTABLE
LANGUAGE sql
AS $$
WITH
items AS (
  SELECT * FROM webauthn.decode_cbor(cbor)
),
maps AS (
  SELECT
    map.item,
    COALESCE(jsonb_object_agg(
      COALESCE(keys.text_string,keys.integer_value::text),
      COALESCE(values.text_string,encode(values.bytes,'base64'))
    ) FILTER (WHERE values.integer_value IS NULL),jsonb_build_object())
    ||
    COALESCE(jsonb_object_agg(
      COALESCE(keys.text_string,keys.integer_value::text),
      values.integer_value
    ) FILTER (WHERE values.integer_value IS NOT NULL),jsonb_build_object())
    AS key_value_pairs
  FROM items AS map
  JOIN generate_series(1,map.map_item_count) AS map_index ON TRUE
  JOIN items AS keys ON keys.item = map.item+map_index*2-1
  JOIN items AS values ON values.item = map.item+map_index*2
  WHERE map.map_item_count > 0
  GROUP BY map.item
)
SELECT jsonb_agg(key_value_pairs) FROM maps
$$;
