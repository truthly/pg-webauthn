CREATE OR REPLACE FUNCTION webauthn.raise_error(error_message text, debug json, dummy_return_value anyelement)
RETURNS anyelement
LANGUAGE plpgsql
AS $$
BEGIN
RAISE '% %', error_message, debug;
-- Will not return, since error will be raised,
-- but necessary to be able to use the function in place
-- where a value of given type is expected.
RETURN dummy_return_value;
END;
$$;
