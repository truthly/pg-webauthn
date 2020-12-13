CREATE OR REPLACE FUNCTION webauthn.assertion_challenge_expiration(challenge bytea)
RETURNS timestamptz
STABLE
LANGUAGE sql AS $$
SELECT challenge_at + timeout FROM webauthn.assertion_challenges WHERE challenge = $1
$$;
