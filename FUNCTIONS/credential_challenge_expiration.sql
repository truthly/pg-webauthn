CREATE OR REPLACE FUNCTION webauthn.credential_challenge_expiration(challenge bytea)
RETURNS timestamptz
STABLE
LANGUAGE sql AS $$
SELECT challenge_at + timeout FROM webauthn.credential_challenges WHERE challenge = $1
$$;
