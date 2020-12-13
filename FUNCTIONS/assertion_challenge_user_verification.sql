CREATE OR REPLACE FUNCTION webauthn.assertion_challenge_user_verification(challenge bytea)
RETURNS webauthn.user_verification_requirement
STABLE
LANGUAGE sql AS $$
SELECT user_verification FROM webauthn.assertion_challenges WHERE challenge = $1
$$;
