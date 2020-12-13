CREATE OR REPLACE FUNCTION webauthn.credential_challenge_user_verification(challenge bytea)
RETURNS webauthn.user_verification_requirement
STABLE
LANGUAGE sql AS $$
SELECT user_verification FROM webauthn.credential_challenges WHERE challenge = $1
$$;
