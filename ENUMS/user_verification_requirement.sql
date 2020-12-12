CREATE TYPE webauthn.user_verification_requirement AS ENUM (
  'required',
  'preferred',
  'discouraged'
);

COMMENT ON TYPE webauthn.user_verification_requirement IS 'https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement';
