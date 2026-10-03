-- Fresh testing databases apply historical9005 after the production sequence.
-- Restore the additive provider methods while retaining test-only actor sessions.
ALTER TABLE iam.authentication_sessions DROP CONSTRAINT authentication_sessions_method;
ALTER TABLE iam.authentication_sessions ADD CONSTRAINT authentication_sessions_method CHECK(authentication_method IN
 ('email_otp','phone_otp','silicon_credential','workos_sso','refresh_token','google_oidc','apple_oidc','testing_actor_id')) NOT VALID;
SELECT iam_private.reconcile_testing_environment_security();
