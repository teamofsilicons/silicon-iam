-- App-authenticated callback binding. The application owns delivery, as with SLT;
-- IAM no longer has a registered redirect allowlist (removed in migration 0057).
-- A callback cannot redeem a code without the originating application's secret.
ALTER TABLE iam.obo_authorization_requests ADD COLUMN redirect_uri text, ADD COLUMN callback_state text;
ALTER TABLE iam.obo_authorization_requests ADD CONSTRAINT obo_callback_complete CHECK (
 (redirect_uri IS NULL AND callback_state IS NULL) OR
 (redirect_uri IS NOT NULL AND callback_state IS NOT NULL AND length(redirect_uri) BETWEEN 1 AND 2048 AND length(callback_state) BETWEEN 32 AND 512));
CREATE FUNCTION iam_private.obo_authorization_bind_callback(p_id uuid,p_uri text,p_state text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,iam,iam_private AS $$
BEGIN
 UPDATE iam.obo_authorization_requests SET redirect_uri=p_uri,callback_state=p_state
 WHERE id=p_id AND application_id=iam_private.current_application_id() AND status='pending'
 AND redirect_uri IS NULL AND callback_state IS NULL AND expires_at>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION 'obo_request_unavailable' USING ERRCODE='P0001'; END IF;
 RETURN iam_private.obo_request_detail(p_id);
END $$;
REVOKE ALL ON FUNCTION iam_private.obo_authorization_bind_callback(uuid,text,text) FROM PUBLIC;
DO $$ DECLARE definition text; updated text; BEGIN
 SELECT pg_get_functiondef('iam_private.obo_request_detail(uuid)'::regprocedure) INTO definition;
 updated:=replace(definition,'''version'',request.version','''redirect_uri'',request.redirect_uri,''state'',request.callback_state,''version'',request.version');
 IF updated=definition THEN RAISE EXCEPTION 'OBO callback detail patch did not match'; END IF;
 EXECUTE updated;
END $$;
