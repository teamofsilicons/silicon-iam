DO $$ DECLARE definition text;updated text; BEGIN
 SELECT pg_get_functiondef('iam_private.create_testing_actor_login(text,bigint,text,uuid,uuid,bigint)'::regprocedure) INTO definition;
 updated:=replace(definition,'WHERE m.id = s.membership_id AND m.principal_id = p.id AND m.status = ''active''','WHERE m.principal_id = p.id AND m.status = ''active''');
 IF updated=definition THEN RAISE EXCEPTION 'testing silicon membership binding patch did not match'; END IF;
 EXECUTE updated;
END $$;
SELECT iam_private.reconcile_testing_environment_security();
