-- Fresh testing databases receive the generic 9001 policies. Upgraded testing
-- databases receive the equivalent keys and isolation in base migration 0126.
SELECT iam_private.reconcile_testing_environment_security();
