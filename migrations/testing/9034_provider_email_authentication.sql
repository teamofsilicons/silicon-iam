-- The production migration is additive for existing testing databases; this
-- reconciliation also restricts the new helper on freshly built test planes.
SELECT iam_private.reconcile_testing_environment_security();
