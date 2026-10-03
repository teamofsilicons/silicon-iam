-- Reconcile the new security-definer testing login wrapper and existing rows.
SELECT iam_private.reconcile_testing_environment_security();
