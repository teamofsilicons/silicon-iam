-- An integrity assertion must see every row it validates. These trigger
-- functions and the assertion helpers they delegate to ran as the invoking
-- role, so row-level security hid the very rows under test.
--
-- Signup completion failed in production for exactly that reason.
-- `complete_verified_signup` is SECURITY DEFINER and inserts both contacts,
-- but the deferred assertion fires at COMMIT as the API runtime role, where
-- `carbon_contacts_self_access` matches only the current principal. Signup
-- authenticates no principal, so `iam_private.current_principal_id()` is NULL,
-- the policy denied every row, and the assertion counted zero verified primary
-- contacts while demanding two. No Carbon could ever be created.
--
-- Twelve trigger chains shared the defect, and the failure mode is not
-- uniformly closed. The reporting-cycle walk reads a truncated `iam.silicons`
-- graph and can miss a cycle; the webhook topic assertion returns early when
-- the subscription is invisible. Both fail open. The outbox tenancy
-- assertions, the owner-count assertion, the principal-subtype assertion, and
-- the approval-shape assertion instead read NULL and raise against writes that
-- were legitimate.
--
-- Every one of these returns void or trigger and only ever raises, so running
-- them as the owning role discloses nothing it did not already validate. A
-- definer function must also pin its search_path, and PUBLIC execution stays
-- revoked.

ALTER FUNCTION iam_private.assert_active_carbon_contacts(uuid) SECURITY DEFINER;
ALTER FUNCTION iam_private.assert_active_carbon_contacts(uuid)
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.assert_active_carbon_contacts(uuid) FROM PUBLIC;

ALTER FUNCTION iam_private.assert_active_principal_subtype(uuid) SECURITY DEFINER;
ALTER FUNCTION iam_private.assert_active_principal_subtype(uuid)
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.assert_active_principal_subtype(uuid) FROM PUBLIC;

ALTER FUNCTION iam_private.assert_approval_request_shape(uuid) SECURITY DEFINER;
ALTER FUNCTION iam_private.assert_approval_request_shape(uuid)
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.assert_approval_request_shape(uuid) FROM PUBLIC;

ALTER FUNCTION iam_private.assert_exactly_one_organization_owner(uuid) SECURITY DEFINER;
ALTER FUNCTION iam_private.assert_exactly_one_organization_owner(uuid)
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.assert_exactly_one_organization_owner(uuid) FROM PUBLIC;

ALTER FUNCTION iam_private.assert_outbox_event_affected_tag_tenant() SECURITY DEFINER;
ALTER FUNCTION iam_private.assert_outbox_event_affected_tag_tenant()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.assert_outbox_event_affected_tag_tenant() FROM PUBLIC;

ALTER FUNCTION iam_private.assert_outbox_event_own_tag_membership_tenant() SECURITY DEFINER;
ALTER FUNCTION iam_private.assert_outbox_event_own_tag_membership_tenant()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.assert_outbox_event_own_tag_membership_tenant() FROM PUBLIC;

ALTER FUNCTION iam_private.assert_silicon_webhook_subscription_topics() SECURITY DEFINER;
ALTER FUNCTION iam_private.assert_silicon_webhook_subscription_topics()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.assert_silicon_webhook_subscription_topics() FROM PUBLIC;

ALTER FUNCTION iam_private.check_approval_shape_from_payload() SECURITY DEFINER;
ALTER FUNCTION iam_private.check_approval_shape_from_payload()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.check_approval_shape_from_payload() FROM PUBLIC;

ALTER FUNCTION iam_private.check_approval_shape_from_request() SECURITY DEFINER;
ALTER FUNCTION iam_private.check_approval_shape_from_request()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.check_approval_shape_from_request() FROM PUBLIC;

ALTER FUNCTION iam_private.check_carbon_contacts_from_contact() SECURITY DEFINER;
ALTER FUNCTION iam_private.check_carbon_contacts_from_contact()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.check_carbon_contacts_from_contact() FROM PUBLIC;

ALTER FUNCTION iam_private.check_carbon_contacts_from_principal() SECURITY DEFINER;
ALTER FUNCTION iam_private.check_carbon_contacts_from_principal()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.check_carbon_contacts_from_principal() FROM PUBLIC;

ALTER FUNCTION iam_private.check_owner_after_membership_change() SECURITY DEFINER;
ALTER FUNCTION iam_private.check_owner_after_membership_change()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.check_owner_after_membership_change() FROM PUBLIC;

ALTER FUNCTION iam_private.check_owner_after_organization_change() SECURITY DEFINER;
ALTER FUNCTION iam_private.check_owner_after_organization_change()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.check_owner_after_organization_change() FROM PUBLIC;

ALTER FUNCTION iam_private.check_principal_subtype_from_principal() SECURITY DEFINER;
ALTER FUNCTION iam_private.check_principal_subtype_from_principal()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.check_principal_subtype_from_principal() FROM PUBLIC;

ALTER FUNCTION iam_private.check_principal_subtype_from_subtype() SECURITY DEFINER;
ALTER FUNCTION iam_private.check_principal_subtype_from_subtype()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.check_principal_subtype_from_subtype() FROM PUBLIC;

ALTER FUNCTION iam_private.prevent_silicon_reporting_cycle() SECURITY DEFINER;
ALTER FUNCTION iam_private.prevent_silicon_reporting_cycle()
    SET search_path TO 'pg_catalog', 'iam';
REVOKE ALL ON FUNCTION iam_private.prevent_silicon_reporting_cycle() FROM PUBLIC;
