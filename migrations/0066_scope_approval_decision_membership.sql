BEGIN;

-- The original policy's unqualified `organization_id` inside the scalar
-- subquery resolved to the inner membership row. A Carbon with active
-- memberships in more than one organization therefore produced multiple rows
-- instead of matching the decision's organization. Bind both comparisons to
-- the approval_decisions row explicitly.
DROP POLICY approval_decisions_create ON iam.approval_decisions;

CREATE POLICY approval_decisions_create
ON iam.approval_decisions FOR INSERT
WITH CHECK (
    approval_decisions.organization_id = iam_private.current_organization_id()
    AND approval_decisions.decided_by_membership_id = (
        SELECT membership.id
        FROM iam.organization_memberships AS membership
        WHERE membership.organization_id = approval_decisions.organization_id
          AND membership.principal_id = iam_private.current_principal_id()
          AND membership.status = 'active'
    )
);

COMMIT;
