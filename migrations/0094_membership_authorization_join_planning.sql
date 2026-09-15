-- This point lookup joins eight exact token/consent/member/identity records.
-- Exhaustive join-order planning can occupy the small scoped testing pool for
-- seconds under concurrent requests. Follow this helper's explicit join order
-- without changing its body, privileges, RLS, or any connection-wide setting.
ALTER FUNCTION iam_private.application_token_allows_membership(uuid, uuid)
    SET join_collapse_limit = 1;
