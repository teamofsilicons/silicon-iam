-- Keep Silicon Hook provisioning claims bounded as the durable queue grows.

CREATE INDEX silicon_hooks_worker_pending_retry_claim_idx
    ON iam.silicon_hooks (
        (COALESCE(next_attempt_at, created_at)),
        id
    )
    INCLUDE (status, attempt_count)
    WHERE status IN ('pending', 'failed');

CREATE INDEX silicon_hooks_worker_expired_lease_claim_idx
    ON iam.silicon_hooks (lease_expires_at, id)
    INCLUDE (attempt_count, created_at, next_attempt_at)
    WHERE status = 'provisioning';

COMMENT ON INDEX iam.silicon_hooks_worker_pending_retry_claim_idx IS
    'Supports ordered pending and due-retry Silicon Hook claims without scanning terminal hooks.';

COMMENT ON INDEX iam.silicon_hooks_worker_expired_lease_claim_idx IS
    'Supports recovery of expired Silicon Hook provisioning leases without scanning live or terminal hooks.';
