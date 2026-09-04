-- Any active Silicon may request a job-role change. The API has always
-- enforced that caller type, and the public contract permits requests for any
-- active Carbon or Silicon in the organization. Requiring an explicit
-- roles.request grant in row security made every ordinary Silicon request
-- fail as a database error, while the parallel tag-request path worked.

DROP POLICY approval_requests_create ON iam.approval_requests;
CREATE POLICY approval_requests_create
ON iam.approval_requests FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND EXISTS (
        SELECT 1
        FROM iam.organization_memberships AS requester
        WHERE requester.organization_id = approval_requests.organization_id
          AND requester.id = approval_requests.requested_by_membership_id
          AND requester.principal_id = iam_private.current_principal_id()
          AND requester.status = 'active'
          AND (
              (
                  approval_requests.request_kind IN (
                      'carbon_job_role_change', 'silicon_job_role_change'
                  )
                  AND requester.principal_kind = 'silicon'
              )
              OR (
                  approval_requests.request_kind IN (
                      'carbon_tag_change', 'silicon_tag_change'
                  )
                  AND requester.principal_kind IN ('carbon', 'silicon')
              )
              OR (
                  approval_requests.request_kind = 'silicon_token_rotation'
                  AND iam_private.has_organization_capability(
                      approval_requests.organization_id,
                      iam_private.current_principal_id(),
                      'silicons.rotate_token'
                  )
              )
              OR (
                  approval_requests.request_kind = 'ownership_transfer'
                  AND requester.principal_kind = 'carbon'
                  AND requester.org_role = 'owner'
              )
          )
    )
);

DROP POLICY approval_requirements_create ON iam.approval_requirements;
CREATE POLICY approval_requirements_create
ON iam.approval_requirements FOR INSERT
WITH CHECK (
    organization_id = iam_private.current_organization_id()
    AND EXISTS (
        SELECT 1
        FROM iam.approval_requests AS request
        JOIN iam.organization_memberships AS requester
          ON requester.organization_id = request.organization_id
         AND requester.id = request.requested_by_membership_id
         AND requester.principal_id = iam_private.current_principal_id()
         AND requester.status = 'active'
        LEFT JOIN iam.job_role_change_requests AS role_change
          ON role_change.organization_id = request.organization_id
         AND role_change.approval_request_id = request.id
        LEFT JOIN iam.tag_change_requests AS tag_change
          ON tag_change.organization_id = request.organization_id
         AND tag_change.approval_request_id = request.id
        WHERE request.organization_id = approval_requirements.organization_id
          AND request.id = approval_requirements.approval_request_id
          AND (
              (
                  request.request_kind = 'carbon_job_role_change'
                  AND requester.principal_kind = 'silicon'
                  AND (
                      (
                          approval_requirements.requirement_kind = 'specific_membership'
                          AND approval_requirements.specific_membership_id =
                              role_change.target_membership_id
                          AND approval_requirements.required_capability IS NULL
                          AND approval_requirements.quorum = 1
                      )
                      OR (
                          approval_requirements.requirement_kind = 'current_owner_or_admin'
                          AND approval_requirements.specific_membership_id IS NULL
                          AND approval_requirements.required_capability = 'roles.approve'
                          AND approval_requirements.quorum = 1
                      )
                  )
              )
              OR (
                  request.request_kind = 'silicon_job_role_change'
                  AND requester.principal_kind = 'silicon'
                  AND approval_requirements.requirement_kind = 'current_owner_or_admin'
                  AND approval_requirements.specific_membership_id IS NULL
                  AND approval_requirements.required_capability = 'roles.approve'
                  AND approval_requirements.quorum = 1
              )
              OR (
                  request.request_kind = 'carbon_tag_change'
                  AND requester.principal_kind IN ('carbon', 'silicon')
                  AND (
                      (
                          approval_requirements.requirement_kind = 'specific_membership'
                          AND approval_requirements.specific_membership_id =
                              tag_change.target_membership_id
                          AND approval_requirements.required_capability IS NULL
                          AND approval_requirements.quorum = 1
                      )
                      OR (
                          approval_requirements.requirement_kind = 'current_owner_or_admin'
                          AND approval_requirements.specific_membership_id IS NULL
                          AND approval_requirements.required_capability = 'tags.manage'
                          AND approval_requirements.quorum = 1
                      )
                  )
              )
              OR (
                  request.request_kind = 'silicon_tag_change'
                  AND requester.principal_kind IN ('carbon', 'silicon')
                  AND approval_requirements.requirement_kind = 'current_owner_or_admin'
                  AND approval_requirements.specific_membership_id IS NULL
                  AND approval_requirements.required_capability = 'tags.manage'
                  AND approval_requirements.quorum = 1
              )
              OR (
                  request.request_kind = 'silicon_token_rotation'
                  AND iam_private.has_organization_capability(
                      request.organization_id,
                      iam_private.current_principal_id(),
                      'silicons.rotate_token'
                  )
                  AND approval_requirements.requirement_kind = 'current_owner'
                  AND approval_requirements.specific_membership_id IS NULL
                  AND approval_requirements.required_capability IS NULL
                  AND approval_requirements.quorum = 1
              )
              OR (
                  request.request_kind = 'ownership_transfer'
                  AND requester.principal_kind = 'carbon'
                  AND requester.org_role = 'owner'
                  AND approval_requirements.requirement_kind = 'current_owner'
                  AND approval_requirements.specific_membership_id IS NULL
                  AND approval_requirements.required_capability IS NULL
                  AND approval_requirements.quorum = 1
              )
          )
    )
);

COMMENT ON POLICY approval_requests_create ON iam.approval_requests IS
    'Active Silicons may create role/tag requests; rotation and ownership requests retain their explicit authority checks.';
COMMENT ON POLICY approval_requirements_create ON iam.approval_requirements IS
    'Permits only the fixed quorum shape for the request kind, including role requests from any active Silicon.';
