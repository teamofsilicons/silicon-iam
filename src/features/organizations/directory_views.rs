use std::collections::BTreeMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Response,
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, QueryBuilder, Transaction, types::Json};
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::actor::ActorType,
    error::AppError,
};

use super::{
    model::{PageInfo, TagSummary, TrustEvaluationResponse},
    support, trust, validation,
};

const FIELD_NAME: u8 = 1 << 0;
const FIELD_ID: u8 = 1 << 1;
const FIELD_ROLE: u8 = 1 << 2;
const FIELD_ORG: u8 = 1 << 3;
const FIELD_TAGS: u8 = 1 << 4;
const FIELD_TRUST: u8 = 1 << 5;
const ALL_FIELDS: u8 = FIELD_NAME | FIELD_ID | FIELD_ROLE | FIELD_ORG | FIELD_TAGS | FIELD_TRUST;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryFields(u8);

impl DirectoryFields {
    const ALL: Self = Self(ALL_FIELDS);

    fn parse(value: Option<&str>) -> Result<Self, AppError> {
        let Some(value) = value else {
            return Ok(Self::ALL);
        };
        if value.is_empty() {
            return Err(invalid_fields());
        }

        let mut fields = 0;
        for field in value.split(',') {
            fields |= match field.trim() {
                "name" => FIELD_NAME,
                "id" => FIELD_ID,
                "role" => FIELD_ROLE,
                "org" => FIELD_ORG,
                "tags" => FIELD_TAGS,
                "trust" => FIELD_TRUST,
                _ => return Err(invalid_fields()),
            };
        }
        Ok(Self(fields))
    }

    const fn contains(self, field: u8) -> bool {
        self.0 & field != 0
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DirectoryQuery {
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DirectoryPageQuery {
    cursor: Option<String>,
    limit: Option<u16>,
    fields: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct DirectoryRow {
    membership_id: Uuid,
    principal_kind: String,
    name: String,
    public_id: String,
    org_role: String,
    job_role: String,
    organization_public_id: String,
    organization_name: String,
    tags: Json<Vec<TagSummary>>,
}

#[derive(Debug, sqlx::FromRow)]
struct DirectoryTrustDefaultRow {
    subject_membership_id: Uuid,
    default_trust_boundary: String,
    default_trust_level: String,
}

#[derive(Debug, sqlx::FromRow)]
struct DirectoryTrustMatchRow {
    directory_membership_id: Uuid,
    id: Uuid,
    subject_kind: String,
    target_kind: String,
    trust_boundary: String,
    trust_level: String,
}

impl DirectoryTrustMatchRow {
    fn into_parts(self) -> (Uuid, trust::MatchRow) {
        (
            self.directory_membership_id,
            trust::MatchRow {
                id: self.id,
                subject_kind: self.subject_kind,
                target_kind: self.target_kind,
                trust_boundary: self.trust_boundary,
                trust_level: self.trust_level,
            },
        )
    }
}

#[derive(Debug, Serialize)]
struct DirectoryRole {
    org_role: String,
    job_role: String,
}

#[derive(Debug, Serialize)]
struct DirectoryOrganization {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum DirectoryTrustProjection {
    Defined(TrustEvaluationResponse),
    Undefined(()),
}

#[derive(Debug, Serialize)]
struct DirectoryMember {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<DirectoryRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org: Option<DirectoryOrganization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<TagSummary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<DirectoryTrustProjection>,
}

impl DirectoryMember {
    fn project(
        row: DirectoryRow,
        fields: DirectoryFields,
        trust: Option<TrustEvaluationResponse>,
    ) -> Self {
        let DirectoryRow {
            membership_id: _,
            principal_kind: _,
            name,
            public_id,
            org_role,
            job_role,
            organization_public_id,
            organization_name,
            tags,
        } = row;
        let trust = fields.contains(FIELD_TRUST).then(|| {
            trust.map_or(
                DirectoryTrustProjection::Undefined(()),
                DirectoryTrustProjection::Defined,
            )
        });

        Self {
            name: fields.contains(FIELD_NAME).then_some(name),
            id: fields.contains(FIELD_ID).then_some(public_id),
            role: fields
                .contains(FIELD_ROLE)
                .then_some(DirectoryRole { org_role, job_role }),
            org: fields.contains(FIELD_ORG).then_some(DirectoryOrganization {
                id: organization_public_id,
                name: organization_name,
            }),
            tags: fields.contains(FIELD_TAGS).then_some(tags.0),
            trust,
        }
    }
}

#[derive(Debug, Serialize)]
struct DirectoryPage {
    items: Vec<DirectoryMember>,
    page: PageInfo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrustEvaluationTarget {
    directory_member: Uuid,
    subject: Uuid,
    target_silicon: Uuid,
}

pub(super) async fn get_self(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<DirectoryQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let fields = DirectoryFields::parse(query.fields.as_deref())?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let row = fetch_directory_member(
        &mut scope.transaction,
        scope.access.organization_id,
        scope.access.membership_id,
        fields,
    )
    .await?;
    let mut trust = evaluate_directory_trust(
        &mut scope.transaction,
        scope.access.organization_id,
        scope.access.membership_id,
        authenticated.0.subject.actor_type,
        fields,
        std::slice::from_ref(&row),
    )
    .await?;
    let member = DirectoryMember::project(row, fields, trust.remove(&scope.access.membership_id));
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &member, None)
}

pub(super) async fn get_member(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
    Query(query): Query<DirectoryQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let fields = DirectoryFields::parse(query.fields.as_deref())?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let row = fetch_directory_member(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
        fields,
    )
    .await?;
    let mut trust = evaluate_directory_trust(
        &mut scope.transaction,
        scope.access.organization_id,
        scope.access.membership_id,
        authenticated.0.subject.actor_type,
        fields,
        std::slice::from_ref(&row),
    )
    .await?;
    let member = DirectoryMember::project(row, fields, trust.remove(&membership_id));
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &member, None)
}

pub(super) async fn list_members(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<DirectoryPageQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let fields = DirectoryFields::parse(query.fields.as_deref())?;
    let (cursor, limit) = validation::page_parts(query.cursor.as_deref(), query.limit)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let mut rows = list_directory_members(
        &mut scope.transaction,
        scope.access.organization_id,
        cursor,
        limit + 1,
        fields,
    )
    .await?;
    let page = take_page(&mut rows, limit)?;
    let mut trust = evaluate_directory_trust(
        &mut scope.transaction,
        scope.access.organization_id,
        scope.access.membership_id,
        authenticated.0.subject.actor_type,
        fields,
        &rows,
    )
    .await?;
    let items = rows
        .into_iter()
        .map(|row| {
            let membership_id = row.membership_id;
            DirectoryMember::project(row, fields, trust.remove(&membership_id))
        })
        .collect::<Vec<_>>();
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &DirectoryPage { items, page }, None)
}

async fn fetch_directory_member(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    fields: DirectoryFields,
) -> Result<DirectoryRow, AppError> {
    let mut statement = directory_statement(fields);
    statement
        .push(" WHERE membership.organization_id = ")
        .push_bind(organization_id)
        .push(" AND membership.id = ")
        .push_bind(membership_id)
        .push(" AND membership.status = 'active' LIMIT 1");
    statement
        .build_query_as::<DirectoryRow>()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)
}

async fn list_directory_members(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    cursor: Option<Uuid>,
    limit: i64,
    fields: DirectoryFields,
) -> Result<Vec<DirectoryRow>, AppError> {
    let mut statement = directory_statement(fields);
    statement
        .push(" WHERE membership.organization_id = ")
        .push_bind(organization_id)
        .push(" AND membership.status = 'active'");
    if let Some(cursor) = cursor {
        statement.push(" AND membership.id > ").push_bind(cursor);
    }
    statement
        .push(" ORDER BY membership.id LIMIT ")
        .push_bind(limit);
    statement
        .build_query_as::<DirectoryRow>()
        .fetch_all(&mut **transaction)
        .await
        .map_err(support::database)
}

fn directory_statement(fields: DirectoryFields) -> QueryBuilder<Postgres> {
    let mut statement = QueryBuilder::<Postgres>::new(DIRECTORY_PROJECTION_BEFORE_TAGS);
    if fields.contains(FIELD_TAGS) {
        statement.push(ACTIVE_TAGS_PROJECTION);
    } else {
        statement.push("'[]'::jsonb AS tags");
    }
    statement.push(DIRECTORY_PROJECTION_AFTER_TAGS);
    statement
}

async fn evaluate_directory_trust(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    requester_membership_id: Uuid,
    requester_kind: ActorType,
    fields: DirectoryFields,
    rows: &[DirectoryRow],
) -> Result<BTreeMap<Uuid, TrustEvaluationResponse>, AppError> {
    if !fields.contains(FIELD_TRUST) {
        return Ok(BTreeMap::new());
    }

    let mut targets = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(target) = trust_target(requester_membership_id, requester_kind, row)? {
            targets.push(target);
        }
    }
    let mut subject_membership_ids = targets
        .iter()
        .map(|target| target.subject)
        .collect::<Vec<_>>();
    subject_membership_ids.sort_unstable();
    subject_membership_ids.dedup();
    let defaults = if subject_membership_ids.is_empty() {
        BTreeMap::new()
    } else {
        sqlx::query_as::<_, DirectoryTrustDefaultRow>(DIRECTORY_TRUST_DEFAULT_SQL)
            .bind(organization_id)
            .bind(&subject_membership_ids)
            .fetch_all(&mut **transaction)
            .await
            .map_err(support::database)?
            .into_iter()
            .map(|row| {
                (
                    row.subject_membership_id,
                    (row.default_trust_boundary, row.default_trust_level),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    if defaults.len() != subject_membership_ids.len() {
        return Err(AppError::Internal {
            category: "directory_trust_default",
        });
    }

    let mut matches = BTreeMap::<Uuid, Vec<trust::MatchRow>>::new();
    if !targets.is_empty() {
        let directory_membership_ids = targets
            .iter()
            .map(|target| target.directory_member)
            .collect::<Vec<_>>();
        let subject_membership_ids = targets
            .iter()
            .map(|target| target.subject)
            .collect::<Vec<_>>();
        let target_silicon_membership_ids = targets
            .iter()
            .map(|target| target.target_silicon)
            .collect::<Vec<_>>();
        let rows = sqlx::query_as::<_, DirectoryTrustMatchRow>(DIRECTORY_TRUST_MATCH_SQL)
            .bind(organization_id)
            .bind(directory_membership_ids)
            .bind(subject_membership_ids)
            .bind(target_silicon_membership_ids)
            .fetch_all(&mut **transaction)
            .await
            .map_err(support::database)?;
        for row in rows {
            let (membership_id, candidate) = row.into_parts();
            matches.entry(membership_id).or_default().push(candidate);
        }
    }

    let mut evaluated = BTreeMap::new();
    for target in targets {
        let (default_boundary, default_level) =
            defaults.get(&target.subject).ok_or(AppError::Internal {
                category: "directory_trust_default",
            })?;
        let candidates = matches
            .get(&target.directory_member)
            .map(Vec::as_slice)
            .unwrap_or_default();
        evaluated.insert(
            target.directory_member,
            trust::evaluate_matches(default_boundary, default_level, candidates)?,
        );
    }
    Ok(evaluated)
}

fn trust_target(
    requester_membership_id: Uuid,
    requester_kind: ActorType,
    row: &DirectoryRow,
) -> Result<Option<TrustEvaluationTarget>, AppError> {
    match (requester_kind, row.principal_kind.as_str()) {
        (ActorType::Carbon | ActorType::Silicon, "silicon") => Ok(Some(TrustEvaluationTarget {
            directory_member: row.membership_id,
            subject: requester_membership_id,
            target_silicon: row.membership_id,
        })),
        (ActorType::Carbon | ActorType::Silicon, "carbon") => Ok(None),
        (ActorType::Application | ActorType::Service, _) => Err(AppError::Forbidden),
        (_, _) => Err(AppError::Internal {
            category: "directory_principal_kind",
        }),
    }
}

fn take_page(rows: &mut Vec<DirectoryRow>, limit: i64) -> Result<PageInfo, AppError> {
    let limit = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "directory_page_limit",
    })?;
    let has_more = rows.len() > limit;
    if has_more {
        rows.truncate(limit);
    }
    let next_cursor = has_more
        .then(|| {
            rows.last()
                .map(|row| validation::encode_cursor(row.membership_id))
        })
        .flatten();
    Ok(PageInfo {
        next_cursor,
        has_more,
    })
}

fn invalid_fields() -> AppError {
    validation::field(
        "fields",
        "must be a comma-separated subset of name,id,role,org,tags,trust",
    )
}

const DIRECTORY_PROJECTION_BEFORE_TAGS: &str = r"
    SELECT
        membership.id AS membership_id,
        membership.principal_kind::text AS principal_kind,
        CASE
            WHEN membership.principal_kind = 'carbon' THEN carbon.display_name
            ELSE silicon.display_name
        END AS name,
        CASE
            WHEN membership.principal_kind = 'carbon' THEN carbon.carbon_id
            ELSE silicon.global_silicon_id
        END AS public_id,
        membership.org_role::text AS org_role,
        membership.job_role,
        organization.org_id AS organization_public_id,
        organization.name AS organization_name,
";

const ACTIVE_TAGS_PROJECTION: &str = r"
        COALESCE((
            SELECT jsonb_agg(
                jsonb_build_object('id', tag.id, 'name', tag.name)
                ORDER BY tag.id
            )
            FROM iam.membership_tags AS assignment
            JOIN iam.organization_tags AS tag
              ON tag.organization_id = assignment.organization_id
             AND tag.id = assignment.tag_id
             AND tag.status = 'active'
            WHERE assignment.organization_id = membership.organization_id
              AND assignment.membership_id = membership.id
        ), '[]'::jsonb) AS tags
";

const DIRECTORY_PROJECTION_AFTER_TAGS: &str = r"
    FROM iam.organization_memberships AS membership
    JOIN iam.organizations AS organization
      ON organization.id = membership.organization_id
     AND organization.status = 'active'
    LEFT JOIN iam.carbons AS carbon
      ON carbon.id = membership.principal_id
     AND membership.principal_kind = 'carbon'
    LEFT JOIN iam.silicons AS silicon
      ON silicon.id = membership.principal_id
     AND membership.principal_kind = 'silicon'
";

const DIRECTORY_TRUST_DEFAULT_SQL: &str = r"
    SELECT
        subject_membership.id AS subject_membership_id,
        COALESCE(
            carbon_settings.default_trust_boundary,
            organization.default_trust_boundary
        )::text AS default_trust_boundary,
        COALESCE(
            carbon_settings.default_trust_level,
            organization.default_trust_level
        )::text AS default_trust_level
    FROM iam.organization_memberships AS subject_membership
    JOIN iam.organizations AS organization
      ON organization.id = subject_membership.organization_id
    LEFT JOIN iam.carbon_membership_settings AS carbon_settings
      ON carbon_settings.organization_id = subject_membership.organization_id
     AND carbon_settings.membership_id = subject_membership.id
     AND subject_membership.principal_kind = 'carbon'
    WHERE subject_membership.organization_id = $1
      AND subject_membership.id = ANY($2)
      AND subject_membership.status = 'active'
";

const DIRECTORY_TRUST_MATCH_SQL: &str = r"
    WITH evaluation_target (
        directory_membership_id,
        subject_membership_id,
        target_silicon_membership_id
    ) AS (
        SELECT *
        FROM unnest($2::uuid[], $3::uuid[], $4::uuid[])
    )
    SELECT
        evaluation_target.directory_membership_id,
        rule.id,
        rule.subject_kind,
        rule.target_kind,
        rule.trust_boundary::text AS trust_boundary,
        rule.trust_level::text AS trust_level
    FROM evaluation_target
    JOIN iam.trust_rules AS rule
      ON rule.organization_id = $1
     AND rule.archived_at IS NULL
     AND (
         (
             rule.subject_kind = 'membership'
             AND rule.subject_membership_id = evaluation_target.subject_membership_id
         )
         OR (
             rule.subject_kind = 'tag'
             AND EXISTS (
                 SELECT 1
                 FROM iam.membership_tags AS subject_tag
                 WHERE subject_tag.organization_id = rule.organization_id
                   AND subject_tag.membership_id = evaluation_target.subject_membership_id
                   AND subject_tag.tag_id = rule.subject_tag_id
             )
         )
     )
     AND (
         (
             rule.target_kind = 'silicon'
             AND rule.target_silicon_membership_id = evaluation_target.target_silicon_membership_id
         )
         OR (
             rule.target_kind = 'tag'
             AND EXISTS (
                 SELECT 1
                 FROM iam.membership_tags AS target_tag
                 WHERE target_tag.organization_id = rule.organization_id
                   AND target_tag.membership_id = evaluation_target.target_silicon_membership_id
                   AND target_tag.tag_id = rule.target_tag_id
             )
         )
     )
    ORDER BY evaluation_target.directory_membership_id, rule.id
";

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn directory_row(principal_kind: &str) -> DirectoryRow {
        DirectoryRow {
            membership_id: Uuid::from_u128(10),
            principal_kind: principal_kind.to_owned(),
            name: "Directory member".to_owned(),
            public_id: "directory-member".to_owned(),
            org_role: "member".to_owned(),
            job_role: "Engineer".to_owned(),
            organization_public_id: "example-org".to_owned(),
            organization_name: "Example Org".to_owned(),
            tags: Json(vec![TagSummary {
                id: Uuid::from_u128(11),
                name: "Engineering".to_owned(),
            }]),
        }
    }

    #[test]
    fn directory_fields_default_to_all_and_reject_unknown_or_empty_values() {
        assert!(matches!(
            DirectoryFields::parse(None),
            Ok(fields) if fields == DirectoryFields::ALL
        ));
        assert!(matches!(
            DirectoryFields::parse(Some("name,id,trust")),
            Ok(fields) if fields == DirectoryFields(FIELD_NAME | FIELD_ID | FIELD_TRUST)
        ));
        assert!(DirectoryFields::parse(Some("")).is_err());
        assert!(DirectoryFields::parse(Some("name,principal_type")).is_err());
    }

    #[test]
    fn sparse_projection_omits_every_unrequested_field() {
        let member = DirectoryMember::project(
            directory_row("carbon"),
            DirectoryFields(FIELD_NAME | FIELD_ROLE),
            None,
        );
        assert!(matches!(
            serde_json::to_value(member),
            Ok(value) if value == json!({
                "name": "Directory member",
                "role": { "org_role": "member", "job_role": "Engineer" }
            })
        ));
    }

    #[test]
    fn default_projection_contains_the_complete_directory_contract() {
        let trust = trust::evaluate_matches("internal", "not_trusted", &[]).ok();
        let member = DirectoryMember::project(directory_row("carbon"), DirectoryFields::ALL, trust);
        assert!(matches!(
            serde_json::to_value(member),
            Ok(value) if value == json!({
                "name": "Directory member",
                "id": "directory-member",
                "role": { "org_role": "member", "job_role": "Engineer" },
                "org": { "id": "example-org", "name": "Example Org" },
                "tags": [{
                    "id": Uuid::from_u128(11),
                    "name": "Engineering"
                }],
                "trust": {
                    "trust": { "boundary": "internal", "level": "not_trusted" },
                    "source": "organization_default",
                    "matching_rule_ids": [],
                    "advisory": true
                }
            })
        ));
    }

    #[test]
    fn trust_orientation_uses_the_requesters_point_of_view() {
        let requester = Uuid::from_u128(20);
        let silicon = directory_row("silicon");
        assert!(matches!(
            trust_target(requester, ActorType::Carbon, &silicon),
            Ok(Some(target)) if target == (TrustEvaluationTarget {
                directory_member: silicon.membership_id,
                subject: requester,
                target_silicon: silicon.membership_id,
            })
        ));

        let carbon = directory_row("carbon");
        assert!(matches!(
            trust_target(requester, ActorType::Carbon, &carbon),
            Ok(None)
        ));
        let undefined =
            DirectoryMember::project(directory_row("carbon"), DirectoryFields(FIELD_TRUST), None);
        assert!(matches!(
            serde_json::to_value(undefined),
            Ok(value) if value == json!({ "trust": null })
        ));
        assert!(matches!(
            trust_target(requester, ActorType::Silicon, &carbon),
            Ok(None)
        ));
    }

    #[test]
    fn carbon_subject_defaults_are_membership_scoped_without_per_row_queries() {
        let requester = Uuid::from_u128(20);
        let carbon = directory_row("carbon");
        let silicon = directory_row("silicon");

        assert!(matches!(
            trust_target(requester, ActorType::Carbon, &silicon),
            Ok(Some(target)) if target.subject == requester
        ));
        assert!(matches!(
            trust_target(requester, ActorType::Silicon, &carbon),
            Ok(None)
        ));
        assert!(DIRECTORY_TRUST_DEFAULT_SQL.contains("carbon_membership_settings"));
        assert!(DIRECTORY_TRUST_DEFAULT_SQL.contains("ANY($2)"));
    }
}
