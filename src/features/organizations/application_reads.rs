//! Application bearer read gates and explicit field allowlists.
//!
//! Direct IAM reads retain their full resource shape. Application reads expose
//! only fields authorized by their current token scopes; absent data is omitted.

use crate::domain::id::Id;
use axum::{http::StatusCode, response::Response};
use serde::Serialize;
use serde_json::Value;

use crate::{api::authentication::Authenticated, error::AppError};

use super::support;

#[derive(Clone, Copy)]
pub(crate) struct ReadScopes<'a>(Option<&'a [String]>);

impl<'a> ReadScopes<'a> {
    pub(crate) fn for_actor(actor: &'a Authenticated) -> Self {
        Self(
            actor
                .0
                .client_application_id
                .map(|_| actor.0.scopes.as_slice()),
        )
    }

    pub(crate) const fn is_application(self) -> bool {
        self.0.is_some()
    }

    pub(crate) fn has(self, scope: &str) -> bool {
        self.0
            .is_none_or(|scopes| scopes.iter().any(|value| value == scope))
    }

    pub(crate) fn require(self, scope: &str) -> Result<(), AppError> {
        if self.has(scope) {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    pub(crate) fn require_any(self, scopes: &[&str]) -> Result<(), AppError> {
        if scopes.iter().any(|scope| self.has(scope)) {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    pub(crate) fn require_actor(self, kind: &str) -> Result<(), AppError> {
        self.require(if kind == "carbon" {
            "directory.carbons.read"
        } else {
            "directory.silicons.read"
        })
    }

    /// Restrict SQL before pagination so an app cannot discover an unapproved actor type.
    pub(crate) fn actor_filter(
        self,
        requested: Option<&'a str>,
    ) -> Result<Option<&'a str>, AppError> {
        if let Some(kind) = requested {
            self.require_actor(kind)?;
            return Ok(Some(kind));
        }
        match (
            self.has("directory.carbons.read"),
            self.has("directory.silicons.read"),
        ) {
            (true, true) => Ok(None),
            (true, false) => Ok(Some("carbon")),
            (false, true) => Ok(Some("silicon")),
            (false, false) => Err(AppError::Forbidden),
        }
    }

    pub(crate) fn profile(self, mut value: Value, is_self: bool) -> Value {
        if !self.is_application() {
            return value;
        }
        let identity = self.has(if is_self {
            "self.identity.read"
        } else {
            "directory.carbons.read"
        });
        let profile = self.has(if is_self {
            "self.profile.read"
        } else {
            "directory.profiles.read"
        });
        retain(&mut value, |key| match key {
            "principal_id" | "carbon_id" | "silicon_id" | "type" => identity,
            "display_name" | "timezone" | "profile_photo" => profile,
            "email" => is_self && self.has("self.email.read"),
            "phone_number" => is_self && self.has("self.phone.read"),
            "version" => true,
            _ => false,
        });
        value
    }

    pub(crate) fn organization(self, mut value: Value) -> Value {
        if self.is_application() {
            retain(&mut value, |key| {
                matches!(
                    key,
                    "id" | "org_id" | "name" | "logo" | "description" | "version"
                )
            });
        }
        value
    }

    pub(crate) fn member(self, mut value: Value, is_self: bool) -> Value {
        if !self.is_application() {
            return value;
        }
        let membership = self.has(if is_self {
            "self.membership.read"
        } else {
            "directory.memberships.read"
        });
        let job = self.has(if is_self {
            "self.job_role.read"
        } else {
            "directory.job_roles.read"
        });
        let tags = self.has(if is_self {
            "self.tags.read"
        } else {
            "directory.tags.read"
        });
        let hierarchy = self.has(if is_self {
            "self.hierarchy.read"
        } else {
            "directory.hierarchy.read"
        });
        let access = self.has(if is_self {
            "self.silicon_access.read"
        } else {
            "directory.silicon_access.read"
        });
        let capabilities = self.has(if is_self {
            "self.capabilities.read"
        } else {
            "directory.capabilities.read"
        });
        let identity = !is_self || self.has("self.identity.read");
        retain(&mut value, |key| match key {
            "id" | "membership_id" | "version" => true,
            "principal" => identity,
            "org_id" => self.has("self.organizations.read"),
            "org_role" | "status" | "removed_at" | "authorization_epoch" => membership,
            "job_description" => job,
            "profile" | "display_name" => self.has(if is_self {
                "self.profile.read"
            } else {
                "directory.profiles.read"
            }),
            "tags" => tags,
            "reports_to_membership_id" | "hierarchy_level" => hierarchy,
            "first_silicon_membership_id" | "extra_silicons" | "accessible_silicons" => access,
            "capabilities" => capabilities,
            // self.trust.read is an effective POV, never this raw configuration.
            "default_trust" => self.has("organization.trust.read"),
            _ => false,
        });
        value
    }

    pub(crate) fn silicon(self, mut value: Value, is_self: bool) -> Value {
        if !self.is_application() {
            return value;
        }
        value["type"] = Value::String("silicon".to_owned());
        let mut profile = self.profile(value.clone(), is_self);
        if !is_self && self.has("directory.silicons.read") {
            for key in ["principal_id", "silicon_id", "type"] {
                if let Some(field) = value.get(key) {
                    profile[key] = field.clone();
                }
            }
        }
        if let (Some(target), Some(fields)) = (
            profile.as_object_mut(),
            self.member(value, is_self).as_object(),
        ) {
            target.extend(fields.clone());
        }
        profile
    }

    pub(crate) fn directory(self, mut value: Value, is_self: bool) -> Value {
        if !self.is_application() {
            return value;
        }
        let profile = self.has(if is_self {
            "self.profile.read"
        } else {
            "directory.profiles.read"
        });
        let membership = self.has(if is_self {
            "self.membership.read"
        } else {
            "directory.memberships.read"
        });
        let job = self.has(if is_self {
            "self.job_role.read"
        } else {
            "directory.job_roles.read"
        });
        let tags = self.has(if is_self {
            "self.tags.read"
        } else {
            "directory.tags.read"
        });
        retain(&mut value, |key| match key {
            "id" => !is_self || self.has("self.identity.read"),
            "name" | "display_name" => profile,
            "role" => membership || job,
            "org" => self.has("self.organizations.read"),
            "tags" => tags,
            "trust" => self.has("self.trust.read"),
            _ => false,
        });
        if let Some(role) = value.get_mut("role") {
            retain(role, |key| match key {
                "org_role" => membership,
                "job_description" => job,
                "profile" | "display_name" => self.has(if is_self {
                    "self.profile.read"
                } else {
                    "directory.profiles.read"
                }),
                _ => false,
            });
        }
        // The effective answer is allowed, but matching rule IDs reveal the organization configuration.
        if !self.has("organization.trust.read")
            && let Some(trust) = value.get_mut("trust")
        {
            retain(trust, |key| key == "trust");
        }
        value
    }
}

fn retain(value: &mut Value, allowed: impl Fn(&str) -> bool) {
    if let Some(object) = value.as_object_mut() {
        object.retain(|key, _| allowed(key));
    }
}

pub(crate) fn value<T: Serialize>(resource: &T) -> Result<Value, AppError> {
    serde_json::to_value(resource).map_err(|_| AppError::Internal {
        category: "application_read_projection",
    })
}

pub(crate) fn member_json<T: Serialize>(
    actor: &Authenticated,
    resource: &T,
    membership_id: Id,
    own_membership_id: Id,
    version: Option<i64>,
) -> Result<Response, AppError> {
    let projected =
        ReadScopes::for_actor(actor).member(value(resource)?, membership_id == own_membership_id);
    support::json(StatusCode::OK, &projected, version)
}

pub(crate) fn page_json<T: Serialize>(
    resource: &T,
    project: impl Fn(Value) -> Value,
) -> Result<Response, AppError> {
    let mut page = value(resource)?;
    if let Some(items) = page.get_mut("items").and_then(Value::as_array_mut) {
        for item in items {
            *item = project(std::mem::take(item));
        }
    }
    support::json(StatusCode::OK, &page, None)
}

/// Adds only requested profile, capability, and access columns in one bounded query.
pub(super) async fn enrich_members(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &Authenticated,
    organization_id: Id,
    members: &[super::model::MembershipResponse],
    is_self: bool,
) -> Result<Vec<Value>, AppError> {
    let scopes = ReadScopes::for_actor(actor);
    let mut projected = members.iter().map(value).collect::<Result<Vec<_>, _>>()?;
    let profiles = scopes.has(if is_self {
        "self.profile.read"
    } else {
        "directory.profiles.read"
    });
    let capabilities = scopes.has(if is_self {
        "self.capabilities.read"
    } else {
        "directory.capabilities.read"
    });
    let access = scopes.has(if is_self {
        "self.silicon_access.read"
    } else {
        "directory.silicon_access.read"
    });
    if profiles || capabilities || access {
        let ids = members.iter().map(|member| member.id).collect::<Vec<_>>();
        let rows = sqlx::query_as::<_, (Id, sqlx::types::Json<Value>)>(MEMBER_EXTRAS_SQL)
            .bind(organization_id)
            .bind(&ids)
            .bind(profiles)
            .bind(capabilities)
            .bind(access)
            .fetch_all(&mut **transaction)
            .await
            .map_err(support::database)?;
        let extra = rows
            .into_iter()
            .map(|(id, data)| (id, data.0))
            .collect::<std::collections::BTreeMap<_, _>>();
        for (member, item) in members.iter().zip(&mut projected) {
            if let (Some(target), Some(fields)) = (
                item.as_object_mut(),
                extra.get(&member.id).and_then(Value::as_object),
            ) {
                target.extend(fields.clone());
            }
        }
    }
    for item in &mut projected {
        if let Some(name) = item
            .get("profile")
            .and_then(|profile| profile.get("display_name"))
            .cloned()
        {
            item["display_name"] = name;
        }
    }
    Ok(projected
        .into_iter()
        .map(|item| scopes.member(item, is_self))
        .collect())
}

const MEMBER_EXTRAS_SQL: &str = r"
    WITH RECURSIVE hierarchy AS (
        SELECT root.membership_id, 1 AS level FROM iam.silicons root
        WHERE $3 AND root.organization_id = $1 AND root.reports_to_membership_id IS NULL
          AND root.provisioning_status <> 'deleted'
        UNION ALL
        SELECT child.membership_id, hierarchy.level + 1 FROM iam.silicons child
        JOIN hierarchy ON child.reports_to_membership_id = hierarchy.membership_id
        WHERE child.organization_id = $1 AND child.provisioning_status <> 'deleted'
    )
    SELECT membership.id, jsonb_strip_nulls(jsonb_build_object(
      'profile', CASE WHEN $3 THEN jsonb_build_object(
        'display_name', COALESCE(carbon.display_name, silicon.display_name),
        'timezone', COALESCE(carbon.timezone_id, silicon.timezone_id),
        'profile_photo', CASE WHEN membership.principal_kind = 'carbon'
          THEN COALESCE(carbon.profile_photo_uri, 'https://iris.teamofsilicons.com/pfp/carbon?id=' || carbon.carbon_id)
          ELSE COALESCE(silicon.profile_photo_override_uri, 'https://iris.teamofsilicons.com/pfp/silicon?id=' || silicon.global_silicon_id || '&level=' || COALESCE(hierarchy.level, 1)::text) END
      ) END,
      'capabilities', CASE WHEN $4 THEN (SELECT COALESCE(jsonb_agg(grant_record.capability ORDER BY grant_record.capability), '[]'::jsonb)
        FROM iam.organization_capability_grants grant_record WHERE grant_record.organization_id = $1
        AND grant_record.grantee_membership_id = membership.id AND grant_record.revoked_at IS NULL) END,
      'accessible_silicons', CASE WHEN $5 AND membership.principal_kind = 'carbon' THEN (
        SELECT COALESCE(jsonb_agg(jsonb_build_object('membership_id', target.membership_id, 'silicon_id', target.global_silicon_id, 'display_name', CASE WHEN $3 THEN target.display_name END) ORDER BY target.membership_id), '[]'::jsonb)
        FROM iam.silicons target JOIN iam.organization_memberships active_target ON active_target.id = target.membership_id AND active_target.organization_id = $1 AND active_target.status = 'active'
        WHERE target.organization_id = $1 AND target.provisioning_status = 'active' AND (
          target.membership_id = settings.first_silicon_membership_id
          OR EXISTS (SELECT 1 FROM iam.extra_silicon_access_grants extra WHERE extra.organization_id = $1 AND extra.carbon_membership_id = membership.id AND extra.silicon_membership_id = target.membership_id AND extra.revoked_at IS NULL)
          OR EXISTS (SELECT 1 FROM iam.membership_tags own_tag JOIN iam.membership_tags target_tag ON target_tag.organization_id = own_tag.organization_id AND target_tag.tag_id = own_tag.tag_id JOIN iam.organization_tags tag ON tag.id = own_tag.tag_id AND tag.organization_id = $1 AND tag.status = 'active' WHERE own_tag.organization_id = $1 AND own_tag.membership_id = membership.id AND target_tag.membership_id = target.membership_id)
        )
      ) END
    )) FROM iam.organization_memberships membership
    LEFT JOIN iam.carbons carbon ON carbon.id = membership.principal_id AND membership.principal_kind = 'carbon'
    LEFT JOIN iam.silicons silicon ON silicon.id = membership.principal_id AND membership.principal_kind = 'silicon'
    LEFT JOIN hierarchy ON hierarchy.membership_id = silicon.membership_id
    LEFT JOIN iam.carbon_membership_settings settings ON settings.organization_id = $1 AND settings.membership_id = membership.id
    WHERE membership.organization_id = $1 AND membership.id = ANY($2)
";

/// Reads the authenticated Silicon itself through the same selected-organization gate.
pub(crate) async fn self_silicon(
    state: crate::api::ApiState,
    actor: Authenticated,
) -> Result<Response, AppError> {
    use crate::infrastructure::postgres::context::{self, DatabaseContext};
    use axum::extract::{Path, State};
    let mut transaction =
        context::begin(state.db(), DatabaseContext::principal(actor.0.subject.id))
            .await
            .map_err(support::database)?;
    let (organization, silicon_id) = sqlx::query_as::<_, (String, String)>(
        "SELECT organization.org_id, silicon.global_silicon_id FROM iam.silicons silicon JOIN iam.organizations organization ON organization.id = silicon.organization_id WHERE silicon.id = $1 AND silicon.provisioning_status <> 'deleted'"
    ).bind(actor.0.subject.id).fetch_optional(&mut *transaction).await.map_err(support::database)?.ok_or(AppError::NotFound)?;
    transaction.commit().await.map_err(support::database)?;
    super::silicons::get_silicon(State(state), actor, Path((organization, silicon_id))).await
}

/// Effective trust snapshots without raw defaults or rule identifiers.
pub(crate) async fn effective_self_trust(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Id,
    subjects: &[Id],
) -> Result<std::collections::BTreeMap<Id, Value>, AppError> {
    super::directory_views::effective_trust_for_subjects(transaction, organization_id, subjects)
        .await
}

#[cfg(test)]
mod tests {
    use super::ReadScopes;
    use serde_json::json;

    #[test]
    fn profile_permission_cannot_disclose_contacts_or_membership_data() {
        let granted = vec!["self.profile.read".to_owned()];
        let scopes = ReadScopes(Some(&granted));
        let profile = scopes.profile(json!({"carbon_id":"ada","display_name":"Ada","email":"secret@example.test","phone_number":"+15555550100","org_role":"owner","version":4}), true);
        assert_eq!(profile, json!({"display_name":"Ada","version":4}));
    }

    #[test]
    fn role_and_job_disclosures_are_independent_even_inside_nested_objects() {
        let granted = vec![
            "directory.carbons.read".to_owned(),
            "directory.job_roles.read".to_owned(),
        ];
        let scopes = ReadScopes(Some(&granted));
        let projected = scopes.directory(json!({"id":"ada","name":"Ada","role":{"org_role":"owner","job_description":"Engineer"},"tags":[{"name":"private"}]}), false);
        assert_eq!(
            projected,
            json!({"id":"ada","role":{"job_description":"Engineer"}})
        );
        assert_eq!(scopes.actor_filter(None).ok(), Some(Some("carbon")));
        assert!(scopes.actor_filter(Some("silicon")).is_err());
    }

    #[test]
    fn self_scopes_do_not_disclose_other_members_and_raw_trust_is_never_self_trust() {
        let granted = vec!["self.tags.read".to_owned(), "self.trust.read".to_owned()];
        let scopes = ReadScopes(Some(&granted));
        let input = json!({"id":"m1","tags":[{"id":"t1"}],"default_trust":{"boundary":"internal"}});
        assert_eq!(scopes.member(input.clone(), false), json!({"id":"m1"}));
        assert_eq!(
            scopes.member(input, true),
            json!({"id":"m1","tags":[{"id":"t1"}]})
        );
        assert!(scopes.actor_filter(None).is_err());
    }

    #[test]
    fn organization_disclosure_excludes_owner_and_internal_configuration() {
        let granted = vec!["self.organizations.read".to_owned()];
        let scopes = ReadScopes(Some(&granted));
        assert_eq!(scopes.organization(json!({"org_id":"acme","name":"Acme","owner_membership_id":"secret","join_method":"open","sso_status":"enabled","trusted_org":true})),json!({"org_id":"acme","name":"Acme"}));
    }

    #[test]
    fn silicon_identity_includes_type_without_granting_profile_or_hierarchy() {
        let granted = vec!["self.identity.read".to_owned()];
        let projected = ReadScopes(Some(&granted)).silicon(json!({
            "silicon_id":"acme>worker","display_name":"Worker","reports_to_membership_id":"parent",
            "tags":[{"id":"private"}],"version":2
        }), true);
        assert_eq!(
            projected,
            json!({"silicon_id":"acme>worker","type":"silicon","version":2})
        );
    }

    #[test]
    fn effective_self_trust_does_not_reveal_matching_rules() {
        let granted = vec!["self.trust.read".to_owned()];
        let projected = ReadScopes(Some(&granted)).directory(json!({
            "trust":{"trust":{"level":"high","boundary":"internal"},"source":"tag_rule","matching_rule_ids":["private-rule"]}
        }), true);
        assert_eq!(
            projected,
            json!({"trust":{"trust":{"level":"high","boundary":"internal"}}})
        );
    }
}
