//! Temporary digest translation for authenticated retries across the identity cutover.
//!
//! This metadata is never consulted by identity lookup or authentication. New
//! reservations use canonical digests; only existing reservations are searched
//! using the legacy candidates, until their original maximum expiry.
pub mod cutover;

use crate::{domain::id::Id, infrastructure::testing_plane};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// Private operator export; UUIDs are replay/consumer migration metadata only.
#[derive(Clone, Debug, Deserialize, Serialize, sqlx::FromRow)]
pub struct Entry {
    /// Pre-cutover identifier.
    pub legacy_id: uuid::Uuid,
    /// Immutable canonical handle.
    pub public_id: String,
    /// Isolated data plane, absent for production.
    pub testing_environment_id: Option<uuid::Uuid>,
    /// Identity subtype; resource identifiers are deliberately excluded.
    pub actor_type: String,
}

#[derive(Clone, Default)]
pub(crate) struct Bridge {
    entries: BTreeMap<(Option<Id>, String), (uuid::Uuid, OffsetDateTime)>,
    expires_at: Option<OffsetDateTime>,
}
impl Bridge {
    pub(crate) async fn load(&mut self, pool: &sqlx::PgPool) -> anyhow::Result<()> {
        let rows: Vec<(String, Option<uuid::Uuid>, uuid::Uuid, OffsetDateTime)> = sqlx::query_as(
            "SELECT public_id, testing_environment_id, legacy_id, expires_at FROM iam_private.canonical_replay_contexts()"
        ).fetch_all(pool).await?;
        for (id, environment, legacy, expiry) in rows {
            Id::identity(&id)?;
            let previous = self
                .entries
                .insert((environment.map(Id::from), id), (legacy, expiry));
            anyhow::ensure!(
                previous.is_none_or(|old| old.0 == legacy),
                "conflicting replay metadata"
            );
            self.expires_at = Some(self.expires_at.map_or(expiry, |old| old.max(expiry)));
        }
        Ok(())
    }
    pub(crate) fn active(&self) -> bool {
        self.entries.iter().any(|((env, _), (_, expiry))| {
            *env == testing_plane::current_id() && *expiry > OffsetDateTime::now_utc()
        })
    }
    pub(crate) fn legacy_identity(&self, value: &[u8]) -> Option<uuid::Uuid> {
        if self
            .expires_at
            .is_none_or(|expiry| expiry <= OffsetDateTime::now_utc())
        {
            return None;
        }
        let value = std::str::from_utf8(value).ok()?;
        self.entries
            .get(&(testing_plane::current_id(), value.to_owned()))
            .filter(|(_, expiry)| *expiry > OffsetDateTime::now_utc())
            .map(|(id, _)| *id)
    }
    pub(crate) fn caller(&self, value: &str) -> String {
        if self
            .expires_at
            .is_none_or(|expiry| expiry <= OffsetDateTime::now_utc())
        {
            return value.to_owned();
        }
        // Caller scopes are server-created namespaces, never arbitrary request
        // text. Longest-first matching keeps Silicon's embedded colon intact.
        let mut identities: Vec<_> = self
            .entries
            .iter()
            .filter(|((env, _), (_, expiry))| {
                *env == testing_plane::current_id() && *expiry > OffsetDateTime::now_utc()
            })
            .collect();
        identities.sort_by_key(|((_, id), _)| std::cmp::Reverse(id.len()));
        let mut out = String::new();
        let mut offset = 0;
        while offset < value.len() {
            let prefix = &value[..offset];
            let identity_slot = matches!(
                prefix,
                "carbon:"
                    | "silicon:"
                    | "application:"
                    | "platform-admin:"
                    | "application-testing:"
                    | "testing_environment:carbon:"
                    | "testing_environment:silicon:"
                    | "testing_environment:application:"
            ) || prefix.ends_with(":app:")
                || prefix.ends_with(":application:")
                || prefix.ends_with(":application:Some(");
            let found = identity_slot
                .then(|| {
                    identities.iter().find(|((_, id), _)| {
                        value[offset..].starts_with(id.as_str())
                            && (offset + id.len() == value.len()
                                || matches!(value.as_bytes()[offset + id.len()], b':' | b')'))
                    })
                })
                .flatten();
            if let Some(((_, id), (old, _))) = found {
                out.push_str(&old.to_string());
                offset += id.len();
            } else {
                let ch = value[offset..].chars().next().unwrap_or_default();
                out.push(ch);
                offset += ch.len_utf8();
            }
        }
        out
    }
    pub(crate) fn inputs(
        &self,
        caller: &SecretString,
        request: &SecretString,
    ) -> Option<(SecretString, SecretString)> {
        if !self.active() {
            return None;
        }
        let old_caller = self.caller(caller.expose_secret());
        let mut old_request = legacy_json(request.expose_secret(), |value| {
            self.legacy_identity(value.as_bytes())
        });
        // Silicon creation serialized an absent Description as null. Patch
        // requests omitted it, so only this exact creation shape gets the slot.
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(request.expose_secret())
            && value.get("silicon_id").is_some()
            && value.get("job_description").is_some()
            && value.get("profile_photo").is_some()
            && value.get("description").is_none()
        {
            old_request = old_request.replacen(
                "\"profile_photo\":",
                "\"description\":null,\"profile_photo\":",
                1,
            );
        }
        if old_caller == caller.expose_secret() && old_request == request.expose_secret() {
            return None;
        }
        Some((
            SecretString::from(old_caller),
            SecretString::from(old_request),
        ))
    }
}

/// Rewrites JSON string tokens in place, preserving exact field order and every
/// non-identity byte used by the historical request digest.
pub(crate) fn legacy_json(
    input: &str,
    mut lookup: impl FnMut(&str) -> Option<uuid::Uuid>,
) -> String {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut offset = 0;
    let mut key = String::new();
    let mut depth = 0_u32;
    while offset < bytes.len() {
        if bytes[offset] != b'"' {
            match bytes[offset] {
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
            output.push(char::from(bytes[offset]));
            offset += 1;
            continue;
        }
        let start = offset;
        offset += 1;
        while offset < bytes.len() {
            if bytes[offset] == b'\\' {
                offset += 2;
            } else if bytes[offset] == b'"' {
                offset += 1;
                break;
            } else {
                offset += 1;
            }
        }
        let raw = &input[start..offset.min(bytes.len())];
        let Ok(value) = serde_json::from_str::<String>(raw) else {
            return input.to_owned();
        };
        let is_key = bytes
            .get(offset..)
            .is_some_and(|rest| rest.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b':'));
        let replacement = if is_key {
            key.clone_from(&value);
            match (depth, value.as_str()) {
                (1, "job_description") => Some("job_role".to_owned()),
                (1, "old_job_description") => Some("old_job_role".to_owned()),
                (1, "new_job_description") => Some("new_job_role".to_owned()),
                _ => None,
            }
        } else if depth == 1
            && identity_field(&key)
            && !matches!(key.as_str(), "id" | "carbon_id" | "silicon_id")
        {
            lookup(&value).map(|id| id.to_string())
        } else {
            None
        };
        output.push_str(
            replacement
                .as_ref()
                .and_then(|value| serde_json::to_string(value).ok())
                .as_deref()
                .unwrap_or(raw),
        );
    }
    output
}
fn identity_field(key: &str) -> bool {
    !key.starts_with("encryption_")
        && (key == "id"
            || key == "application_id"
            || key == "source_application_id"
            || key == "subject_id"
            || key == "actor_id"
            || key == "target_id"
            || key == "created_by_carbon_id"
            || key.ends_with("principal_id")
            || key.ends_with("_application_id")
            || key == "carbon_id"
            || key == "silicon_id")
}

/// Converts protected historical response JSON without rewriting unrelated
/// resource UUIDs or user-authored strings. Callers retain all ciphertext rows.
pub fn canonical_payload(
    value: &mut serde_json::Value,
    entries: &[Entry],
    environment: Option<uuid::Uuid>,
) {
    convert(value, entries, environment, None);
}
fn convert(
    value: &mut serde_json::Value,
    entries: &[Entry],
    environment: Option<uuid::Uuid>,
    parent: Option<&str>,
) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                convert(item, entries, environment, parent);
            }
        }
        serde_json::Value::Object(object) => {
            let explicit_type = object.get("type").and_then(serde_json::Value::as_str);
            let typed_identity = object
                .get("actor_type")
                .or_else(|| object.get("type"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| {
                    matches!(kind, "carbon" | "silicon" | "application" | "service")
                })
                || (explicit_type.is_none()
                    && (object.contains_key("carbon_id")
                        || object.contains_key("silicon_id")
                        || object.contains_key("app_id")
                        || matches!(
                            parent,
                            Some("actor" | "subject" | "principal" | "recipient")
                        )));
            for (key, child) in object.iter_mut() {
                if key == "id" && !typed_identity {
                    continue;
                }
                convert(child, entries, environment, Some(key));
            }
            for (old, new) in [
                ("job_role", "job_description"),
                ("old_job_role", "old_job_description"),
                ("new_job_role", "new_job_description"),
                ("previous_job_role", "previous_job_description"),
            ] {
                if let Some(old) = object.remove(old) {
                    object.entry(new).or_insert(old);
                }
            }
            if object.contains_key("carbon_id")
                || object.contains_key("silicon_id")
                || parent == Some("profile")
            {
                object.remove("description");
            }
            if matches!(parent, Some("trust"))
                || (object.contains_key("trust") && object.contains_key("source"))
            {
                object.remove("advisory");
            }
        }
        serde_json::Value::String(text) if parent.is_some_and(identity_field) => {
            if let Ok(id) = uuid::Uuid::parse_str(text)
                && let Some(entry) = entries.iter().find(|entry| {
                    entry.legacy_id == id && entry.testing_environment_id == environment
                })
            {
                text.clone_from(&entry.public_id);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    impl Bridge {
        // Exercise the old 0111 replay bridge without admitting old public IDs to
        // the current runtime loader. This is only compiled for its migration test.
        pub(crate) async fn load_legacy_cutover_fixture(
            &mut self,
            pool: &sqlx::PgPool,
        ) -> anyhow::Result<()> {
            let rows: Vec<(String, Option<uuid::Uuid>, uuid::Uuid, OffsetDateTime)> = sqlx::query_as(
                "SELECT public_id, testing_environment_id, legacy_id, expires_at FROM iam_private.canonical_replay_contexts()",
            ).fetch_all(pool).await?;
            for (id, environment, legacy, expiry) in rows {
                self.entries
                    .insert((environment.map(Id::from), id), (legacy, expiry));
                self.expires_at = Some(self.expires_at.map_or(expiry, |old| old.max(expiry)));
            }
            Ok(())
        }

        pub(crate) fn fixture(
            entries: &[(Option<Id>, &str, uuid::Uuid)],
            expiry: OffsetDateTime,
        ) -> Self {
            Self {
                entries: entries
                    .iter()
                    .map(|(env, id, old)| ((*env, (*id).to_owned()), (*old, expiry)))
                    .collect(),
                expires_at: Some(expiry),
            }
        }
    }

    #[tokio::test]
    async fn replay_translation_expires_and_never_rewrites_resource_scope() {
        let old = uuid::Uuid::from_u128(1);
        let other = uuid::Uuid::from_u128(2);
        let env = Id::from_u128(3);
        let bridge = Bridge::fixture(
            &[
                (None, "saket", old),
                (None, "chef:bricks", other),
                (Some(env), "saket", other),
            ],
            OffsetDateTime::now_utc() + time::Duration::hours(1),
        );
        assert_eq!(
            bridge.caller("carbon:saket:global:chef:bricks"),
            format!("carbon:{old}:global:chef:bricks")
        );
        testing_plane::scope(
            testing_plane::SelectedEnvironment {
                id: env,
                organization_id: Id::nil(),
            },
            async {
                assert_eq!(bridge.caller("carbon:saket"), format!("carbon:{other}"));
            },
        )
        .await;
        let expired = Bridge::fixture(
            &[(None, "saket", old)],
            OffsetDateTime::now_utc() - time::Duration::seconds(1),
        );
        assert_eq!(expired.caller("carbon:saket"), "carbon:saket");
        assert!(
            expired
                .inputs(
                    &SecretString::from("carbon:saket"),
                    &SecretString::from(r#"{"job_description":"Chef"}"#)
                )
                .is_none()
        );
        assert_eq!(
            legacy_json(
                r#"{"metadata":{"job_description":"leave","actor_id":"saket"}}"#,
                |_| Some(old)
            ),
            r#"{"metadata":{"job_description":"leave","actor_id":"saket"}}"#
        );
    }

    #[test]
    fn rewrites_only_identity_fields_and_preserves_request_bytes() {
        let old = uuid::Uuid::from_u128(1);
        assert_eq!(
            legacy_json(
                r#"{"job_description":"saket","actor_id":"saket","name":"saket"}"#,
                |id| (id == "saket").then_some(old)
            ),
            format!(r#"{{"job_role":"saket","actor_id":"{old}","name":"saket"}}"#)
        );
        let mut response = serde_json::json!({"membership":{"id":old.to_string()},"actor":{"id":old.to_string(),"actor_type":"carbon"},"message":old.to_string(),"encryption_application_id":old.to_string()});
        canonical_payload(
            &mut response,
            &[Entry {
                legacy_id: old,
                public_id: "saket".into(),
                testing_environment_id: None,
                actor_type: "carbon".into(),
            }],
            None,
        );
        assert_eq!(response["actor"]["id"], "saket");
        assert_eq!(response["membership"]["id"], old.to_string());
        assert_eq!(response["message"], old.to_string());
        assert_eq!(response["encryption_application_id"], old.to_string());
    }
}
