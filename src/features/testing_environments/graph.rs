//! Cycle-safe production dependency discovery and atomic test-plane imports.

use std::collections::{BTreeMap, BTreeSet};

use crate::domain::id::Id;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};

use crate::{
    api::ApiState,
    error::AppError,
    infrastructure::{
        crypto::{DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField, SecretKind},
        testing_plane,
    },
};

use super::{imports::ProductionApplication, support};

/// Expand each unique application once. A frontier is fetched in one query;
/// cycles and diamonds terminate without imposing an arbitrary graph depth.
pub(super) async fn load(
    state: &ApiState,
    root: &str,
) -> Result<BTreeMap<String, ProductionApplication>, AppError> {
    load_with_pins(state, root, &BTreeMap::new(), &BTreeSet::new()).await
}

pub(super) async fn load_with_pins(
    state: &ApiState,
    root: &str,
    pins: &BTreeMap<String, ProductionApplication>,
    refresh: &BTreeSet<String>,
) -> Result<BTreeMap<String, ProductionApplication>, AppError> {
    let mut graph = BTreeMap::new();
    let mut pending = BTreeSet::from([root.to_owned()]);
    while !pending.is_empty() {
        let requested = std::mem::take(&mut pending);
        let from_production = requested
            .iter()
            .filter(|id| !pins.contains_key(*id) || refresh.contains(*id))
            .cloned()
            .collect::<Vec<_>>();
        let mut sources = sqlx::query_as::<_, ProductionApplication>(
            "SELECT * FROM iam_private.get_testing_application_import_v2($1)",
        )
        .bind(&from_production)
        .fetch_all(&state.pool)
        .await
        .map_err(support::database)?;
        if sources.len() != from_production.len() {
            return Err(AppError::Conflict {
                code: "testing_dependency_unavailable".into(),
            });
        }
        for id in requested
            .iter()
            .filter(|id| pins.contains_key(*id) && !refresh.contains(*id))
        {
            if let Some(source) = pins.get(id) {
                sources.push(source.clone());
            }
        }
        for source in sources {
            for dependency in dependencies(&source.app_scope)? {
                if !graph.contains_key(&dependency) && !requested.contains(&dependency) {
                    pending.insert(dependency);
                }
            }
            graph.insert(source.app_id.clone(), source);
        }
    }
    Ok(graph)
}

fn dependencies(scope: &Value) -> Result<BTreeSet<String>, AppError> {
    let Some(external) = scope.get("external").and_then(Value::as_array) else {
        return Err(AppError::Internal {
            category: "testing_dependency_scope",
        });
    };
    external
        .iter()
        .map(|entry| {
            entry
                .get("app_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(AppError::Internal {
                    category: "testing_dependency_scope",
                })
        })
        .collect()
}

#[derive(sqlx::FromRow)]
struct StoredImport {
    application_id: Id,
    secret_ciphertext: Vec<u8>,
    secret_nonce: Vec<u8>,
    secret_key_version: i16,
}

pub(super) struct ImportedApplication {
    pub(super) application_id: Id,
    pub(super) app_secret: SecretString,
    pub(super) created: bool,
    pub(super) refreshed: bool,
}

/// The control plane has already verified the production app and environment.
/// One test transaction creates every missing dependency and activates their
/// declared scopes only after all endpoints exist.
pub(super) async fn import_all(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    graph: &BTreeMap<String, ProductionApplication>,
    root: &str,
) -> Result<BTreeMap<String, ImportedApplication>, AppError> {
    import_graph(transaction, state, graph, root, &BTreeSet::new()).await
}

/// Explicitly refreshes requested imported revisions and their test credentials.
pub(super) async fn import_exact(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    graph: &BTreeMap<String, ProductionApplication>,
    root: &str,
    refresh: &BTreeSet<String>,
) -> Result<BTreeMap<String, ImportedApplication>, AppError> {
    import_graph(transaction, state, graph, root, refresh).await
}

#[allow(
    clippy::too_many_lines,
    reason = "one transaction preserves graph identity, credentials, and accepted pins"
)]
async fn import_graph(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    graph: &BTreeMap<String, ProductionApplication>,
    root: &str,
    refresh: &BTreeSet<String>,
) -> Result<BTreeMap<String, ImportedApplication>, AppError> {
    let selected = testing_plane::current().ok_or(AppError::Forbidden)?;
    // Serialize all import entry points within this environment, including a
    // failed cross-database retry. IDs and credentials can then be reused.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("testing-import:{}", selected.id))
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    let mut imported = BTreeMap::new();
    for (app_id, source) in graph {
        let imported_source = sqlx::query_scalar::<_, Id>(
            "SELECT source_application_id FROM iam_private.honeycomb_testing_application_source($1)")
            .bind(app_id).fetch_optional(&mut **transaction).await.map_err(support::database)?;
        if imported_source.is_some_and(|identity| identity != source.source_application_id) {
            return Err(AppError::Conflict {
                code: "testing_source_identity_conflict".into(),
            });
        }
        let existing = sqlx::query_as::<_, StoredImport>(
            "SELECT * FROM iam_private.get_testing_application_secret($1)",
        )
        .bind(app_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?;
        let refresh_id = if let Some(existing) = &existing {
            let revision: i64 =
                sqlx::query_scalar("SELECT iam_private.testing_import_revision($1)")
                    .bind(existing.application_id)
                    .fetch_one(&mut **transaction)
                    .await
                    .map_err(support::database)?;
            (refresh.contains(app_id) && revision != source.source_revision)
                .then_some(existing.application_id)
        } else {
            None
        };
        let application = if let Some(id) = refresh_id {
            create_one(transaction, state, source, selected.id, Some(id)).await?
        } else if let Some(existing) = existing {
            let plaintext = state
                .crypto
                .decrypt(
                    secret_context(selected.id, existing.application_id),
                    &encrypted(
                        existing.secret_key_version,
                        &existing.secret_nonce,
                        existing.secret_ciphertext,
                    )?,
                )
                .map_err(|_| AppError::Internal {
                    category: "testing_application_secret_decrypt",
                })?;
            ImportedApplication {
                application_id: existing.application_id,
                created: false,
                refreshed: false,
                app_secret: SecretString::from(String::from_utf8(plaintext.to_vec()).map_err(
                    |_| AppError::Internal {
                        category: "testing_application_secret_encoding",
                    },
                )?),
            }
        } else {
            create_one(transaction, state, source, selected.id, None).await?
        };
        super::discovery::register(
            transaction,
            application.application_id,
            &application.app_secret,
        )
        .await?;
        // The pinned source contains only already-encrypted webhook material.
        // It lets later additive imports retain accepted dependency revisions.
        if application.created || application.refreshed {
            let snapshot = serde_json::to_value(source).map_err(|_| AppError::Internal {
                category: "testing_snapshot_encode",
            })?;
            // This helper exists only on upgraded testing databases.
            sqlx::query("SELECT iam_private.honeycomb_testing_store_snapshot($1,$2,$3)")
                .bind(application.application_id)
                .bind(source.source_revision)
                .bind(snapshot)
                .execute(&mut **transaction)
                .await
                .map_err(support::database)?;
        }
        imported.insert(app_id.clone(), application);
    }
    if !imported.contains_key(root) {
        return Err(AppError::NotFound);
    }
    super::scope_policy::synchronize(transaction, &state.pool).await?;
    sqlx::query("SELECT iam_private.activate_testing_application_scopes($1)")
        .bind(
            imported
                .values()
                .map(|app| app.application_id.to_string())
                .collect::<Vec<_>>(),
        )
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    Ok(imported)
}

#[allow(clippy::too_many_lines)]
pub(super) async fn create_one(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    source: &ProductionApplication,
    environment_id: Id,
    existing: Option<Id>,
) -> Result<ImportedApplication, AppError> {
    let application_id = Id::identity(&source.app_id).map_err(|_| AppError::Internal {
        category: "canonical_imported_application_identity",
    })?;
    let signing_key_id = Id::now_v7();
    let app_secret = state
        .crypto
        .generate_secret(SecretKind::ApplicationSecret)
        .map_err(|_| AppError::Internal {
            category: "testing_application_secret_generate",
        })?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::ApplicationSecret, &app_secret)
        .map_err(|_| AppError::Internal {
            category: "testing_application_secret_digest",
        })?;
    let stored_secret = state
        .crypto
        .encrypt(
            secret_context(environment_id, application_id),
            app_secret.expose_secret().as_bytes(),
        )
        .map_err(|_| AppError::Internal {
            category: "testing_application_secret_encrypt",
        })?;
    let webhook_url = state
        .crypto
        .decrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookUrl,
                source
                    .encryption_application_id
                    .unwrap_or(source.source_application_id),
                source.source_webhook_endpoint_id,
            )
            .production_application(),
            &encrypted(
                source.webhook_url_encryption_key_version,
                &source.webhook_url_nonce,
                source.webhook_url_ciphertext.clone(),
            )?,
        )
        .map_err(|_| AppError::Internal {
            category: "testing_import_url_decrypt",
        })?;
    let webhook_secret = state
        .crypto
        .decrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookSigningSecret,
                source
                    .encryption_application_id
                    .unwrap_or(source.source_application_id),
                source.source_webhook_signing_key_id,
            )
            .production_application(),
            &encrypted(
                source.webhook_secret_encryption_key_version,
                &source.webhook_secret_nonce,
                source.webhook_secret_ciphertext.clone(),
            )?,
        )
        .map_err(|_| AppError::Internal {
            category: "testing_import_webhook_decrypt",
        })?;
    let endpoint_id = sqlx::query_scalar::<_, Option<Id>>(
        "SELECT iam_private.testing_import_webhook_endpoint($1,$2)",
    )
    .bind(application_id)
    .bind(Sha256::digest(&webhook_url).as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?
    .unwrap_or_else(Id::now_v7);
    let url = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookUrl,
                application_id,
                endpoint_id,
            ),
            &webhook_url,
        )
        .map_err(|_| AppError::Internal {
            category: "testing_import_url_encrypt",
        })?;
    let signing_secret = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookSigningSecret,
                application_id,
                signing_key_id,
            ),
            &webhook_secret,
        )
        .map_err(|_| AppError::Internal {
            category: "testing_import_webhook_encrypt",
        })?;
    let config = json!({
        "application_id": application_id, "source_application_id": source.source_application_id, "source_revision":source.source_revision,
        "app_id": source.app_id, "org_id": source.org_id, "organization_name": source.organization_name,
        "organization_logo": source.organization_logo_uri, "organization_description": source.organization_description,
        "app_name": source.app_name, "app_logo": source.app_logo_uri, "base_url": source.base_url,
        "visibility": source.visibility, "app_scope": source.app_scope, "webhook_scope": source.webhook_scope, "testing_idle_days": source.testing_idle_days,
        "obo_endpoints": source.obo_endpoints, "endpoint_id": endpoint_id, "signing_key_id": signing_key_id,
        "webhook_secret_version": source.webhook_secret_version,
        "webhook_fingerprint": crate::features::applications::webhook_secret_fingerprint(std::str::from_utf8(&webhook_secret)
            .map_err(|_| AppError::Internal { category: "testing_import_webhook_encoding" })?),
        "url_ciphertext": hex::encode(url.ciphertext), "url_nonce": hex::encode(url.nonce), "url_key_version": url.key_version,
        "url_digest": hex::encode(Sha256::digest(&webhook_url)),
        "signing_ciphertext": hex::encode(signing_secret.ciphertext), "signing_nonce": hex::encode(signing_secret.nonce),
        "signing_key_version": signing_secret.key_version,
        "secret_id": Id::now_v7(), "secret_digest": hex::encode(digest.as_bytes()), "secret_digest_version": digest.key_version(),
        "secret_prefix": app_secret.expose_secret().chars().take(12).collect::<String>(),
        "secret_ciphertext": hex::encode(stored_secret.ciphertext), "secret_nonce": hex::encode(stored_secret.nonce),
        "secret_key_version": stored_secret.key_version,
    });
    sqlx::query("SELECT iam_private.import_testing_application_configuration($1)")
        .bind(sqlx::types::Json(config))
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    Ok(ImportedApplication {
        application_id,
        app_secret,
        created: existing.is_none(),
        refreshed: existing.is_some(),
    })
}

pub(super) const fn secret_context(environment_id: Id, application_id: Id) -> EncryptionContext {
    EncryptionContext::tenant(
        ProtectedField::TestingApplicationSecret,
        environment_id,
        application_id,
    )
}

pub(super) fn encrypted(
    version: i16,
    nonce: &[u8],
    ciphertext: Vec<u8>,
) -> Result<EncryptedValue, AppError> {
    Ok(EncryptedValue {
        key_version: version,
        nonce: nonce.try_into().map_err(|_| AppError::Internal {
            category: "testing_import_nonce",
        })?,
        ciphertext,
    })
}

/// Keeps the test-only recoverable credential aligned with explicit rotation.
pub(crate) async fn record_rotated_application_secret(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    application_id: Id,
    secret: &SecretString,
) -> Result<(), AppError> {
    let Some(environment_id) = testing_plane::current_id() else {
        return Ok(());
    };
    super::discovery::register(transaction, application_id, secret).await?;
    let stored = state
        .crypto
        .encrypt(
            secret_context(environment_id, application_id),
            secret.expose_secret().as_bytes(),
        )
        .map_err(|_| AppError::Internal {
            category: "testing_application_secret_encrypt",
        })?;
    sqlx::query("SELECT iam_private.update_testing_application_secret($1,$2,$3,$4)")
        .bind(application_id)
        .bind(stored.ciphertext)
        .bind(stored.nonce.as_slice())
        .bind(stored.key_version)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    Ok(())
}

/// Testing recipients validate their environment-bound app secret with IAM.
/// The production protocol never includes this context or reveals a secret.
pub(crate) async fn obo_context(state: &ApiState, app_id: &str) -> Result<Option<Value>, AppError> {
    let Some(environment) = testing_plane::current() else {
        return Ok(None);
    };
    let mut transaction = crate::infrastructure::postgres::context::begin(
        state.db(),
        crate::infrastructure::postgres::context::DatabaseContext::anonymous(),
    )
    .await
    .map_err(support::database)?;
    let stored = sqlx::query_as::<_, StoredImport>(
        "SELECT * FROM iam_private.get_testing_application_secret($1)",
    )
    .bind(app_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(support::database)?;
    let Some(stored) = stored else {
        // Locally authored test applications are already held by their creator.
        return Ok(None);
    };
    let secret = state
        .crypto
        .decrypt(
            secret_context(environment.id, stored.application_id),
            &encrypted(
                stored.secret_key_version,
                &stored.secret_nonce,
                stored.secret_ciphertext,
            )?,
        )
        .map_err(|_| AppError::Internal {
            category: "testing_application_secret_decrypt",
        })?;
    transaction.commit().await.map_err(support::database)?;
    let key = sqlx::query_as::<_, (Id, Vec<u8>, Vec<u8>, i16)>(
        "SELECT * FROM iam_private.get_testing_environment_obo_key($1)",
    )
    .bind(environment.id)
    .fetch_one(&state.pool)
    .await
    .map_err(support::database)?;
    let iam_test_key = state
        .crypto
        .decrypt(
            EncryptionContext::tenant(ProtectedField::TestingEnvironmentKey, key.0, environment.id),
            &encrypted(key.3, &key.2, key.1)?,
        )
        .map_err(|_| AppError::Internal {
            category: "testing_environment_key_decrypt",
        })?;
    Ok(Some(json!({"app_id":app_id,
        "app_secret":std::str::from_utf8(&secret).map_err(|_| AppError::Internal { category: "testing_application_secret_encoding" })?,
        "iam_test_key":std::str::from_utf8(&iam_test_key).map_err(|_| AppError::Internal { category: "testing_environment_key_encoding" })?})))
}

/// Reflect successfully authenticated test traffic in the production listing.
/// The test database remains authoritative when the worker rechecks expiry.
pub(crate) async fn touch_application_activity(state: &ApiState, application_id: Id) {
    let Some(environment_id) = testing_plane::current_id() else {
        return;
    };
    if let Err(error) =
        sqlx::query("SELECT iam_private.touch_application_testing_environment($1,$2)")
            .bind(environment_id)
            .bind(application_id)
            .execute(&state.pool)
            .await
    {
        tracing::warn!(%error,%environment_id,%application_id,"could not sync application testing activity");
    }
}

#[cfg(test)]
mod tests {
    use super::dependencies;
    use serde_json::json;

    #[test]
    fn dependency_edges_are_deduplicated_without_losing_distinct_apps() {
        let result = dependencies(&json!({"external": [
            {"app_id":"files", "endpoint_id":"read"},
            {"app_id":"files", "endpoint_id":"write"},
            {"app_id":"other>search", "endpoint_id":"query"}
        ]}));
        assert_eq!(result.ok().map(|value| value.len()), Some(2));
        assert!(dependencies(&json!({"external":[{}]})).is_err());
    }
}
