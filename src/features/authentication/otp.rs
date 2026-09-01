use secrecy::{ExposeSecret as _, SecretString};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, FromRow, PartialEq, Eq)]
pub(super) struct AttemptState {
    pub(super) failed_attempts: i16,
    pub(super) cooldown_until: Option<OffsetDateTime>,
}

/// Carries one failed-verification window across replacement codes.
///
/// Callers normalize expired cooldowns to `None` in their locked SQL query.
/// An active cooldown dominates any partial counter; otherwise the greatest
/// counter wins so legacy duplicate active rows cannot weaken the scope.
pub(super) fn inherited_attempt_state(states: &[AttemptState]) -> AttemptState {
    if let Some(cooldown_until) = states.iter().filter_map(|state| state.cooldown_until).max() {
        return AttemptState {
            failed_attempts: 0,
            cooldown_until: Some(cooldown_until),
        };
    }
    AttemptState {
        failed_attempts: states
            .iter()
            .map(|state| state.failed_attempts)
            .max()
            .unwrap_or_default(),
        cooldown_until: None,
    }
}

pub(super) fn bound_secret(
    domain: &'static str,
    scope_id: Uuid,
    code: &SecretString,
) -> SecretString {
    let mut value = String::with_capacity(domain.len() + 1 + 36 + 1 + 6);
    value.push_str(domain);
    value.push(':');
    value.push_str(&scope_id.to_string());
    value.push(':');
    value.push_str(code.expose_secret());
    SecretString::from(value)
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret as _, SecretString};
    use uuid::Uuid;

    use time::{Duration, OffsetDateTime};

    use super::{AttemptState, bound_secret, inherited_attempt_state};

    #[test]
    fn otp_binding_separates_domain_and_session() {
        let code = SecretString::from("123456".to_owned());
        let first = bound_secret("login", Uuid::from_u128(1), &code);
        let second = bound_secret("login", Uuid::from_u128(2), &code);
        let third = bound_secret("step-up", Uuid::from_u128(1), &code);
        assert_ne!(first.expose_secret(), second.expose_secret());
        assert_ne!(first.expose_secret(), third.expose_secret());
    }

    #[test]
    fn replacement_codes_inherit_failed_attempts_or_active_cooldown() {
        let partial = inherited_attempt_state(&[
            AttemptState {
                failed_attempts: 3,
                cooldown_until: None,
            },
            AttemptState {
                failed_attempts: 7,
                cooldown_until: None,
            },
        ]);
        assert_eq!(partial.failed_attempts, 7);
        assert_eq!(partial.cooldown_until, None);

        let first_cooldown = OffsetDateTime::UNIX_EPOCH + Duration::minutes(1);
        let last_cooldown = first_cooldown + Duration::seconds(10);
        let cooldown = inherited_attempt_state(&[
            AttemptState {
                failed_attempts: 9,
                cooldown_until: Some(first_cooldown),
            },
            AttemptState {
                failed_attempts: 2,
                cooldown_until: Some(last_cooldown),
            },
        ]);
        assert_eq!(cooldown.failed_attempts, 0);
        assert_eq!(cooldown.cooldown_until, Some(last_cooldown));
    }
}
