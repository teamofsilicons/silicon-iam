use secrecy::{ExposeSecret as _, SecretString};
use uuid::Uuid;

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

    use super::bound_secret;

    #[test]
    fn otp_binding_separates_domain_and_session() {
        let code = SecretString::from("123456".to_owned());
        let first = bound_secret("login", Uuid::from_u128(1), &code);
        let second = bound_secret("login", Uuid::from_u128(2), &code);
        let third = bound_secret("step-up", Uuid::from_u128(1), &code);
        assert_ne!(first.expose_secret(), second.expose_secret());
        assert_ne!(first.expose_secret(), third.expose_secret());
    }
}
