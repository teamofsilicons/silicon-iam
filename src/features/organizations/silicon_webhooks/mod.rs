//! Configurable, authenticated organization event webhooks for Silicons.

mod endpoints;
mod shared;
mod subscriptions;

pub(super) use endpoints::{delete_webhook, get_webhook, replace_webhook};
pub(super) use subscriptions::{delete_subscription, get_subscription, replace_subscription};
