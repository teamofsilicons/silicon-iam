//! Configurable, authenticated organization event webhooks for Silicons.

mod endpoints;
mod replays;
mod shared;
mod subscriptions;

pub(super) use endpoints::{delete_webhook, get_webhook, replace_webhook};
pub(super) use replays::{list_dead_letters, replay_dead_letters};
pub(super) use subscriptions::{delete_subscription, get_subscription, replace_subscription};
