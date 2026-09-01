//! Shared actor identity types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Kind of principal represented by an IAM actor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// Human account.
    Carbon,
    /// AI-agent account.
    Silicon,
    /// Registered OAuth application.
    Application,
    /// Internal platform service.
    Service,
}

impl ActorType {
    /// Stable PostgreSQL and API representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Carbon => "carbon",
            Self::Silicon => "silicon",
            Self::Application => "application",
            Self::Service => "service",
        }
    }
}

/// Collision-free reference to a principal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ActorRef {
    /// Principal kind.
    #[serde(rename = "type")]
    pub actor_type: ActorType,
    /// Internal `UUIDv7` identity.
    pub id: Uuid,
}
