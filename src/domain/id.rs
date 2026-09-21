//! Storage references: canonical identity handles and opaque resource UUIDs.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sqlx::{
    Decode, Encode, Postgres, Type,
    postgres::{PgArgumentBuffer, PgHasArrayType, PgTypeInfo, PgValueRef},
};
use uuid::Uuid;

/// A reference to either an identity or an independently identified resource.
///
/// Identity keys are the immutable public handles themselves. Resource keys
/// (sessions, memberships, organizations, credentials, events) remain UUIDs.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Id {
    /// Opaque resource key; never a newly created identity key.
    Resource(Uuid),
    /// Canonical Carbon, Silicon, application, or service handle.
    Identity(IdentityId),
}

/// Bounded canonical ASCII identity handle, stored without allocation.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityId {
    bytes: [u8; 131],
    length: u8,
}

/// Invalid canonical identity key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("identity must be a canonical carbon_id, silicon_id, app_id, or service handle")]
pub struct InvalidIdentity;

const fn valid_part(
    bytes: &[u8],
    start: usize,
    end: usize,
    minimum: usize,
    maximum: usize,
) -> bool {
    if end - start < minimum || end - start > maximum {
        return false;
    }
    let mut index = start;
    while index < end {
        if !matches!(bytes[index], b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-') {
            return false;
        }
        index += 1;
    }
    true
}

const fn valid_identity(bytes: &[u8]) -> bool {
    if matches!(bytes, [b's', b'e', b'r', b'v', b'i', b'c', b'e', b'/', ..]) {
        return valid_part(bytes, 8, bytes.len(), 3, 63);
    }
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'>' {
            return valid_part(bytes, 0, index, 3, 50)
                && valid_part(bytes, index + 1, bytes.len(), 1, 80);
        }
        if bytes[index] == b':' {
            return valid_part(bytes, 0, index, 3, 50)
                && valid_part(bytes, index + 1, bytes.len(), 3, 50);
        }
        index += 1;
    }
    valid_part(bytes, 0, bytes.len(), 3, 30)
}

impl IdentityId {
    /// Validates an immutable public identity handle.
    ///
    /// # Errors
    /// Rejects whitespace, non-ASCII, uppercase, UUIDs, and invalid delimiters.
    pub fn parse(value: &str) -> Result<Self, InvalidIdentity> {
        if !valid_identity(value.as_bytes()) {
            return Err(InvalidIdentity);
        }
        let mut bytes = [0; 131];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            length: u8::try_from(value.len()).map_err(|_| InvalidIdentity)?,
        })
    }

    /// Canonical, immutable handle.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Construction accepts only ASCII and the fields are private.
        std::str::from_utf8(&self.bytes[..usize::from(self.length)]).unwrap_or_default()
    }
}

impl Id {
    /// Constructs an identity from its existing canonical public handle.
    ///
    /// # Errors
    /// Rejects values which are not canonical identity handles.
    pub fn identity(value: &str) -> Result<Self, InvalidIdentity> {
        IdentityId::parse(value).map(Self::Identity)
    }

    /// Creates an opaque resource UUID, never an identity handle.
    #[must_use]
    pub fn now_v7() -> Self {
        Self::Resource(Uuid::now_v7())
    }

    /// Constructs a resource fixture UUID.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        Self::Resource(Uuid::from_u128(value))
    }

    /// The nil resource UUID.
    #[must_use]
    pub const fn nil() -> Self {
        Self::Resource(Uuid::nil())
    }

    /// Parses an opaque resource UUID.
    ///
    /// # Errors
    /// Rejects canonical identity handles and malformed UUIDs.
    pub fn parse_str(value: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(value).map(Self::Resource)
    }

    /// Parses a canonical identity or opaque resource reference.
    ///
    /// # Errors
    /// Rejects values which are neither valid handles nor UUIDs.
    pub fn parse(value: &str) -> Result<Self, InvalidIdentity> {
        value.parse()
    }

    /// Constructs a resource UUID from exactly sixteen bytes.
    ///
    /// # Errors
    /// Rejects byte slices with the wrong length.
    pub fn from_slice(value: &[u8]) -> Result<Self, uuid::Error> {
        Uuid::from_slice(value).map(Self::Resource)
    }

    /// Binary UUID bytes or ASCII canonical identity bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Resource(value) => value.as_bytes(),
            Self::Identity(value) => value.as_str().as_bytes(),
        }
    }
}

impl From<Uuid> for Id {
    fn from(value: Uuid) -> Self {
        Self::Resource(value)
    }
}
impl From<IdentityId> for Id {
    fn from(value: IdentityId) -> Self {
        Self::Identity(value)
    }
}
impl FromStr for Id {
    type Err = InvalidIdentity;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self::Resource)
            .or_else(|_| Self::identity(value))
    }
}
impl fmt::Display for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource(value) => value.fmt(formatter),
            Self::Identity(value) => formatter.write_str(value.as_str()),
        }
    }
}
impl fmt::Debug for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}
impl fmt::Debug for IdentityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

impl Type<Postgres> for Id {
    fn type_info() -> PgTypeInfo {
        <Uuid as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <Uuid as Type<Postgres>>::compatible(ty) || <String as Type<Postgres>>::compatible(ty)
    }
}
impl PgHasArrayType for Id {
    fn array_type_info() -> PgTypeInfo {
        <Uuid as PgHasArrayType>::array_type_info()
    }
    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <Uuid as PgHasArrayType>::array_compatible(ty)
            || <String as PgHasArrayType>::array_compatible(ty)
    }
}
impl Encode<'_, Postgres> for Id {
    fn encode_by_ref(
        &self,
        buffer: &mut PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        match self {
            Self::Resource(value) => value.encode_by_ref(buffer),
            Self::Identity(value) => value.as_str().encode_by_ref(buffer),
        }
    }
    fn produces(&self) -> Option<PgTypeInfo> {
        Some(match self {
            Self::Resource(_) => <Uuid as Type<Postgres>>::type_info(),
            Self::Identity(_) => <String as Type<Postgres>>::type_info(),
        })
    }
    fn size_hint(&self) -> usize {
        self.as_bytes().len()
    }
}
impl<'r> Decode<'r, Postgres> for Id {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        use sqlx::ValueRef as _;
        if <Uuid as Type<Postgres>>::compatible(&value.type_info()) {
            Ok(Self::Resource(Uuid::decode(value)?))
        } else {
            Ok(Self::parse(<&str as Decode<Postgres>>::decode(value)?)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Id, IdentityId, valid_identity};

    impl Id {
        /// Builds a validated canonical identity constant for isolated test fixtures.
        pub(crate) const fn fixture(value: &str) -> Self {
            assert!(
                valid_identity(value.as_bytes()),
                "invalid canonical fixture identity"
            );
            let mut bytes = [0; 131];
            let mut length = 0_u8;
            while (length as usize) < value.len() {
                bytes[length as usize] = value.as_bytes()[length as usize];
                length += 1;
            }
            Self::Identity(IdentityId { bytes, length })
        }
    }

    #[test]
    fn identities_are_the_public_handles_and_do_not_accept_uuid_keys() -> anyhow::Result<()> {
        for handle in ["saket", "chef:bricks", "tos>iam", "service/iam-worker"] {
            let identity = Id::identity(handle)?;
            assert_eq!(identity.to_string(), handle);
            assert_eq!(serde_json::to_string(&identity)?, format!("\"{handle}\""));
            assert_eq!(
                serde_json::from_str::<Id>(&serde_json::to_string(&identity)?)?,
                identity
            );
        }
        for invalid in [
            "",
            "Saket",
            " saket",
            "a:b:c",
            "foo>bar>baz",
            "00000000-0000-0000-0000-000000000001",
        ] {
            assert!(IdentityId::parse(invalid).is_err());
        }
        for handle in [
            "a".repeat(30),
            format!("{}:{}", "s".repeat(50), "o".repeat(50)),
            format!("{}>{}", "o".repeat(50), "a".repeat(80)),
            format!("service/{}", "s".repeat(63)),
        ] {
            assert!(IdentityId::parse(&handle).is_ok());
        }
        for handle in [
            "a".repeat(31),
            format!("{}:org", "s".repeat(51)),
            format!("org>{}", "a".repeat(81)),
            format!("service/{}", "s".repeat(64)),
        ] {
            assert!(IdentityId::parse(&handle).is_err());
        }
        assert!(Id::parse_str("saket").is_err());
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires an isolated PostgreSQL URL in IAM_ID_TEST_DATABASE_URL"]
    async fn postgres_keeps_identity_text_distinct_from_resource_uuid() -> anyhow::Result<()> {
        let pool = sqlx::PgPool::connect(&std::env::var("IAM_ID_TEST_DATABASE_URL")?).await?;
        let identity = Id::identity("chef:bricks")?;
        let resource = Id::now_v7();
        let decoded_identity: Id = sqlx::query_scalar("SELECT $1::text")
            .bind(identity)
            .fetch_one(&pool)
            .await?;
        let decoded_resource: Id = sqlx::query_scalar("SELECT $1::uuid")
            .bind(resource)
            .fetch_one(&pool)
            .await?;
        assert_eq!(decoded_identity, identity);
        assert_eq!(decoded_resource, resource);
        assert!(
            sqlx::query_scalar::<_, Id>("SELECT $1::uuid")
                .bind(identity)
                .fetch_one(&pool)
                .await
                .is_err()
        );

        let mut connection = pool.acquire().await?;
        sqlx::query("CREATE TEMP TABLE canonical_identity_test (id text PRIMARY KEY CHECK (id = 'chef:bricks'))").execute(&mut *connection).await?;
        sqlx::query("INSERT INTO canonical_identity_test(id) VALUES($1)")
            .bind(identity)
            .execute(&mut *connection)
            .await?;
        // SQLx cannot infer the dynamic variant from None or a collection.
        // Identity cursors and batches therefore bind explicit text values.
        for after in [None, Some(identity)] {
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM canonical_identity_test WHERE $1::text IS NULL OR id >= $1",
            )
            .bind(after.map(|id| id.to_string()))
            .fetch_one(&mut *connection)
            .await?;
            assert_eq!(count, 1);
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM canonical_identity_test WHERE id = ANY($1::text[])",
        )
        .bind(vec![identity.to_string()])
        .fetch_one(&mut *connection)
        .await?;
        assert_eq!(count, 1);
        assert!(
            sqlx::query("INSERT INTO canonical_identity_test(id) VALUES($1)")
                .bind(resource)
                .execute(&mut *connection)
                .await
                .is_err()
        );
        Ok(())
    }
}
