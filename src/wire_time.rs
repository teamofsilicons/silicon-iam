//! Stable JSON encoding for API timestamps.
//!
//! The public contract is RFC3339. The legacy tuple is accepted only while
//! decoding server-owned idempotency records written before that contract was
//! enforced; serialization can never produce it again.

use serde::{Deserialize, Deserializer, de::Error as _};
use time::{Date, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

#[derive(Deserialize)]
#[serde(untagged)]
enum Representation {
    Rfc3339(String),
    Legacy((i32, u16, u8, u8, u8, u32, i8, i8, i8)),
}

/// Serializes one timestamp as RFC3339.
pub(crate) fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    time::serde::rfc3339::serialize(value, serializer)
}

/// Deserializes RFC3339 plus the old server-only tuple representation.
pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    decode(Representation::deserialize(deserializer)?).map_err(D::Error::custom)
}

fn decode(value: Representation) -> Result<OffsetDateTime, String> {
    match value {
        Representation::Rfc3339(value) => {
            OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339)
                .map_err(|error| error.to_string())
        }
        Representation::Legacy((year, ordinal, hour, minute, second, nanosecond, oh, om, os)) => {
            let date = Date::from_ordinal_date(year, ordinal).map_err(|error| error.to_string())?;
            let time = Time::from_hms_nano(hour, minute, second, nanosecond)
                .map_err(|error| error.to_string())?;
            let offset = UtcOffset::from_hms(oh, om, os).map_err(|error| error.to_string())?;
            Ok(PrimitiveDateTime::new(date, time).assume_offset(offset))
        }
    }
}

/// Optional timestamp support with the same compatibility rule.
pub(crate) mod option {
    use serde::{Deserialize as _, Deserializer, de::Error as _};
    use time::OffsetDateTime;

    use super::Representation;

    #[allow(
        clippy::ref_option,
        reason = "serde's `with` module contract borrows the field's exact Option type"
    )]
    pub(crate) fn serialize<S>(
        value: &Option<OffsetDateTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        time::serde::rfc3339::option::serialize(value, serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Representation>::deserialize(deserializer)?
            .map(super::decode)
            .transpose()
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use time::macros::datetime;

    #[derive(Debug, Deserialize, Serialize)]
    struct Timestamp {
        #[serde(with = "crate::wire_time")]
        at: time::OffsetDateTime,
    }

    #[test]
    fn writes_rfc3339_and_reads_the_legacy_tuple() {
        let encoded = serde_json::to_value(Timestamp {
            at: datetime!(2026-09-04 13:45:02.409017 UTC),
        })
        .unwrap_or(Value::Null);
        assert_eq!(
            encoded.get("at").and_then(Value::as_str),
            Some("2026-09-04T13:45:02.409017Z")
        );

        let legacy = serde_json::json!({
            "at": [2026, 247, 13, 45, 2, 409_017_000, 0, 0, 0]
        });
        let decoded = serde_json::from_value::<Timestamp>(legacy);
        assert!(decoded.is_ok_and(|value| value.at == datetime!(2026-09-04 13:45:02.409017 UTC)));
    }
}
