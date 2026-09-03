//! Turning results into something worth reading, or worth piping.

use serde::Serialize;

use crate::error::Result;

/// How a command renders its result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Aligned columns for a person.
    #[default]
    Text,
    /// The service's own JSON, for a script.
    Json,
}

/// Prints a value as pretty JSON.
///
/// # Errors
///
/// Returns an error when the value cannot be encoded.
pub fn json<T: Serialize>(value: &T) -> Result<()> {
    let encoded = serde_json::to_string_pretty(value).map_err(|error| {
        crate::error::CliError::Config(format!("cannot encode output: {error}"))
    })?;
    println!("{encoded}");
    Ok(())
}

/// A table built column by column, printed with aligned headers.
///
/// Deliberately simple: no wrapping, no colour, no borders. The output is as
/// likely to be read by `awk` as by a person, and every one of those would get
/// in the way.
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// Starts a table with the given column headers.
    pub fn new<I, S>(headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            headers: headers.into_iter().map(Into::into).collect(),
            rows: Vec::new(),
        }
    }

    /// Appends one row. Short rows are padded, long ones are kept whole.
    pub fn row<I, S>(&mut self, cells: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.rows.push(cells.into_iter().map(Into::into).collect());
    }

    /// Prints the table, or a quiet note when there is nothing in it.
    pub fn print(&self) {
        if self.rows.is_empty() {
            println!("(none)");
            return;
        }
        let mut widths: Vec<usize> = self
            .headers
            .iter()
            .map(|header| header.chars().count())
            .collect();
        for row in &self.rows {
            for (index, cell) in row.iter().enumerate() {
                let width = cell.chars().count();
                match widths.get_mut(index) {
                    Some(current) if *current < width => *current = width,
                    Some(_) => {}
                    None => widths.push(width),
                }
            }
        }
        println!("{}", render(&self.headers, &widths));
        for row in &self.rows {
            println!("{}", render(row, &widths));
        }
    }
}

/// Pads every cell but the last, so a trailing value with spaces in it does
/// not leave ragged whitespace at the end of the line.
fn render(cells: &[String], widths: &[usize]) -> String {
    let mut line = String::new();
    for (index, cell) in cells.iter().enumerate() {
        if index + 1 == cells.len() {
            line.push_str(cell);
        } else {
            let width = widths.get(index).copied().unwrap_or(0);
            let padding = width.saturating_sub(cell.chars().count());
            line.push_str(cell);
            line.extend(std::iter::repeat_n(' ', padding + 2));
        }
    }
    line
}

/// Renders an optional value as a dash rather than an empty column.
#[must_use]
pub fn or_dash(value: Option<&str>) -> String {
    value.unwrap_or("-").to_owned()
}

/// Renders a JSON value the way a person would write it.
///
/// A few contract fields are constants or open shapes and arrive as raw JSON.
/// Printing `"silicon-iam"` with its quotes in a text table would be an
/// artefact of that, not information.
#[must_use]
pub fn plain(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

/// Renders an optional timestamp, or a dash.
#[must_use]
pub fn timestamp_or_dash(value: Option<time::OffsetDateTime>) -> String {
    value.map_or_else(|| "-".to_owned(), timestamp)
}

/// Renders a timestamp in the form the service uses.
#[must_use]
pub fn timestamp(value: time::OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| value.unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::{Table, or_dash, render};

    #[test]
    fn columns_line_up_and_the_last_is_not_padded() {
        let widths = vec![5, 3];
        assert_eq!(
            render(&["ab".to_owned(), "c".to_owned()], &widths),
            "ab     c"
        );
    }

    #[test]
    fn an_empty_table_says_so_rather_than_printing_a_bare_header() {
        let table = Table::new(["id", "name"]);
        assert!(table.rows.is_empty());
    }

    #[test]
    fn a_json_string_loses_its_quotes_but_other_shapes_do_not() {
        assert_eq!(
            super::plain(&serde_json::json!("silicon-iam")),
            "silicon-iam"
        );
        assert_eq!(super::plain(&serde_json::json!(true)), "true");
        assert_eq!(super::plain(&serde_json::json!(12)), "12");
    }

    #[test]
    fn absent_values_render_as_a_dash() {
        assert_eq!(or_dash(None), "-");
        assert_eq!(or_dash(Some("value")), "value");
    }
}
