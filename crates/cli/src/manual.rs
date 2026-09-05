//! Offline, package-contained copies of the complete consumer documentation.

use serde::Serialize;

use crate::{
    error::{CliError, Result},
    output::{self, Format},
};

#[path = "manual_data.rs"]
mod data;

#[derive(Serialize)]
struct Document {
    topic: &'static str,
    title: &'static str,
    source: &'static str,
    source_sha256: &'static str,
    format: &'static str,
    aliases: &'static [&'static str],
    content: &'static str,
}

#[derive(Serialize)]
struct DocumentSummary<'a> {
    topic: &'a str,
    title: &'a str,
    source: &'a str,
    source_sha256: &'a str,
    format: &'a str,
    aliases: &'a [&'a str],
    command: String,
}

impl<'a> From<&'a Document> for DocumentSummary<'a> {
    fn from(document: &'a Document) -> Self {
        Self {
            topic: document.topic,
            title: document.title,
            source: document.source,
            source_sha256: document.source_sha256,
            format: document.format,
            aliases: document.aliases,
            command: format!("iam docs {}", document.topic),
        }
    }
}

#[derive(Serialize)]
struct Index<'a> {
    cli_version: &'a str,
    bundled: bool,
    topics: Vec<DocumentSummary<'a>>,
}

#[derive(Serialize)]
struct SearchHit<'a> {
    #[serde(flatten)]
    topic: DocumentSummary<'a>,
    matches: usize,
    excerpts: Vec<Excerpt<'a>>,
}

#[derive(Serialize)]
struct Excerpt<'a> {
    line: usize,
    text: &'a str,
}

#[derive(Serialize)]
struct SearchResults<'a> {
    query: &'a str,
    cli_version: &'a str,
    results: Vec<SearchHit<'a>>,
}

/// Read or search the installed binary's manual without a client or filesystem.
pub fn run(format: Format, topic: Option<&str>, search: Option<&str>) -> Result<()> {
    let selected = topic.map(resolve).transpose()?;
    if let Some(query) = search {
        return search_documents(format, selected, query);
    }
    if let Some(document) = selected {
        return match format {
            Format::Json => output::json(&document),
            Format::Text => {
                // No preamble: `iam docs openapi > iam-openapi.yaml` is a valid
                // machine-consumable copy of the exact installed wire contract.
                print!("{}", document.content);
                Ok(())
            }
        };
    }
    print_index(format)
}

fn resolve(topic: &str) -> Result<&'static Document> {
    let normalized = topic.trim().to_ascii_lowercase();
    data::DOCUMENTS
        .iter()
        .find(|document| {
            document.topic == normalized
                || document
                    .aliases
                    .iter()
                    .any(|alias| *alias == normalized)
        })
        .ok_or_else(|| {
            CliError::Usage(format!(
                "unknown documentation topic {topic:?}; run `iam docs` for all topics or `iam docs --search <words>` to find a subject"
            ))
        })
}

fn print_index(format: Format) -> Result<()> {
    let index = Index {
        cli_version: env!("CARGO_PKG_VERSION"),
        bundled: true,
        topics: data::DOCUMENTS.iter().map(DocumentSummary::from).collect(),
    };
    match format {
        Format::Json => output::json(&index),
        Format::Text => {
            println!(
                "IAM offline documentation — bundled with CLI {}\n",
                index.cli_version
            );
            println!("Read:   iam docs <topic>");
            println!("Find:   iam docs --search 'authorization snapshot'");
            println!("Scope:  iam docs cli --search 'app create'");
            println!("Export: iam docs openapi > iam-openapi.yaml");
            println!("JSON:   iam -o json docs [topic]\n");
            println!("Start with cli, applications, authorization, testing, obo or storage.\n");
            for document in data::DOCUMENTS {
                println!("  {:<30} {}", document.topic, document.title);
                if !document.aliases.is_empty() {
                    println!("    aliases: {}", document.aliases.join(", "));
                }
            }
            println!(
                "\nThese are this binary's API, client and CLI manuals, not a live fetch.\nRun `iam <command> --help` for exact installed flags and required inputs.\nUse `iam system version` separately to check the configured backend revision."
            );
            Ok(())
        }
    }
}

fn search_documents(format: Format, selected: Option<&Document>, query: &str) -> Result<()> {
    let query = query.trim();
    if query.is_empty() {
        return Err(CliError::Usage(
            "documentation search cannot be empty; use `iam docs` to list topics".to_owned(),
        ));
    }
    let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    let matches_query = |text: &str| {
        let lower = text.to_lowercase();
        terms.iter().all(|term| lower.contains(term))
    };
    let documents = selected.map_or_else(
        || data::DOCUMENTS.iter().collect::<Vec<_>>(),
        |document| vec![document],
    );
    let mut results = Vec::new();
    for document in documents {
        let mut matches = 0;
        let mut excerpts = Vec::new();
        for (index, line) in document.content.lines().enumerate() {
            if matches_query(line) {
                matches += 1;
                if excerpts.len() < 3 {
                    excerpts.push(Excerpt {
                        line: index + 1,
                        text: line.trim(),
                    });
                }
            }
        }
        if matches > 0
            || matches_query(document.title)
            || matches_query(document.topic)
            || document.aliases.iter().any(|alias| matches_query(alias))
        {
            results.push(SearchHit {
                topic: DocumentSummary::from(document),
                matches,
                excerpts,
            });
        }
    }
    let results = SearchResults {
        query,
        cli_version: env!("CARGO_PKG_VERSION"),
        results,
    };
    match format {
        Format::Json => output::json(&results),
        Format::Text => {
            if results.results.is_empty() {
                println!(
                    "No bundled documentation matched {query:?}.\nTry a shorter term, or run `iam docs` to list topics."
                );
            } else {
                println!("Documentation matching {query:?}:\n");
                for hit in results.results {
                    println!("{} — {}", hit.topic.command, hit.topic.title);
                    for excerpt in hit.excerpts {
                        println!("  line {}: {}", excerpt.line, excerpt.text);
                    }
                    if hit.matches > 3 {
                        println!("  … {} matching lines in this document", hit.matches);
                    }
                    println!();
                }
            }
            Ok(())
        }
    }
}
