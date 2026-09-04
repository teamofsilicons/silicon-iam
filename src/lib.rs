//! Silicon IAM backend library.
//!
//! The crate is a modular monolith. Domain policy is isolated from transport
//! and provider details; the API and worker binaries are composition roots.

#![forbid(unsafe_code)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

pub mod api;
pub mod application;
pub mod config;
pub mod domain;
pub mod error;
pub(crate) mod features;
pub mod infrastructure;
pub mod request_context;
pub mod shutdown;
pub mod telemetry;
pub(crate) mod web;
pub(crate) mod wire_time;
pub mod worker;
