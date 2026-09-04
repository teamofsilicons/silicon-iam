//! The client itself: configuration, and the one place a request is sent.

use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use url::Url;

use crate::{
    credentials::{Credential, EnvironmentKey},
    error::{ApiError, Envelope, Error, Result},
    request::Mutation,
};

/// The API version this client speaks.
pub const API_VERSION: &str = "v1";

const SUPPORTED_VERSIONS_HEADER: &str = "silicon-iam-supported-api-versions";
const ENVIRONMENT_KEY_HEADER: &str = "x-testing-environment-key";

/// A configured Silicon IAM client.
///
/// The client holds no mutable state. It never writes to disk, never caches a
/// response, and never refreshes a credential on your behalf -- a token that
/// expires produces an error, and renewing it is the caller's decision. Two
/// calls made with the same client are independent, so one client can be
/// shared across tasks and threads.
#[derive(Clone, Debug)]
pub struct Client {
    http: reqwest::Client,
    base_url: Url,
    credential: Credential,
    environment: Option<EnvironmentKey>,
}

/// Assembles a [`Client`].
#[derive(Debug)]
pub struct ClientBuilder {
    base_url: Url,
    credential: Credential,
    environment: Option<EnvironmentKey>,
    timeout: Duration,
    user_agent: Option<String>,
}

impl Client {
    /// Starts building a client for a service base URL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] when the URL cannot be parsed or is not
    /// `http`/`https`.
    pub fn builder(base_url: &str) -> Result<ClientBuilder> {
        ClientBuilder::new(base_url)
    }

    /// An anonymous client, which is all the signup and login routes need.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is unusable or the HTTP stack cannot be
    /// initialized.
    pub fn new(base_url: &str) -> Result<Self> {
        ClientBuilder::new(base_url)?.build()
    }

    /// The service this client talks to.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// The credential every request from this client presents.
    #[must_use]
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The testing environment this client executes inside, if any.
    #[must_use]
    pub fn environment(&self) -> Option<&EnvironmentKey> {
        self.environment.as_ref()
    }

    /// The same client, presenting a different credential.
    ///
    /// Cheap: the underlying connection pool is shared. Use it to move from
    /// the anonymous client that performed a login to an authenticated one.
    #[must_use]
    pub fn with_credential(&self, credential: Credential) -> Self {
        Self {
            credential,
            ..self.clone()
        }
    }

    /// The same client, executing inside a testing environment.
    ///
    /// Every subsequent request runs against that environment's data instead
    /// of production, over the identical routes -- which is the whole point of
    /// an environment, and why this is a property of the client rather than a
    /// separate set of methods.
    #[must_use]
    pub fn with_environment(&self, environment: EnvironmentKey) -> Self {
        Self {
            environment: Some(environment),
            ..self.clone()
        }
    }

    /// The same client, back on production data.
    #[must_use]
    pub fn without_environment(&self) -> Self {
        Self {
            environment: None,
            ..self.clone()
        }
    }

    /// Builds a request against a versioned API route.
    ///
    /// Routes are named as path segments rather than a formatted string, so a
    /// value carrying a slash or a `..` becomes one escaped segment instead of
    /// changing which route is called.
    pub(crate) fn route(
        &self,
        method: Method,
        segments: &[&str],
    ) -> Result<reqwest::RequestBuilder> {
        Ok(self.prepare(method, self.versioned_url(segments)?))
    }

    fn versioned_url(&self, segments: &[&str]) -> Result<Url> {
        let mut url = self.base_url.clone();
        {
            let Ok(mut path) = url.path_segments_mut() else {
                return Err(Error::Invalid(
                    "the base URL cannot carry a path".to_owned(),
                ));
            };
            path.pop_if_empty()
                .extend(["api", API_VERSION])
                .extend(segments);
        }
        Ok(url)
    }

    /// Builds a request against a route that sits outside `/api/v1`.
    pub(crate) fn unversioned(
        &self,
        method: Method,
        segments: &[&str],
    ) -> Result<reqwest::RequestBuilder> {
        let mut url = self.base_url.clone();
        {
            let Ok(mut path) = url.path_segments_mut() else {
                return Err(Error::Invalid(
                    "the base URL cannot carry a path".to_owned(),
                ));
            };
            path.pop_if_empty().extend(segments);
        }
        Ok(self.prepare(method, url))
    }

    fn prepare(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        let mut request = self
            .http
            .request(method, url)
            .header(SUPPORTED_VERSIONS_HEADER, API_VERSION);
        request = self.credential.apply(request);
        if let Some(environment) = &self.environment {
            request = request.header(ENVIRONMENT_KEY_HEADER, environment.expose());
        }
        request
    }

    pub(crate) async fn get<R: DeserializeOwned>(&self, segments: &[&str]) -> Result<R> {
        self.send_json(self.route(Method::GET, segments)?).await
    }

    pub(crate) async fn get_with<R: DeserializeOwned>(
        &self,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<R> {
        let mut url = self.versioned_url(segments)?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in query {
                pairs.append_pair(name, value);
            }
        }
        self.send_json(self.prepare(Method::GET, url)).await
    }

    pub(crate) async fn post<B: Serialize, R: DeserializeOwned>(
        &self,
        segments: &[&str],
        body: &B,
        mutation: &Mutation,
    ) -> Result<R> {
        let request = mutation
            .apply(self.route(Method::POST, segments)?)
            .json(body);
        self.send_json(request).await
    }

    pub(crate) async fn post_empty<B: Serialize>(
        &self,
        segments: &[&str],
        body: &B,
        mutation: &Mutation,
    ) -> Result<()> {
        let request = mutation
            .apply(self.route(Method::POST, segments)?)
            .json(body);
        self.send_empty(request).await
    }

    /// A POST whose route also takes an `If-Match` precondition.
    pub(crate) async fn post_versioned<B: Serialize, R: DeserializeOwned>(
        &self,
        segments: &[&str],
        version: i64,
        body: &B,
        mutation: &Mutation,
    ) -> Result<R> {
        let request = mutation
            .apply(self.route(Method::POST, segments)?)
            .header(reqwest::header::IF_MATCH, etag(version))
            .json(body);
        self.send_json(request).await
    }

    /// A partial update. The contract takes these as JSON merge-patch, where
    /// an explicit `null` clears a field and an absent one leaves it alone.
    pub(crate) async fn patch<B: Serialize, R: DeserializeOwned>(
        &self,
        segments: &[&str],
        version: i64,
        body: &B,
        mutation: &Mutation,
    ) -> Result<R> {
        let request = mutation
            .apply(self.route(Method::PATCH, segments)?)
            .header(reqwest::header::IF_MATCH, etag(version))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/merge-patch+json",
            )
            .body(serde_json::to_vec(body).map_err(|error| {
                Error::Invalid(format!("the patch could not be encoded: {error}"))
            })?);
        self.send_json(request).await
    }

    pub(crate) async fn put<B: Serialize, R: DeserializeOwned>(
        &self,
        segments: &[&str],
        version: i64,
        body: &B,
        mutation: &Mutation,
    ) -> Result<R> {
        let request = mutation
            .apply(self.route(Method::PUT, segments)?)
            .header(reqwest::header::IF_MATCH, etag(version))
            .json(body);
        self.send_json(request).await
    }

    /// A PUT whose `If-Match` is required only when a representation already
    /// exists, which is how the webhook routes are specified: the first
    /// configuration has nothing to match against.
    pub(crate) async fn put_optional_version<B: Serialize, R: DeserializeOwned>(
        &self,
        segments: &[&str],
        version: Option<i64>,
        body: &B,
        mutation: &Mutation,
    ) -> Result<R> {
        let mut request = mutation.apply(self.route(Method::PUT, segments)?);
        if let Some(version) = version {
            request = request.header(reqwest::header::IF_MATCH, etag(version));
        }
        self.send_json(request.json(body)).await
    }

    pub(crate) async fn delete_with(
        &self,
        segments: &[&str],
        version: Option<i64>,
        query: &[(&str, String)],
        mutation: &Mutation,
    ) -> Result<()> {
        let mut url = self.versioned_url(segments)?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in query {
                pairs.append_pair(name, value);
            }
        }
        let mut request = mutation.apply(self.prepare(Method::DELETE, url));
        if let Some(version) = version {
            request = request.header(reqwest::header::IF_MATCH, etag(version));
        }
        self.send_empty(request).await
    }

    pub(crate) async fn delete(
        &self,
        segments: &[&str],
        version: Option<i64>,
        mutation: &Mutation,
    ) -> Result<()> {
        let mut request = mutation.apply(self.route(Method::DELETE, segments)?);
        if let Some(version) = version {
            request = request.header(reqwest::header::IF_MATCH, etag(version));
        }
        self.send_empty(request).await
    }

    pub(crate) async fn send_json<R: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<R> {
        let body = self.send(request).await?;
        if body.is_empty() {
            return Err(Error::Decode(
                "the service returned an empty body where a value was expected".to_owned(),
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|error| Error::Decode(format!("unexpected response shape: {error}")))
    }

    pub(crate) async fn send_empty(&self, request: reqwest::RequestBuilder) -> Result<()> {
        self.send(request).await.map(|_| ())
    }

    /// Sends one request and turns anything other than success into an error.
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Vec<u8>> {
        let response = request.send().await.map_err(Error::Transport)?;
        let status = response.status();
        let retry_after = header_seconds(&response, "retry-after");
        let limit = header_u64(&response, "ratelimit-limit");
        let remaining = header_u64(&response, "ratelimit-remaining");
        let body = response.bytes().await.map_err(Error::Transport)?.to_vec();

        if status.is_success() {
            return Ok(body);
        }

        let api = decode_envelope(status, &body);
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(Error::RateLimited {
                // A 429 without Retry-After should not become a busy loop.
                retry_after: retry_after.unwrap_or(Duration::from_secs(1)),
                limit,
                remaining,
                source: Box::new(api),
            });
        }
        if status == StatusCode::NOT_ACCEPTABLE && api.code == "api_version_not_acceptable" {
            return Err(Error::ApiVersionUnsupported {
                offered: offered_versions(api.details.as_ref()),
            });
        }
        Err(Error::Api(Box::new(api)))
    }
}

impl ClientBuilder {
    /// Starts from a service base URL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] when the URL cannot be parsed or does not
    /// use an HTTP scheme.
    pub fn new(base_url: &str) -> Result<Self> {
        let mut base_url = Url::parse(base_url)
            .map_err(|error| Error::Invalid(format!("invalid base URL: {error}")))?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(Error::Invalid(
                "the base URL must be http or https".to_owned(),
            ));
        }
        // Every route is joined onto this, and `Url::join` discards the last
        // path segment unless the base ends in a slash.
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        Ok(Self {
            base_url,
            credential: Credential::Anonymous,
            environment: None,
            timeout: Duration::from_secs(30),
            user_agent: None,
        })
    }

    /// Sets the credential every request will present.
    #[must_use]
    pub fn credential(mut self, credential: Credential) -> Self {
        self.credential = credential;
        self
    }

    /// Runs every request inside a testing environment.
    #[must_use]
    pub fn environment(mut self, environment: EnvironmentKey) -> Self {
        self.environment = Some(environment);
        self
    }

    /// Overrides the per-request timeout. Defaults to 30 seconds.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Appends a caller identity to the `User-Agent`.
    ///
    /// Worth setting: it is what makes one integration distinguishable from
    /// another in the service's request logs.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] when the HTTP stack cannot be built, which
    /// in practice means the TLS backend failed to initialize.
    pub fn build(self) -> Result<Client> {
        let default_agent = concat!("silicon-iam-client/", env!("CARGO_PKG_VERSION"));
        let user_agent = match self.user_agent {
            Some(caller) => format!("{default_agent} {caller}"),
            None => default_agent.to_owned(),
        };
        let http = reqwest::Client::builder()
            .timeout(self.timeout)
            .user_agent(user_agent)
            .build()
            .map_err(Error::Transport)?;
        Ok(Client {
            http,
            base_url: self.base_url,
            credential: self.credential,
            environment: self.environment,
        })
    }
}

/// Recovers the service's envelope, falling back to the bare status.
///
/// Every documented failure carries the envelope, but a proxy or a crash can
/// still put something else on the wire, and a client that panicked or hid
/// that would be worse than one that reports the status it saw.
fn decode_envelope(status: StatusCode, body: &[u8]) -> ApiError {
    match serde_json::from_slice::<Envelope>(body) {
        Ok(envelope) => ApiError {
            status: status.as_u16(),
            code: envelope.error.code,
            message: envelope.error.message,
            details: envelope.error.details,
            request_id: envelope.error.request_id,
        },
        Err(_) => ApiError {
            status: status.as_u16(),
            code: "unrecognized_error".to_owned(),
            message: status
                .canonical_reason()
                .unwrap_or("the service reported a failure")
                .to_owned(),
            details: None,
            request_id: None,
        },
    }
}

fn offered_versions(details: Option<&serde_json::Value>) -> Vec<String> {
    details
        .and_then(|details| details.get("supported_versions"))
        .and_then(serde_json::Value::as_array)
        .map(|versions| {
            versions
                .iter()
                .filter_map(|version| version.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The strong entity tag form the contract expects in `If-Match`.
fn etag(version: i64) -> String {
    format!("\"{version}\"")
}

fn header_u64(response: &reqwest::Response, name: &str) -> Option<u64> {
    response
        .headers()
        .get(name)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn header_seconds(response: &reqwest::Response, name: &str) -> Option<Duration> {
    header_u64(response, name).map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;

    use crate::{Credential, EnvironmentKey};

    use super::{Client, decode_envelope, offered_versions};

    #[test]
    fn a_base_url_without_a_trailing_slash_still_joins_correctly() {
        let Ok(client) = Client::new("https://backend.iam.teamofsilicons.com") else {
            panic!("a plain https URL must be accepted");
        };
        let Ok(request) = client.route(reqwest::Method::GET, &["me"]) else {
            panic!("the route must join onto the base");
        };
        let Ok(built) = request.build() else {
            panic!("the request must build");
        };
        assert_eq!(
            built.url().as_str(),
            "https://backend.iam.teamofsilicons.com/api/v1/me"
        );
    }

    #[test]
    fn a_base_url_with_a_path_prefix_keeps_it() {
        let Ok(client) = Client::new("https://example.test/iam") else {
            panic!("a prefixed URL must be accepted");
        };
        let Ok(request) = client.route(reqwest::Method::GET, &["me"]) else {
            panic!("the route must join onto the base");
        };
        let Ok(built) = request.build() else {
            panic!("the request must build");
        };
        assert_eq!(built.url().as_str(), "https://example.test/iam/api/v1/me");
    }

    #[test]
    fn a_path_parameter_cannot_change_which_route_is_called() {
        let Ok(client) = Client::new("https://example.test") else {
            panic!("a plain https URL must be accepted");
        };
        let Ok(request) = client.route(
            reqwest::Method::GET,
            &["organizations", "../../admin/applications", "tags"],
        ) else {
            panic!("the route must build");
        };
        let Ok(built) = request.build() else {
            panic!("the request must build");
        };
        // The hostile segment is escaped into one segment rather than walking
        // up the path.
        assert!(!built.url().path().contains("/admin/"), "{}", built.url());
        assert!(built.url().path().starts_with("/api/v1/organizations/"));
    }

    #[test]
    fn a_non_http_base_url_is_refused() {
        assert!(Client::new("ftp://example.test").is_err());
        assert!(Client::new("not a url").is_err());
    }

    #[test]
    fn test_selection_and_application_auth_are_independent_headers() {
        let Ok(environment) = EnvironmentKey::new("a".repeat(32)) else {
            panic!("the fixed-size test key must be accepted");
        };
        let Ok(client) = Client::builder("https://example.test").and_then(|builder| {
            builder
                .credential(Credential::application("acme>caller", "ask_secret"))
                .environment(environment)
                .build()
        }) else {
            panic!("a valid client must build");
        };
        let Ok(request) = client.route(
            reqwest::Method::GET,
            &["application-directory", "other>target"],
        ) else {
            panic!("the discovery request must build");
        };
        let Ok(built) = request.build() else {
            panic!("the request must finalize");
        };

        assert_eq!(
            built
                .headers()
                .get("x-testing-environment-key")
                .and_then(|value| value.to_str().ok()),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert!(
            built
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("Basic "))
        );
        assert_eq!(
            built.url().as_str(),
            "https://example.test/api/v1/application-directory/other%3Etarget"
        );
    }

    #[test]
    fn an_unparsable_error_body_still_reports_the_status() {
        let error = decode_envelope(StatusCode::BAD_GATEWAY, b"<html>upstream died</html>");
        assert_eq!(error.status, 502);
        assert_eq!(error.code, "unrecognized_error");
        assert!(error.is_retryable());
    }

    #[test]
    fn the_envelope_is_preferred_when_present() {
        let body = br#"{"error":{"code":"etag_mismatch","message":"stale","request_id":"r1"}}"#;
        let error = decode_envelope(StatusCode::PRECONDITION_FAILED, body);
        assert!(error.is_version_conflict());
        assert_eq!(error.request_id.as_deref(), Some("r1"));
    }

    #[test]
    fn offered_versions_survive_a_missing_or_odd_detail_shape() {
        assert!(offered_versions(None).is_empty());
        assert!(offered_versions(Some(&serde_json::json!({}))).is_empty());
        assert_eq!(
            offered_versions(Some(&serde_json::json!({"supported_versions":["v2","v3"]}))),
            vec!["v2".to_owned(), "v3".to_owned()]
        );
    }
}
