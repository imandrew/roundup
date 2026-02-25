use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tracing::debug;

use crate::config::{CachedToken, Password, Server};

#[derive(Debug, thiserror::Error)]
pub enum RancherError {
    #[error("request to {url} failed")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("{url} returned status {status}: {body}")]
    Api {
        url: String,
        status: u16,
        /// Truncated to avoid leaking internal server details.
        body: String,
    },

    #[error("no token in authentication response for {url}")]
    NoToken { url: String },

    #[error("empty kubeconfig for cluster {cluster_id}")]
    EmptyKubeconfig { cluster_id: String },
}

#[derive(Clone)]
pub struct AuthToken {
    value: String,
    expires_at: Instant,
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthToken(***)")
    }
}

impl AuthToken {
    #[cfg(test)]
    pub fn new(value: String, expires_at: Instant) -> Self {
        Self { value, expires_at }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    #[allow(dead_code)] // part of the API; used in tests
    pub fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }

    /// Extract the token name/ID (the part before the colon).
    /// Rancher tokens have the format "token-xxxxx:secretvalue".
    pub fn token_id(&self) -> Option<&str> {
        self.value.split_once(':').map(|(id, _)| id)
    }

    pub fn to_cached(&self) -> CachedToken {
        let remaining = self.expires_at.saturating_duration_since(Instant::now());
        let epoch_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            + remaining.as_secs() as i64;
        CachedToken::new(self.value.clone(), epoch_secs)
    }

    pub fn from_cached(cached: &CachedToken) -> Self {
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let remaining_secs = (cached.expires_at() - now_epoch).max(0) as u64;
        Self {
            value: cached.value().to_owned(),
            expires_at: Instant::now() + Duration::from_secs(remaining_secs),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Cluster {
    pub id: String,
    #[allow(dead_code)] // deserialized from API; used in tests
    pub name: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    token: Option<String>,
    ttl: i64,
}

#[derive(Deserialize)]
struct ClusterResponse {
    data: Vec<ClusterData>,
}

#[derive(Deserialize)]
struct ClusterData {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct KubeconfigResponse {
    config: Option<String>,
}

/// Maximum error body length to include in error messages.
const MAX_ERROR_BODY_LEN: usize = 512;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_RATE_PER_SEC: u32 = 10;
const DEFAULT_RATE_BURST: u32 = 20;
/// Rancher's typical default session TTL.
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(16 * 60 * 60);

#[derive(Clone)]
pub struct RancherClient {
    client: reqwest::Client,
    limiter: Arc<DefaultDirectRateLimiter>,
    max_retries: u32,
}

impl RancherClient {
    #[must_use]
    pub fn builder() -> RancherClientBuilder {
        RancherClientBuilder::default()
    }

    pub async fn authenticate(
        &self,
        server: &Server,
        password: &Password,
    ) -> Result<AuthToken, RancherError> {
        let url = format!(
            "{}/v3-public/{}?action=login",
            server.api_base(),
            server.auth_type.provider_path(),
        );

        let payload = HashMap::from([
            ("username", server.username.as_str()),
            ("password", password.expose()),
            ("responseType", "token"),
        ]);

        let auth: AuthResponse = self
            .send_and_parse(|| self.client.post(&url).json(&payload).send(), url.clone())
            .await?;

        let token_value = auth.token.ok_or_else(|| RancherError::NoToken { url })?;

        // Cap TTL to 30 days to prevent overflow from extreme server values.
        const MAX_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;
        let expires_at = if auth.ttl > 0 {
            let ttl_ms = auth.ttl.min(MAX_TTL_MS) as u64;
            Instant::now() + Duration::from_millis(ttl_ms)
        } else {
            Instant::now() + DEFAULT_TOKEN_TTL
        };

        Ok(AuthToken {
            value: token_value,
            expires_at,
        })
    }

    pub async fn list_clusters(
        &self,
        server: &Server,
        token: &AuthToken,
    ) -> Result<Vec<Cluster>, RancherError> {
        let url = format!("{}/v3/clusters", server.api_base());

        let clusters_resp: ClusterResponse = self
            .send_and_parse(
                || self.client.get(&url).bearer_auth(token.value()).send(),
                url.clone(),
            )
            .await?;

        Ok(clusters_resp
            .data
            .into_iter()
            .filter(|c| !c.id.is_empty() && !c.name.is_empty())
            .map(|c| Cluster {
                id: c.id,
                name: c.name,
            })
            .collect())
    }

    /// Delete a token from the Rancher server. Best-effort — errors are returned
    /// but callers may choose to ignore them.
    pub async fn delete_token(
        &self,
        server: &Server,
        token: &AuthToken,
    ) -> Result<(), RancherError> {
        let Some(token_id) = token.token_id() else {
            return Ok(());
        };
        let url = format!("{}/v3/tokens/{}", server.api_base(), token_id);

        let resp = self
            .send_with_retry(|| self.client.delete(&url).bearer_auth(token.value()).send())
            .await
            .map_err(|source| RancherError::Http {
                url: url.clone(),
                source,
            })?;

        Self::check_response(resp, &url).await?;
        Ok(())
    }

    pub async fn get_kubeconfig(
        &self,
        server: &Server,
        token: &AuthToken,
        cluster_id: &str,
    ) -> Result<String, RancherError> {
        if !cluster_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(RancherError::Api {
                url: server.api_base().to_owned(),
                status: 0,
                body: format!("invalid cluster ID: {cluster_id}"),
            });
        }

        let url = format!(
            "{}/v3/clusters/{}?action=generateKubeconfig",
            server.api_base(),
            cluster_id,
        );

        let kc_resp: KubeconfigResponse = self
            .send_and_parse(
                || self.client.post(&url).bearer_auth(token.value()).send(),
                url.clone(),
            )
            .await?;

        kc_resp
            .config
            .filter(|s| !s.is_empty())
            .ok_or_else(|| RancherError::EmptyKubeconfig {
                cluster_id: cluster_id.to_owned(),
            })
    }

    async fn check_response(
        resp: reqwest::Response,
        url: &str,
    ) -> Result<reqwest::Response, RancherError> {
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = truncate_body(&resp.text().await.unwrap_or_default());
            return Err(RancherError::Api {
                url: url.to_owned(),
                status,
                body,
            });
        }
        Ok(resp)
    }

    async fn send_and_parse<T, F, Fut>(&self, request_fn: F, url: String) -> Result<T, RancherError>
    where
        T: DeserializeOwned,
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
    {
        let resp = self
            .send_with_retry(request_fn)
            .await
            .map_err(|source| RancherError::Http {
                url: url.clone(),
                source,
            })?;

        let resp = Self::check_response(resp, &url).await?;

        resp.json()
            .await
            .map_err(|source| RancherError::Http { url, source })
    }

    async fn send_with_retry<F, Fut>(&self, f: F) -> Result<reqwest::Response, reqwest::Error>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
    {
        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            self.limiter.until_ready().await;
            match f().await {
                Ok(resp) => return Ok(resp),
                Err(e) if attempt < self.max_retries && (e.is_timeout() || e.is_connect()) => {
                    debug!(attempt, error = %e, "retrying request");
                    last_err = Some(e);
                    let backoff = 100u64.checked_shl(attempt).unwrap_or(30_000).min(30_000);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap())
    }
}

#[derive(Default)]
pub struct RancherClientBuilder {
    insecure: bool,
}

impl RancherClientBuilder {
    #[must_use]
    pub fn insecure(mut self, yes: bool) -> Self {
        self.insecure = yes;
        self
    }

    pub fn build(self) -> Result<RancherClient, reqwest::Error> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.insecure)
            .timeout(DEFAULT_TIMEOUT)
            .build()?;

        let quota = Quota::per_second(NonZeroU32::new(DEFAULT_RATE_PER_SEC).expect("rate > 0"))
            .allow_burst(NonZeroU32::new(DEFAULT_RATE_BURST).expect("burst > 0"));
        let limiter = Arc::new(RateLimiter::direct(quota));

        Ok(RancherClient {
            client,
            limiter,
            max_retries: DEFAULT_MAX_RETRIES,
        })
    }
}

fn truncate_body(body: &str) -> String {
    if body.len() <= MAX_ERROR_BODY_LEN {
        body.to_owned()
    } else {
        let truncated: String = body.chars().take(MAX_ERROR_BODY_LEN).collect();
        format!("{truncated}... (truncated)")
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use crate::config::AuthType;

    pub fn test_client() -> RancherClient {
        RancherClient::builder().build().unwrap()
    }

    pub fn test_server(uri: &str) -> Server {
        Server::new_insecure(uri, "admin".into(), AuthType::Local).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn authenticate_success() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v3-public/localProviders/local"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": "kubeconfig-user:abc123",
                "ttl": 3600000
            })))
            .mount(&mock)
            .await;

        let client = test_client();
        let server = test_server(&mock.uri());
        let token = client
            .authenticate(&server, &Password::new("pass"))
            .await
            .unwrap();

        assert_eq!(token.value(), "kubeconfig-user:abc123");
        assert!(token.is_valid());
    }

    #[tokio::test]
    async fn authenticate_bad_credentials() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v3-public/localProviders/local"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&mock)
            .await;

        let client = test_client();
        let server = test_server(&mock.uri());
        let err = client
            .authenticate(&server, &Password::new("wrong"))
            .await
            .unwrap_err();

        assert!(matches!(err, RancherError::Api { status: 401, .. }))
    }

    #[tokio::test]
    async fn authenticate_missing_token() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v3-public/localProviders/local"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ttl": 3600000
            })))
            .mount(&mock)
            .await;

        let client = test_client();
        let server = test_server(&mock.uri());
        let err = client
            .authenticate(&server, &Password::new("pass"))
            .await
            .unwrap_err();

        assert!(matches!(err, RancherError::NoToken { .. }));
    }

    #[tokio::test]
    async fn list_clusters_success() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v3/clusters"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [
                    {"id": "c-1", "name": "production"},
                    {"id": "c-2", "name": "staging"}
                ]
            })))
            .mount(&mock)
            .await;

        let client = test_client();
        let server = test_server(&mock.uri());
        let token = AuthToken::new(
            "test-token".into(),
            Instant::now() + Duration::from_secs(3600),
        );

        let clusters = client.list_clusters(&server, &token).await.unwrap();

        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0].name, "production");
        assert_eq!(clusters[1].name, "staging");
    }

    #[tokio::test]
    async fn list_clusters_skips_empty_names() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v3/clusters"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [
                    {"id": "c-1", "name": "valid"},
                    {"id": "", "name": "no-id"},
                    {"id": "c-3", "name": ""}
                ]
            })))
            .mount(&mock)
            .await;

        let client = test_client();
        let server = test_server(&mock.uri());
        let token = AuthToken::new(
            "test-token".into(),
            Instant::now() + Duration::from_secs(3600),
        );

        let clusters = client.list_clusters(&server, &token).await.unwrap();

        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].name, "valid");
    }

    #[tokio::test]
    async fn get_kubeconfig_success() {
        let mock = MockServer::start().await;
        let yaml = "apiVersion: v1\nclusters: []\ncontexts: []\nusers: []\n";

        Mock::given(method("POST"))
            .and(path("/v3/clusters/c-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "config": yaml
            })))
            .mount(&mock)
            .await;

        let client = test_client();
        let server = test_server(&mock.uri());
        let token = AuthToken::new(
            "test-token".into(),
            Instant::now() + Duration::from_secs(3600),
        );

        let config = client.get_kubeconfig(&server, &token, "c-1").await.unwrap();

        assert!(config.contains("apiVersion"));
    }

    #[tokio::test]
    async fn get_kubeconfig_empty() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v3/clusters/c-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "config": ""
            })))
            .mount(&mock)
            .await;

        let client = test_client();
        let server = test_server(&mock.uri());
        let token = AuthToken::new(
            "test-token".into(),
            Instant::now() + Duration::from_secs(3600),
        );

        let err = client
            .get_kubeconfig(&server, &token, "c-1")
            .await
            .unwrap_err();

        assert!(matches!(err, RancherError::EmptyKubeconfig { .. }));
    }

    #[test]
    fn token_id_extracts_name() {
        let token = AuthToken::new(
            "token-abc123:secretvalue".into(),
            Instant::now() + Duration::from_secs(3600),
        );
        assert_eq!(token.token_id(), Some("token-abc123"));
    }

    #[test]
    fn token_id_none_without_colon() {
        let token = AuthToken::new(
            "no-colon-token".into(),
            Instant::now() + Duration::from_secs(3600),
        );
        assert_eq!(token.token_id(), None);
    }

    #[tokio::test]
    async fn delete_token_success() {
        let mock = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/v3/tokens/token-abc123"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock)
            .await;

        let client = test_client();
        let server = test_server(&mock.uri());
        let token = AuthToken::new(
            "token-abc123:secretvalue".into(),
            Instant::now() + Duration::from_secs(3600),
        );

        client.delete_token(&server, &token).await.unwrap();
    }

    #[tokio::test]
    async fn delete_token_not_found() {
        let mock = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/v3/tokens/token-gone"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&mock)
            .await;

        let client = test_client();
        let server = test_server(&mock.uri());
        let token = AuthToken::new(
            "token-gone:secretvalue".into(),
            Instant::now() + Duration::from_secs(3600),
        );

        let err = client.delete_token(&server, &token).await.unwrap_err();
        assert!(matches!(err, RancherError::Api { status: 404, .. }));
    }
}
