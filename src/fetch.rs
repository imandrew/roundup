use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use url::Url;

use tracing::{info, warn};

use crate::config::Server;
use crate::rancher::{ApiToken, Cluster, RancherClient};

const MAX_CONCURRENT_DOWNLOADS: usize = 5;

pub struct DiscoveredServer {
    pub server: Server,
    pub token: ApiToken,
    pub clusters: Vec<Cluster>,
}

pub struct FetchedKubeconfig {
    pub server: Server,
    pub yaml: String,
}

/// Discovers clusters from all servers concurrently.
/// Returns per-server results so callers can report progress.
/// Tolerates partial failures — logs warnings and returns whatever succeeded.
pub async fn discover_clusters(
    client: &RancherClient,
    servers: &[Server],
    tokens: &HashMap<Url, ApiToken>,
) -> Vec<DiscoveredServer> {
    let mut discovery = JoinSet::new();
    for server in servers {
        let Some(token) = tokens.get(server.url()) else {
            warn!(server = %server.api_base(), "no token, skipping");
            continue;
        };
        let client = client.clone();
        let server = server.clone();
        let token = token.clone();
        discovery.spawn(async move {
            let clusters = client.list_clusters(&server, &token).await?;
            Ok::<_, crate::rancher::RancherError>((server, token, clusters))
        });
    }

    let mut results = Vec::new();
    while let Some(result) = discovery.join_next().await {
        match result {
            Ok(Ok((server, token, clusters))) => {
                info!(server = %server.api_base(), clusters = clusters.len(), "discovered clusters");
                results.push(DiscoveredServer {
                    server,
                    token,
                    clusters,
                });
            }
            Ok(Err(e)) => warn!(error = %e, "server discovery failed"),
            Err(e) => warn!(error = %e, "discovery task panicked"),
        }
    }

    results
}

/// Downloads kubeconfigs for the given cluster tasks concurrently.
/// Calls `on_progress(completed, total)` after each download attempt (success or failure).
pub async fn download_kubeconfigs(
    client: &RancherClient,
    tasks: Vec<(Server, ApiToken, Cluster)>,
    mut on_progress: impl FnMut(usize, usize),
) -> Vec<FetchedKubeconfig> {
    let total = tasks.len();
    if total == 0 {
        return Vec::new();
    }

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS));
    let mut downloads = JoinSet::new();
    for (server, token, cluster) in tasks {
        let client = client.clone();
        let permit = Arc::clone(&semaphore);
        downloads.spawn(async move {
            let _permit = permit.acquire_owned().await.expect("semaphore closed");
            let yaml = client.get_kubeconfig(&server, &token, &cluster.id).await?;
            Ok::<_, crate::rancher::RancherError>(FetchedKubeconfig { server, yaml })
        });
    }

    let mut results = Vec::new();
    let mut completed = 0;
    while let Some(result) = downloads.join_next().await {
        completed += 1;
        match result {
            Ok(Ok(kc)) => results.push(kc),
            Ok(Err(e)) => warn!(error = %e, "kubeconfig download failed"),
            Err(e) => warn!(error = %e, "download task panicked"),
        }
        on_progress(completed, total);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthType;
    use crate::rancher::test_helpers::*;
    use serde_json::json;
    use std::time::{Duration, Instant};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn token_for(server: &Server, value: &str) -> HashMap<Url, ApiToken> {
        HashMap::from([(
            server.url().clone(),
            ApiToken::new(value.into(), Instant::now() + Duration::from_secs(3600)),
        )])
    }

    async fn setup_mock_server() -> (MockServer, Server) {
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

        let kc_yaml = "apiVersion: v1\nclusters: []\ncontexts: []\nusers: []\n";
        Mock::given(method("POST"))
            .and(path("/v3/clusters/c-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "config": kc_yaml
            })))
            .mount(&mock)
            .await;

        Mock::given(method("POST"))
            .and(path("/v3/clusters/c-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "config": kc_yaml
            })))
            .mount(&mock)
            .await;

        let server = test_server(&mock.uri());
        (mock, server)
    }

    #[tokio::test]
    async fn discovers_clusters_from_server() {
        let (_mock, server) = setup_mock_server().await;
        let client = test_client();
        let tokens = token_for(&server, "test-token");

        let results = discover_clusters(&client, &[server], &tokens).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].clusters.len(), 2);
    }

    #[tokio::test]
    async fn downloads_kubeconfigs_with_progress() {
        let (_mock, server) = setup_mock_server().await;
        let client = test_client();
        let tokens = token_for(&server, "test-token");

        let discovered = discover_clusters(&client, &[server], &tokens).await;
        let tasks: Vec<_> = discovered
            .into_iter()
            .flat_map(|d| {
                d.clusters
                    .into_iter()
                    .map(move |c| (d.server.clone(), d.token.clone(), c))
            })
            .collect();

        let mut progress_calls = Vec::new();
        let results = download_kubeconfigs(&client, tasks, |completed, total| {
            progress_calls.push((completed, total));
        })
        .await;

        assert_eq!(results.len(), 2);
        assert_eq!(progress_calls.len(), 2);
        assert_eq!(progress_calls.last(), Some(&(2, 2)));
    }

    #[tokio::test]
    async fn skips_server_without_token() {
        let client = test_client();
        let server = Server::new(
            "https://no-token.example.com",
            "admin".into(),
            AuthType::Local,
        )
        .unwrap();
        let tokens = HashMap::new();

        let results = discover_clusters(&client, &[server], &tokens).await;

        assert!(results.is_empty());
    }
}
