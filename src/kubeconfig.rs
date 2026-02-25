use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::Server;
use crate::fetch::FetchedKubeconfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kubeconfig {
    #[serde(default, rename = "apiVersion")]
    pub api_version: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub clusters: Vec<NamedCluster>,
    #[serde(default)]
    pub contexts: Vec<NamedContext>,
    #[serde(default)]
    pub users: Vec<NamedUser>,
    #[serde(default, rename = "current-context")]
    pub current_context: Option<String>,
}

impl Default for Kubeconfig {
    fn default() -> Self {
        Self {
            api_version: Some("v1".into()),
            kind: Some("Config".into()),
            clusters: Vec::new(),
            contexts: Vec::new(),
            users: Vec::new(),
            current_context: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedCluster {
    pub name: String,
    #[serde(default)]
    pub cluster: Option<yaml_serde::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedContext {
    pub name: String,
    pub context: ContextFields,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextFields {
    pub cluster: String,
    pub user: String,
    #[serde(flatten)]
    pub extra: HashMap<String, yaml_serde::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedUser {
    pub name: String,
    #[serde(default)]
    pub user: Option<yaml_serde::Value>,
}

pub struct ExcludeFilter {
    patterns: Vec<Regex>,
}

impl ExcludeFilter {
    pub fn new(patterns: &[String]) -> Result<Self> {
        let compiled = patterns
            .iter()
            .map(|p| Regex::new(p).with_context(|| format!("invalid regex pattern: {p}")))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { patterns: compiled })
    }

    pub fn should_exclude(&self, name: &str) -> bool {
        self.patterns.iter().any(|re| re.is_match(name))
    }
}

/// Names that appear in more than one server's kubeconfig need disambiguation.
fn detect_conflicts(configs: &[(Server, Kubeconfig)]) -> HashSet<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (_, kc) in configs {
        let names: HashSet<&str> = kc
            .contexts
            .iter()
            .map(|c| c.name.as_str())
            .chain(kc.clusters.iter().map(|c| c.name.as_str()))
            .chain(kc.users.iter().map(|u| u.name.as_str()))
            .collect();
        for name in names {
            *seen.entry(name.to_owned()).or_default() += 1;
        }
    }
    seen.into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(name, _)| name)
        .collect()
}

fn maybe_rename(name: &str, suffix: &str, conflicts: &HashSet<String>) -> String {
    if conflicts.contains(name) {
        format!("{name}-{suffix}")
    } else {
        name.to_owned()
    }
}

fn build_rename_map(
    names: impl Iterator<Item = String>,
    suffix: &str,
    conflicts: &HashSet<String>,
) -> HashMap<String, String> {
    names
        .map(|name| {
            let renamed = maybe_rename(&name, suffix, conflicts);
            (name, renamed)
        })
        .collect()
}

fn namespace_kubeconfig(
    mut config: Kubeconfig,
    server: &Server,
    conflicts: &HashSet<String>,
) -> Kubeconfig {
    let suffix = server.host_slug();

    let cluster_map = build_rename_map(
        config.clusters.iter().map(|c| c.name.clone()),
        &suffix,
        conflicts,
    );
    let user_map = build_rename_map(
        config.users.iter().map(|u| u.name.clone()),
        &suffix,
        conflicts,
    );

    for cluster in &mut config.clusters {
        cluster.name = cluster_map[&cluster.name].clone();
    }

    for user in &mut config.users {
        user.name = user_map[&user.name].clone();
    }

    for ctx in &mut config.contexts {
        ctx.name = maybe_rename(&ctx.name, &suffix, conflicts);
        if let Some(new) = cluster_map.get(&ctx.context.cluster) {
            ctx.context.cluster = new.clone();
        }
        if let Some(new) = user_map.get(&ctx.context.user) {
            ctx.context.user = new.clone();
        }
    }

    config
}

fn filter_kubeconfig(mut config: Kubeconfig, filter: &ExcludeFilter) -> Option<Kubeconfig> {
    config.contexts.retain(|ctx| {
        !filter.should_exclude(&ctx.name) && !filter.should_exclude(&ctx.context.cluster)
    });

    if config.contexts.is_empty() {
        return None;
    }

    let used_clusters: HashSet<&str> = config
        .contexts
        .iter()
        .map(|c| c.context.cluster.as_str())
        .collect();
    let used_users: HashSet<&str> = config
        .contexts
        .iter()
        .map(|c| c.context.user.as_str())
        .collect();

    config
        .clusters
        .retain(|c| used_clusters.contains(c.name.as_str()));
    config
        .users
        .retain(|u| used_users.contains(u.name.as_str()));

    Some(config)
}

pub fn merge_kubeconfigs(
    raw_configs: Vec<FetchedKubeconfig>,
    filter: Option<&ExcludeFilter>,
    output: &Path,
) -> Result<()> {
    if raw_configs.is_empty() {
        bail!("no kubeconfigs to merge");
    }

    // Parse YAML
    let configs: Vec<(Server, Kubeconfig)> = raw_configs
        .into_iter()
        .filter_map(|kc| match yaml_serde::from_str(&kc.yaml) {
            Ok(parsed) => Some((kc.server, parsed)),
            Err(e) => {
                warn!(server = %kc.server.api_base(), error = %e, "failed to parse kubeconfig");
                None
            }
        })
        .collect();

    if configs.is_empty() {
        bail!("no valid kubeconfigs to merge");
    }

    // Detect conflicts across servers
    let conflicts = detect_conflicts(&configs);

    // Namespace -> filter -> merge
    let merged = configs
        .into_iter()
        .map(|(server, kc)| namespace_kubeconfig(kc, &server, &conflicts))
        .filter_map(|kc| match filter {
            Some(f) => filter_kubeconfig(kc, f),
            None => Some(kc),
        })
        .fold(Kubeconfig::default(), |mut dest, src| {
            dest.clusters.extend(src.clusters);
            dest.contexts.extend(src.contexts);
            dest.users.extend(src.users);
            dest
        });

    if merged.contexts.is_empty() {
        bail!("no clusters remain after filtering");
    }

    let contents = yaml_serde::to_string(&merged).context("failed to serialize kubeconfig")?;
    crate::config::write_secure(output, &contents, 0o700, 0o600)
        .context("failed to write kubeconfig")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthType;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn make_server(url: &str) -> Server {
        Server::new(url, "admin".into(), AuthType::Local).unwrap()
    }

    fn make_kubeconfig(names: &[&str]) -> Kubeconfig {
        Kubeconfig {
            clusters: names
                .iter()
                .map(|n| NamedCluster {
                    name: n.to_string(),
                    cluster: Some(yaml_serde::Value::Mapping(yaml_serde::Mapping::from_iter(
                        [(
                            yaml_serde::Value::String("server".into()),
                            yaml_serde::Value::String(format!("https://{n}.example.com")),
                        )],
                    ))),
                })
                .collect(),
            contexts: names
                .iter()
                .map(|n| NamedContext {
                    name: n.to_string(),
                    context: ContextFields {
                        cluster: n.to_string(),
                        user: n.to_string(),
                        extra: HashMap::new(),
                    },
                })
                .collect(),
            users: names
                .iter()
                .map(|n| NamedUser {
                    name: n.to_string(),
                    user: None,
                })
                .collect(),
            ..Kubeconfig::default()
        }
    }

    fn make_fetched(server: Server, kc: &Kubeconfig) -> FetchedKubeconfig {
        FetchedKubeconfig {
            server,
            yaml: yaml_serde::to_string(kc).unwrap(),
        }
    }

    fn context_names(kc: &Kubeconfig) -> HashSet<String> {
        kc.contexts.iter().map(|c| c.name.clone()).collect()
    }

    #[test]
    fn no_conflicts_names_unchanged() {
        let configs = vec![
            (
                make_server("https://prod.example.com"),
                make_kubeconfig(&["app-prod"]),
            ),
            (
                make_server("https://staging.example.com"),
                make_kubeconfig(&["app-staging"]),
            ),
        ];
        let conflicts = detect_conflicts(&configs);
        assert!(!conflicts.contains("app-prod"));
        assert!(!conflicts.contains("app-staging"));
    }

    #[test]
    fn local_cluster_conflicts_detected() {
        let configs = vec![
            (
                make_server("https://prod.example.com"),
                make_kubeconfig(&["local", "app-prod"]),
            ),
            (
                make_server("https://staging.example.com"),
                make_kubeconfig(&["local", "app-staging"]),
            ),
        ];
        let conflicts = detect_conflicts(&configs);
        assert!(conflicts.contains("local"));
        assert!(!conflicts.contains("app-prod"));
        assert!(!conflicts.contains("app-staging"));
    }

    #[test]
    fn only_conflicting_names_get_renamed() {
        let server = make_server("https://prod.example.com");
        let kc = make_kubeconfig(&["local", "unique-app"]);

        let conflicts = HashSet::from(["local".to_owned()]);

        let result = namespace_kubeconfig(kc, &server, &conflicts);
        let names = context_names(&result);

        assert!(names.contains("local-prod-example-com"));
        assert!(names.contains("unique-app"));
        assert!(!names.contains("local"));
    }

    #[test]
    fn cross_references_updated_on_rename() {
        let server = make_server("https://prod.example.com");
        let kc = make_kubeconfig(&["local"]);

        let conflicts = HashSet::from(["local".to_owned()]);

        let result = namespace_kubeconfig(kc, &server, &conflicts);

        let ctx = &result.contexts[0];
        assert_eq!(ctx.context.cluster, result.clusters[0].name);
        assert_eq!(ctx.context.user, result.users[0].name);
    }

    #[test]
    fn filter_removes_matching_contexts() {
        let kc = make_kubeconfig(&["keep-me", "test-cluster", "also-keep"]);
        let filter = ExcludeFilter::new(&["^test-".to_owned()]).unwrap();

        let result = filter_kubeconfig(kc, &filter).unwrap();

        let names = context_names(&result);
        assert_eq!(names.len(), 2);
        assert!(names.contains("keep-me"));
        assert!(names.contains("also-keep"));
        assert_eq!(result.clusters.len(), 2);
        assert_eq!(result.users.len(), 2);
    }

    #[test]
    fn filter_all_returns_none() {
        let kc = make_kubeconfig(&["test-a", "test-b"]);
        let filter = ExcludeFilter::new(&["^test-".to_owned()]).unwrap();
        assert!(filter_kubeconfig(kc, &filter).is_none());
    }

    #[test]
    fn filter_matches_cluster_name_too() {
        let kc = make_kubeconfig(&["my-context"]);
        // The cluster name equals the context name in our helper
        let filter = ExcludeFilter::new(&["my-context".to_owned()]).unwrap();
        assert!(filter_kubeconfig(kc, &filter).is_none());
    }

    #[test]
    fn merge_renames_only_conflicts() {
        let tmp = TempDir::new().unwrap();
        let output = tmp.path().join("config");

        let raw = vec![
            make_fetched(
                make_server("https://prod.example.com"),
                &make_kubeconfig(&["local", "app-prod"]),
            ),
            make_fetched(
                make_server("https://staging.example.com"),
                &make_kubeconfig(&["local", "app-staging"]),
            ),
        ];

        merge_kubeconfigs(raw, None, &output).unwrap();

        let merged: Kubeconfig =
            yaml_serde::from_str(&fs::read_to_string(&output).unwrap()).unwrap();

        let names = context_names(&merged);
        assert_eq!(names.len(), 4);
        assert!(names.contains("app-prod"));
        assert!(names.contains("app-staging"));
        assert!(names.contains("local-prod-example-com"));
        assert!(names.contains("local-staging-example-com"));
    }

    #[test]
    fn merge_with_filter() {
        let tmp = TempDir::new().unwrap();
        let output = tmp.path().join("config");

        let raw = vec![
            make_fetched(
                make_server("https://prod.example.com"),
                &make_kubeconfig(&["local", "app-prod"]),
            ),
            make_fetched(
                make_server("https://staging.example.com"),
                &make_kubeconfig(&["local", "app-staging"]),
            ),
        ];

        let filter = ExcludeFilter::new(&["local".to_owned()]).unwrap();
        merge_kubeconfigs(raw, Some(&filter), &output).unwrap();

        let merged: Kubeconfig =
            yaml_serde::from_str(&fs::read_to_string(&output).unwrap()).unwrap();

        let names = context_names(&merged);
        assert_eq!(names.len(), 2);
        assert!(names.contains("app-prod"));
        assert!(names.contains("app-staging"));
    }

    #[test]
    fn merge_sets_secure_permissions() {
        let tmp = TempDir::new().unwrap();
        let kube_dir = tmp.path().join(".kube");
        let output = kube_dir.join("config");

        let raw = vec![make_fetched(
            make_server("https://prod.example.com"),
            &make_kubeconfig(&["app"]),
        )];

        merge_kubeconfigs(raw, None, &output).unwrap();

        let dir_perms = fs::metadata(&kube_dir).unwrap().permissions();
        assert_eq!(dir_perms.mode() & 0o777, 0o700);

        let file_perms = fs::metadata(&output).unwrap().permissions();
        assert_eq!(file_perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn merge_empty_input_fails() {
        let tmp = TempDir::new().unwrap();
        let output = tmp.path().join("config");
        assert!(merge_kubeconfigs(vec![], None, &output).is_err());
    }

    #[test]
    fn kubeconfig_yaml_roundtrip() {
        let kc = make_kubeconfig(&["my-cluster"]);
        let yaml = yaml_serde::to_string(&kc).unwrap();
        let parsed: Kubeconfig = yaml_serde::from_str(&yaml).unwrap();

        assert_eq!(parsed.contexts.len(), 1);
        assert_eq!(parsed.contexts[0].name, "my-cluster");
        assert_eq!(parsed.contexts[0].context.cluster, "my-cluster");
        assert_eq!(parsed.contexts[0].context.user, "my-cluster");
    }
}
