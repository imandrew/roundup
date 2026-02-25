use std::fmt;
use std::fs::{self, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Password(Zeroizing<String>);

impl Password {
    pub fn new(s: impl Into<String>) -> Self {
        Self(Zeroizing::new(s.into()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(***)")
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CachedToken {
    value: String,
    #[serde(rename = "expiresAt")]
    expires_at: i64,
}

impl CachedToken {
    pub fn new(value: String, expires_at: i64) -> Self {
        Self { value, expires_at }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    fn now_epoch() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    pub fn is_valid(&self) -> bool {
        Self::now_epoch() < self.expires_at
    }

    /// Returns true if the token expires within the given number of seconds.
    pub fn expires_within(&self, secs: i64) -> bool {
        Self::now_epoch() + secs >= self.expires_at
    }
}

impl fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CachedToken(***)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Local,
    #[serde(rename = "openldap")]
    OpenLdap,
    #[serde(rename = "activedirectory")]
    ActiveDirectory,
    Github,
    #[serde(rename = "googleoauth")]
    GoogleOAuth,
    Shibboleth,
    #[serde(rename = "azuread")]
    AzureAd,
    Keycloak,
    Ping,
    Okta,
    #[serde(rename = "freeipa")]
    FreeIpa,
}

impl AuthType {
    /// Returns the Rancher v3-public provider path segment.
    pub fn provider_path(&self) -> &'static str {
        match self {
            Self::Local => "localProviders/local",
            Self::OpenLdap => "openldapProviders/openldap",
            Self::ActiveDirectory => "activedirectoryProviders/activedirectory",
            Self::Github => "githubProviders/github",
            Self::GoogleOAuth => "googleoauthProviders/googleoauth",
            Self::Shibboleth => "shibbolethProviders/shibboleth",
            Self::AzureAd => "azureadProviders/azuread",
            Self::Keycloak => "keycloakProviders/keycloak",
            Self::Ping => "pingProviders/ping",
            Self::Okta => "oktaProviders/okta",
            Self::FreeIpa => "freeipaProviders/freeipa",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    url: Url,
    pub username: String,
    #[serde(rename = "authType")]
    pub auth_type: AuthType,
    #[serde(
        default,
        rename = "cachedToken",
        skip_serializing_if = "Option::is_none"
    )]
    pub cached_token: Option<CachedToken>,
}

impl Server {
    pub fn new(url: &str, username: String, auth_type: AuthType) -> Result<Self> {
        let parsed = Url::parse(url).context("invalid server URL")?;
        if parsed.scheme() != "https" {
            bail!("server URL must use https (got {}://)", parsed.scheme());
        }
        Ok(Self {
            url: parsed,
            username,
            auth_type,
            cached_token: None,
        })
    }

    /// Test-only constructor that allows non-HTTPS URLs (for wiremock).
    #[cfg(test)]
    pub fn new_insecure(url: &str, username: String, auth_type: AuthType) -> Result<Self> {
        let parsed = Url::parse(url).context("invalid server URL")?;
        Ok(Self {
            url: parsed,
            username,
            auth_type,
            cached_token: None,
        })
    }

    /// Base URL with trailing slash stripped for building API paths.
    pub fn api_base(&self) -> &str {
        self.url.as_str().trim_end_matches('/')
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Hostname with dots replaced by dashes, used as a suffix for conflict resolution.
    /// e.g. "rancher.prod.example.com" -> "rancher-prod-example-com"
    pub fn host_slug(&self) -> String {
        self.url.host_str().unwrap_or("unknown").replace('.', "-")
    }

    /// Returns true if the server matches a target URL or hostname.
    pub fn matches(&self, target: &str) -> bool {
        self.api_base() == target || self.url.host_str() == Some(target)
    }
}

fn default_version() -> String {
    "2.0".into()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub servers: Vec<Server>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: default_version(),
            servers: Vec::new(),
        }
    }
}

impl Config {
    /// Maximum config file size (10 MiB) to prevent memory exhaustion from
    /// malicious or corrupt YAML.
    const MAX_CONFIG_SIZE: u64 = 10 * 1024 * 1024;

    pub fn load(path: &Path) -> Result<Self> {
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).context("failed to read config file"),
        };
        if metadata.len() > Self::MAX_CONFIG_SIZE {
            bail!("config file is too large ({} bytes)", metadata.len());
        }
        let contents = fs::read_to_string(path).context("failed to read config file")?;
        yaml_serde::from_str(&contents).context("failed to parse config file")
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = yaml_serde::to_string(self).context("failed to serialize config")?;
        write_secure(path, &contents, 0o700, 0o600).context("failed to save config file")
    }

    pub fn add_server(&mut self, server: Server) -> Result<()> {
        if self.servers.iter().any(|s| s.url == server.url) {
            bail!("server {} already configured", server.url);
        }
        self.servers.push(server);
        Ok(())
    }

    pub fn remove_server(&mut self, target: &str) -> bool {
        let before = self.servers.len();
        self.servers.retain(|s| !s.matches(target));
        self.servers.len() < before
    }
}

pub fn config_path() -> Result<PathBuf> {
    let mut p = dirs::config_dir().context("could not determine config directory")?;
    p.push("roundup");
    p.push("config.yaml");
    Ok(p)
}

pub fn default_kubeconfig_path() -> Result<PathBuf> {
    let mut p = dirs::home_dir().context("could not determine home directory")?;
    p.push(".kube");
    p.push("roundup-config");
    Ok(p)
}

/// Write a file with secure permissions on both the parent directory and the file itself.
/// File permissions are set atomically at creation time to avoid a TOCTOU window
/// where the file could be briefly world-readable.
pub(crate) fn write_secure(
    path: &Path,
    contents: &str,
    dir_mode: u32,
    file_mode: u32,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create directory")?;
        fs::set_permissions(parent, Permissions::from_mode(dir_mode))
            .context("failed to set directory permissions")?;
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(file_mode)
        .open(path)
        .context("failed to open file")?;
    f.write_all(contents.as_bytes())
        .context("failed to write file")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn api_base_strips_trailing_slash() {
        let server = Server::new(
            "https://rancher.example.com/",
            "admin".into(),
            AuthType::Local,
        )
        .unwrap();
        assert!(!server.api_base().ends_with('/'));
    }

    #[test]
    fn invalid_url_is_rejected_at_construction() {
        let result = Server::new("not a url", "admin".into(), AuthType::Local);
        assert!(result.is_err());
    }

    #[test]
    fn config_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.yaml");

        let mut config = Config::default();
        config
            .add_server(
                Server::new(
                    "https://rancher.example.com",
                    "admin".into(),
                    AuthType::Local,
                )
                .unwrap(),
            )
            .unwrap();

        config.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();

        assert_eq!(loaded.servers.len(), 1);
        assert_eq!(loaded.servers[0].username, "admin");
        assert_eq!(loaded.servers[0].auth_type, AuthType::Local);
    }

    #[test]
    fn config_load_missing_file_returns_default() {
        let config = Config::load(Path::new("/nonexistent/path/config.yaml")).unwrap();
        assert!(config.servers.is_empty());
        assert_eq!(config.version, "2.0");
    }

    #[test]
    fn add_duplicate_server_fails() {
        let mut config = Config::default();
        let server = Server::new(
            "https://rancher.example.com",
            "admin".into(),
            AuthType::Local,
        )
        .unwrap();
        config.add_server(server.clone()).unwrap();

        let result = config.add_server(server);
        assert!(result.is_err());
    }

    #[test]
    fn remove_server_by_url() {
        let mut config = Config::default();
        config
            .add_server(
                Server::new(
                    "https://rancher.example.com",
                    "admin".into(),
                    AuthType::Local,
                )
                .unwrap(),
            )
            .unwrap();

        assert!(config.remove_server("https://rancher.example.com"));
        assert!(config.servers.is_empty());
    }

    #[test]
    fn remove_server_by_hostname() {
        let mut config = Config::default();
        config
            .add_server(
                Server::new(
                    "https://rancher.example.com",
                    "admin".into(),
                    AuthType::Local,
                )
                .unwrap(),
            )
            .unwrap();

        assert!(config.remove_server("rancher.example.com"));
        assert!(config.servers.is_empty());
    }

    #[test]
    fn http_url_is_rejected() {
        let result = Server::new(
            "http://rancher.example.com",
            "admin".into(),
            AuthType::Local,
        );
        assert!(result.is_err());
    }

    #[test]
    fn remove_nonexistent_server_returns_false() {
        let mut config = Config::default();
        assert!(!config.remove_server("https://nope.example.com"));
    }

    #[test]
    fn password_debug_is_redacted() {
        let pw = Password::new("super-secret");
        assert_eq!(format!("{pw:?}"), "Password(***)");
        assert_eq!(pw.expose(), "super-secret");
    }

    #[test]
    fn auth_type_serde_roundtrip() {
        let yaml = "openldap";
        let parsed: AuthType = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(parsed, AuthType::OpenLdap);

        let serialized = yaml_serde::to_string(&parsed).unwrap();
        assert_eq!(serialized.trim(), "openldap");
    }

    #[test]
    fn auth_type_provider_path() {
        assert_eq!(AuthType::Local.provider_path(), "localProviders/local");
        assert_eq!(
            AuthType::AzureAd.provider_path(),
            "azureadProviders/azuread"
        );
    }

    #[test]
    fn cached_token_valid_in_future() {
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600;
        let token = CachedToken::new("tok".into(), future);
        assert!(token.is_valid());
    }

    #[test]
    fn cached_token_expired_in_past() {
        let past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 60;
        let token = CachedToken::new("tok".into(), past);
        assert!(!token.is_valid());
    }

    #[test]
    fn cached_token_debug_is_redacted() {
        let token = CachedToken::new("secret-token".into(), 0);
        assert_eq!(format!("{token:?}"), "CachedToken(***)");
    }

    #[test]
    fn cached_token_serde_roundtrip() {
        let token = CachedToken::new("my-token".into(), 1700000000);
        let yaml = yaml_serde::to_string(&token).unwrap();
        let parsed: CachedToken = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(parsed.value(), "my-token");
        assert_eq!(parsed.expires_at(), 1700000000);
    }

    #[test]
    fn config_roundtrip_with_cached_token() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.yaml");

        let mut config = Config::default();
        let mut server = Server::new(
            "https://rancher.example.com",
            "admin".into(),
            AuthType::Local,
        )
        .unwrap();
        server.cached_token = Some(CachedToken::new("tok-123".into(), 1700000000));
        config.add_server(server).unwrap();

        config.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();

        let cached = loaded.servers[0].cached_token.as_ref().unwrap();
        assert_eq!(cached.value(), "tok-123");
        assert_eq!(cached.expires_at(), 1700000000);
    }

    #[test]
    fn cached_token_expires_within() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Expires in 2 hours — within 1 day
        let token = CachedToken::new("tok".into(), now + 7200);
        assert!(token.expires_within(86400));

        // Expires in 2 days — not within 1 day
        let token = CachedToken::new("tok".into(), now + 172800);
        assert!(!token.expires_within(86400));
    }

    #[test]
    fn config_loads_without_cached_token() {
        let yaml = "version: '2.0'\nservers:\n  - url: https://rancher.example.com\n    username: admin\n    authType: local\n";
        let config: Config = yaml_serde::from_str(yaml).unwrap();
        assert!(config.servers[0].cached_token.is_none());
    }
}
