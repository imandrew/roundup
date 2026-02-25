use std::collections::HashMap;
use std::io::{Write, stdout};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use tracing::{debug, info, warn};
use url::Url;

use crate::config::{self, AuthType, Config, Server};
use crate::kubeconfig::{self, ExcludeFilter};
use crate::password::read_password;
use crate::rancher::{AuthToken, RancherClient};

const FETCH_TIMEOUT: Duration = Duration::from_secs(600);
/// Rotate tokens expiring within 1 day.
const TOKEN_REFRESH_BUFFER_SECS: i64 = 24 * 60 * 60;

#[derive(Parser)]
#[command(name = "roundup", about = "Multi-Rancher kubeconfig manager")]
pub struct Cli {
    /// Enable verbose logging (-v info, -vv debug)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Config file path
    #[arg(long)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Add a Rancher server
    Add {
        /// Server URL
        url: String,

        /// Username
        #[arg(short, long)]
        username: String,

        /// Authentication type
        #[arg(short = 'A', long, default_value = "local")]
        authtype: AuthType,
    },

    /// List configured servers
    List,

    /// Remove a server by URL or hostname
    Remove {
        /// Server URL or hostname
        target: String,
    },

    /// Fetch kubeconfigs from all Rancher servers
    Fetch {
        /// Output path for merged kubeconfig
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Exclude clusters matching regex pattern (repeatable)
        #[arg(short = 'x', long)]
        exclude: Vec<String>,

        /// Skip TLS certificate verification
        #[arg(long)]
        insecure: bool,
    },
}

pub async fn run(cli: Cli) -> Result<()> {
    let config_path = cli
        .config
        .unwrap_or_else(|| config::config_path().expect("could not determine config path"));

    match cli.command {
        Command::Add {
            url,
            username,
            authtype,
        } => cmd_add(&config_path, &url, username, authtype),
        Command::List => cmd_list(&config_path),
        Command::Remove { target } => cmd_remove(&config_path, &target),
        Command::Fetch {
            output,
            exclude,
            insecure,
        } => cmd_fetch(&config_path, output, exclude, insecure).await,
    }
}

fn cmd_add(config_path: &Path, url: &str, username: String, authtype: AuthType) -> Result<()> {
    let mut cfg = Config::load(config_path)?;
    let server = Server::new(url, username, authtype)?;

    cfg.add_server(server)?;
    cfg.save(config_path)?;

    println!("Added server {url}");
    Ok(())
}

fn cmd_list(config_path: &Path) -> Result<()> {
    let cfg = Config::load(config_path)?;

    if cfg.servers.is_empty() {
        println!("No servers configured.");
        return Ok(());
    }

    for server in &cfg.servers {
        println!(
            "  {} (user: {}, auth: {:?})",
            server.api_base(),
            server.username,
            server.auth_type
        );
    }

    Ok(())
}

fn cmd_remove(config_path: &Path, target: &str) -> Result<()> {
    let mut cfg = Config::load(config_path)?;

    if cfg.remove_server(target) {
        cfg.save(config_path)?;
        println!("Removed server matching {target}");
    } else {
        bail!("no server found matching {target}");
    }

    Ok(())
}

/// Authenticate all servers, reusing cached tokens where valid and prompting for
/// passwords otherwise. Tokens expiring within 1 day are proactively rotated.
/// Returns the token map and whether any tokens were refreshed (config needs saving).
async fn authenticate_servers(
    client: &RancherClient,
    servers: &mut [Server],
) -> Result<(HashMap<Url, AuthToken>, bool)> {
    if servers.len() > 1 && std::env::var("ROUNDUP_RANCHER_PASSWORD").is_ok() {
        eprintln!(
            "{}: ROUNDUP_RANCHER_PASSWORD is set and will be used for all {} servers",
            "warning".yellow(),
            servers.len()
        );
    }

    let mut tokens = HashMap::new();
    let mut changed = false;

    for server in servers {
        if let Some(cached) = &server.cached_token
            && cached.is_valid()
            && !cached.expires_within(TOKEN_REFRESH_BUFFER_SECS)
        {
            info!(server = %server.api_base(), "using cached token");
            println!(
                "Authenticating to {}... {} {}",
                server.api_base().cyan(),
                "ok".green(),
                "(cached)".dimmed()
            );
            tokens.insert(server.url().clone(), AuthToken::from_cached(cached));
            continue;
        }

        // Delete the old token from Rancher if one exists
        if let Some(cached) = &server.cached_token {
            let old_token = AuthToken::from_cached(cached);
            if let Err(e) = client.delete_token(server, &old_token).await {
                warn!(server = %server.api_base(), error = %e, "failed to delete old token");
            }
        }

        info!(server = %server.api_base(), "authenticating");
        let pw = read_password(&format!(
            "Authenticating to {}... password: ",
            server.api_base().cyan()
        ))?;
        let token = client
            .authenticate(server, &pw)
            .await
            .with_context(|| format!("authentication failed for {}", server.api_base()))?;
        println!(
            "Authenticating to {}... {}",
            server.api_base().cyan(),
            "ok".green()
        );
        server.cached_token = Some(token.to_cached());
        tokens.insert(server.url().clone(), token);
        changed = true;
    }

    Ok((tokens, changed))
}

async fn cmd_fetch(
    config_path: &Path,
    output: Option<PathBuf>,
    exclude: Vec<String>,
    insecure: bool,
) -> Result<()> {
    let mut cfg = Config::load(config_path)?;

    if cfg.servers.is_empty() {
        bail!("no servers configured — use 'roundup add' first");
    }

    if insecure {
        eprintln!(
            "{}: TLS certificate verification is disabled — credentials may be exposed",
            "warning".yellow()
        );
    }

    // Build client
    let client = RancherClient::builder()
        .insecure(insecure)
        .build()
        .context("failed to create HTTP client")?;

    // Phase 1: Authenticate
    let (tokens, config_changed) = authenticate_servers(&client, &mut cfg.servers).await?;

    if config_changed {
        cfg.save(config_path)?;
    }

    // Phase 2: Discover clusters
    println!("\nFetching clusters...");
    let discovered = tokio::time::timeout(
        FETCH_TIMEOUT,
        crate::fetch::discover_clusters(&client, &cfg.servers, &tokens),
    )
    .await
    .context("fetch timed out after 10 minutes")?;

    // Print per-server cluster counts and flatten to download tasks
    let mut download_tasks = Vec::new();
    for d in discovered {
        println!(
            "  {}: {} clusters",
            d.server.api_base().cyan(),
            d.clusters.len().bold()
        );
        for cluster in d.clusters {
            download_tasks.push((d.server.clone(), d.token.clone(), cluster));
        }
    }

    if download_tasks.is_empty() {
        bail!("no kubeconfigs downloaded — check server credentials");
    }

    let total = download_tasks.len();

    // Phase 3: Download kubeconfigs with live progress
    print!("\nDownloading kubeconfigs [{}/{}]...", 0, total);
    let _ = stdout().flush();

    let results =
        crate::fetch::download_kubeconfigs(&client, download_tasks, |completed, total| {
            if completed < total {
                print!("\rDownloading kubeconfigs [{}/{}]...", completed, total);
            } else {
                print!(
                    "\rDownloading kubeconfigs [{}/{}] {}",
                    completed,
                    total,
                    "done".green()
                );
            }
            let _ = stdout().flush();
        })
        .await;

    println!();

    if results.is_empty() {
        bail!("no kubeconfigs downloaded — check server credentials");
    }

    info!(count = results.len(), "downloaded kubeconfigs");

    // Build filter
    let filter = if exclude.is_empty() {
        None
    } else {
        debug!(patterns = ?exclude, "exclude filter active");
        Some(ExcludeFilter::new(&exclude)?)
    };

    // Merge and write
    let using_default = output.is_none();
    let output_path = match output {
        Some(p) => p,
        None => config::default_kubeconfig_path()?,
    };

    kubeconfig::merge_kubeconfigs(results, filter.as_ref(), &output_path)?;

    println!("\nFetch complete — wrote {}", output_path.display().green());
    if using_default {
        println!("export KUBECONFIG={}", output_path.display());
    }
    Ok(())
}
