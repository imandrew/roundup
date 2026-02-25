mod cli;
mod config;
mod fetch;
mod kubeconfig;
mod password;
mod rancher;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();

    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(level))
        .with_target(false)
        .init();

    if let Err(e) = cli::run(cli).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
