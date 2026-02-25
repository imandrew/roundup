use std::env;
use std::io::{self, IsTerminal, Write};

use anyhow::{Result, bail};

use crate::config::Password;

pub fn read_password(prompt: &str) -> Result<Password> {
    if let Ok(pw) = env::var("ROUNDUP_RANCHER_PASSWORD") {
        return Ok(Password::new(pw));
    }

    if !io::stdin().is_terminal() {
        bail!(
            "cannot read password: non-interactive terminal and ROUNDUP_RANCHER_PASSWORD not set"
        );
    }

    eprint!("{prompt}");
    io::stderr().flush()?;

    let pw = rpassword::read_password()?;
    Ok(Password::new(pw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_from_env_var() {
        temp_env::with_var("ROUNDUP_RANCHER_PASSWORD", Some("from-env"), || {
            let pw = read_password("ignored: ").unwrap();
            assert_eq!(pw.expose(), "from-env");
        });
    }

    #[test]
    fn fails_without_env_or_tty() {
        temp_env::with_var_unset("ROUNDUP_RANCHER_PASSWORD", || {
            if !io::stdin().is_terminal() {
                let result = read_password("prompt: ");
                assert!(result.is_err());
            }
        });
    }
}
