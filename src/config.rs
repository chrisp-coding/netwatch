use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Config {
    pub subnet: Option<String>,
    pub watch_interval: Option<u64>,
}

pub fn config_path() -> PathBuf {
    let home = if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        format!("/home/{sudo_user}")
    } else {
        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
    };
    PathBuf::from(home)
        .join(".config")
        .join("netwatch")
        .join("config.toml")
}

pub fn load_config() -> Config {
    let path = config_path();
    if !path.exists() {
        return Config::default();
    }
    let data = match fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Config::default(),
    };
    toml::from_str(&data).unwrap_or_default()
}

pub fn write_default_config() -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {e}"))?;
    }
    if path.exists() {
        return Err(format!("Config file already exists: {}", path.display()));
    }
    let content = "# netwatch configuration\n\
        # All fields are optional. CLI arguments take priority over these settings.\n\
        \n\
        # Subnet to scan (e.g. \"192.168.1.0/24\"). Auto-detected if not set.\n\
        # subnet = \"192.168.1.0/24\"\n\
        \n\
        # Seconds between scans in watch mode. Default: 60.\n\
        # watch_interval = 60\n";
    fs::write(&path, content).map_err(|e| format!("Failed to write config: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_none() {
        let c = Config::default();
        assert!(c.subnet.is_none());
        assert!(c.watch_interval.is_none());
    }

    #[test]
    fn parse_config_toml() {
        let toml = "subnet = \"10.0.0.0/24\"\nwatch_interval = 30\n";
        let c: Config = toml::from_str(toml).unwrap();
        assert_eq!(c.subnet.as_deref(), Some("10.0.0.0/24"));
        assert_eq!(c.watch_interval, Some(30));
    }

    #[test]
    fn parse_partial_config() {
        let toml = "watch_interval = 120\n";
        let c: Config = toml::from_str(toml).unwrap();
        assert!(c.subnet.is_none());
        assert_eq!(c.watch_interval, Some(120));
    }
}
