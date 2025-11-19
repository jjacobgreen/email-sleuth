//! Provides the `ConfigBuilder` for fluent configuration construction.

use super::loading::{apply_file_config, load_config_file};
use super::validation::validate_config;
use super::{Config, ConfigFile, Result};
use crate::AppError;
use std::path::Path;
use std::time::Duration;
/// Builder pattern for creating `Config` instances fluently.
///
/// This is the primary way users should create a `Config` object.
/// It handles loading from files, applying overrides, and validation.
#[derive(Default)]
pub struct ConfigBuilder {
    config: Config,
    config_file_path: Option<String>,
    overrides: ConfigFile,
}

impl ConfigBuilder {
    /// Creates a new builder with default configuration values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Specify an optional configuration file path to load.
    pub fn config_file(mut self, path: impl Into<String>) -> Self {
        self.config_file_path = Some(path.into());
        self
    }

    pub fn max_concurrency(mut self, value: usize) -> Self {
        self.overrides.verification.max_concurrency = Some(value);
        self
    }
    pub fn max_verification_attempts(mut self, value: u32) -> Self {
        self.overrides.smtp.max_verification_attempts = Some(value);
        self
    }
    pub fn sleep_between_requests(mut self, min: f32, max: f32) -> Self {
        self.overrides.network.min_sleep = Some(min);
        self.overrides.network.max_sleep = Some(max);
        self
    }
    pub fn request_timeout(mut self, duration: Duration) -> Self {
        self.overrides.network.request_timeout = Some(duration.as_secs());
        self
    }
    pub fn smtp_timeout(mut self, duration: Duration) -> Self {
        self.overrides.smtp.smtp_timeout = Some(duration.as_secs());
        self
    }
    pub fn dns_timeout(mut self, duration: Duration) -> Self {
        self.overrides.dns.dns_timeout = Some(duration.as_secs());
        self
    }
    pub fn common_pages_to_scrape(mut self, pages: Vec<String>) -> Self {
        self.overrides.scraping.common_pages = Some(pages);
        self
    }
    pub fn generic_email_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.overrides.scraping.generic_email_prefixes = Some(prefixes);
        self
    }
    pub fn user_agent(mut self, value: impl Into<String>) -> Self {
        self.overrides.network.user_agent = Some(value.into());
        self
    }
    pub fn smtp_sender_email(mut self, value: impl Into<String>) -> Self {
        self.overrides.smtp.smtp_sender_email = Some(value.into());
        self
    }
    pub fn dns_servers(mut self, servers: Vec<String>) -> Self {
        self.overrides.dns.dns_servers = Some(servers);
        self
    }
    pub fn confidence_threshold(mut self, value: u8) -> Self {
        self.overrides.verification.confidence_threshold = Some(value);
        self
    }
    pub fn generic_confidence_threshold(mut self, value: u8) -> Self {
        self.overrides.verification.generic_confidence_threshold = Some(value);
        self
    }
    pub fn max_alternatives(mut self, value: usize) -> Self {
        self.overrides.verification.max_alternatives = Some(value);
        self
    }
    pub fn enable_api_checks(mut self, enable: bool) -> Self {
        self.overrides.advanced_verification.enable_api_checks = Some(enable);
        self
    }
    pub fn enable_headless_checks(mut self, enable: bool) -> Self {
        self.overrides.advanced_verification.enable_headless_checks = Some(enable);
        self
    }
    pub fn early_termination_threshold(mut self, value: u8) -> Self {
        self.overrides.verification.early_termination_threshold = Some(value);
        self
    }
    pub fn webdriver_url(mut self, url: Option<impl Into<String>>) -> Self {
        self.overrides.advanced_verification.webdriver_url = url.map(|s| s.into());
        self
    }
    pub fn chromedriver_path(mut self, path: Option<impl Into<String>>) -> Self {
        self.overrides.advanced_verification.chromedriver_path = path.map(|s| s.into());
        self
    }
    /// Builds the final `Config` object, applying defaults, file settings, overrides, and validation.
    pub fn build(mut self) -> Result<Config> {
        let mut loaded_path: Option<String> = None;

        if let Some(ref path) = self.config_file_path {
            match load_config_file(path) {
                Ok(file_config) => {
                    apply_file_config(&mut self.config, &file_config);
                    loaded_path = Some(path.clone());
                    tracing::info!("Loaded base configuration from specified file: {}", path);
                }
                Err(e) => {
                    tracing::error!("Failed to load specified config file '{}': {}", path, e);
                    return Err(AppError::Config(format!(
                        "Failed to load specified configuration file '{}': {}",
                        path, e
                    )));
                }
            }
        } else {
            tracing::debug!("No config file specified, checking default locations.");
            for path_str in ["./email-sleuth.toml", "./config.toml"] {
                if Path::new(path_str).exists() {
                    tracing::debug!("Found potential default config file: {}", path_str);
                    match load_config_file(path_str) {
                        Ok(file_config) => {
                            apply_file_config(&mut self.config, &file_config);
                            loaded_path = Some(path_str.to_string());
                            tracing::info!(
                                "Loaded base configuration from default location: {}",
                                path_str
                            );
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to load or parse default config '{}': {}",
                                path_str,
                                e
                            );
                        }
                    }
                }
            }
            if loaded_path.is_none() {
                tracing::info!("No configuration file found. Using default values and overrides.");
            }
        }

        apply_file_config(&mut self.config, &self.overrides);
        self.config.loaded_config_path = loaded_path;
        validate_config(&mut self.config)?;

        tracing::debug!("Final configuration built successfully.");
        Ok(self.config)
    }
}
