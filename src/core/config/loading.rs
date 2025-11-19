//! Handles loading configuration from files and applying it to the Config struct.

use super::{Config, ConfigFile};
use anyhow::Context;
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Loads configuration settings from a TOML file.
/// Returns the parsed `ConfigFile` content.
/// Internal to the builder logic.
pub(crate) fn load_config_file(file_path: &str) -> anyhow::Result<ConfigFile> {
    let path = Path::new(file_path);
    if !path.exists() || !path.is_file() {
        return Err(anyhow::anyhow!(
            "File not found or is not a file: {}",
            file_path
        ));
    }
    tracing::debug!("Attempting to read config file: {}", file_path);
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read configuration file: {}", file_path))?;

    tracing::debug!("Attempting to parse TOML from: {}", file_path);
    let config_file_content: ConfigFile = toml::from_str(&content)
        .with_context(|| format!("Failed to parse TOML configuration from {}", file_path))?;

    tracing::debug!("Successfully parsed configuration file: {}", file_path);
    Ok(config_file_content)
}

/// Applies settings from a parsed `ConfigFile` onto a mutable `Config` instance.
/// Internal helper for the builder. This merges settings.
pub(crate) fn apply_file_config(config: &mut Config, file_config: &ConfigFile) {
    // Network
    if let Some(timeout) = file_config.network.request_timeout {
        config.request_timeout = Duration::from_secs(timeout);
    }
    if let Some(min_sleep) = file_config.network.min_sleep {
        config.sleep_between_requests.0 = min_sleep;
    }
    if let Some(max_sleep) = file_config.network.max_sleep {
        config.sleep_between_requests.1 = max_sleep;
    }
    if let Some(ref user_agent) = file_config.network.user_agent {
        config.user_agent = user_agent.clone();
    }

    // DNS
    if let Some(timeout) = file_config.dns.dns_timeout {
        config.dns_timeout = Duration::from_secs(timeout);
    }
    if let Some(ref servers) = file_config.dns.dns_servers {
        if !servers.is_empty() {
            config.dns_servers = servers.clone();
        }
    }

    // SMTP
    if let Some(timeout) = file_config.smtp.smtp_timeout {
        config.smtp_timeout = Duration::from_secs(timeout);
    }
    if let Some(ref sender) = file_config.smtp.smtp_sender_email {
        config.smtp_sender_email = sender.clone();
    }
    if let Some(attempts) = file_config.smtp.max_verification_attempts {
        config.max_verification_attempts = attempts;
    }

    // Scraping
    if let Some(ref pages) = file_config.scraping.common_pages {
        if !pages.is_empty() {
            config.common_pages_to_scrape = pages.clone();
        }
    }
    if let Some(ref prefixes) = file_config.scraping.generic_email_prefixes {
        config.generic_email_prefixes = prefixes.iter().cloned().collect();
    }

    // Verification
    if let Some(threshold) = file_config.verification.confidence_threshold {
        config.confidence_threshold = threshold;
    }
    if let Some(gen_threshold) = file_config.verification.generic_confidence_threshold {
        config.generic_confidence_threshold = gen_threshold;
    }
    if let Some(max_alt) = file_config.verification.max_alternatives {
        config.max_alternatives = max_alt;
    }
    if let Some(concurrency) = file_config.verification.max_concurrency {
        config.max_concurrency = concurrency;
    }
    if let Some(early_term) = file_config.verification.early_termination_threshold {
        config.early_termination_threshold = early_term;
    }

    // Advanced Verification
    if let Some(enable) = file_config.advanced_verification.enable_api_checks {
        config.enable_api_checks = enable;
    }
    if let Some(enable) = file_config.advanced_verification.enable_headless_checks {
        config.enable_headless_checks = enable;
    }
    if let Some(ref url) = file_config.advanced_verification.webdriver_url {
        if !url.trim().is_empty() {
            config.webdriver_url = Some(url.trim().to_string());
        } else {
            config.webdriver_url = None
        }
    }
    if let Some(ref path) = file_config.advanced_verification.chromedriver_path {
        if !path.trim().is_empty() {
            config.chromedriver_path = Some(path.trim().to_string());
        } else {
            config.chromedriver_path = None;
        }
    }
}
