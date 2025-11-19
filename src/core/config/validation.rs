//! Contains validation logic for the final Config struct.

use super::{Config, Result};
use crate::core::error::AppError;

/// Validates the configuration settings after loading and potential overrides.
/// Mutates the config to clamp values or set defaults where applicable and logical.
/// Internal helper for the builder's `build` method.
pub(crate) fn validate_config(config: &mut Config) -> Result<()> {
    // Returns library Result<()>
    if config.sleep_between_requests.0 < 0.0 || config.sleep_between_requests.1 < 0.0 {
        return Err(AppError::Config(
            "Sleep durations cannot be negative.".to_string(),
        ));
    }
    if config.sleep_between_requests.0 > config.sleep_between_requests.1 {
        tracing::warn!(
            "Min sleep ({:.2}s) > Max sleep ({:.2}s). Setting max sleep = min sleep.",
            config.sleep_between_requests.0,
            config.sleep_between_requests.1
        );
        config.sleep_between_requests.1 = config.sleep_between_requests.0;
    }
    if config.dns_servers.is_empty() {
        tracing::warn!("DNS servers list is empty. Resolver might use system defaults or fail.");
    }
    if config.confidence_threshold > 10 {
        tracing::warn!(
            "Confidence threshold ({}) > 10. Clamping to 10.",
            config.confidence_threshold
        );
        config.confidence_threshold = 10;
    }
    if config.generic_confidence_threshold > 10 {
        tracing::warn!(
            "Generic confidence threshold ({}) > 10. Clamping to 10.",
            config.generic_confidence_threshold
        );
        config.generic_confidence_threshold = 10;
    }
    if config.generic_confidence_threshold < config.confidence_threshold {
        tracing::warn!(
            "Generic confidence threshold ({}) < base threshold ({}). Setting generic threshold = base threshold.",
            config.generic_confidence_threshold, config.confidence_threshold
        );
        config.generic_confidence_threshold = config.confidence_threshold;
    }
    if config.max_concurrency == 0 {
        tracing::warn!("Max concurrency was set to 0. Setting to 1.");
        config.max_concurrency = 1;
    }
    if !config.smtp_sender_email.contains('@') || !config.smtp_sender_email.contains('.') {
        return Err(AppError::Config(format!(
            "Invalid SMTP sender email format: {}",
            config.smtp_sender_email
        )));
    }
    if config.enable_headless_checks && config.webdriver_url.is_none() {
        return Err(AppError::Config(
            "WebDriver URL is required when headless checks are enabled.".to_string(),
        ));
    }
    if !config.enable_headless_checks && config.webdriver_url.is_some() {
        tracing::warn!("A WebDriver URL was provided, but headless checks are disabled. The URL will be ignored.");
    }
    if let Some(ref path) = config.chromedriver_path {
        if path.is_empty() {
            tracing::warn!("Provided ChromeDriver path is empty. It will be ignored.");
            config.chromedriver_path = None;
        }
    }
    Ok(())
}
