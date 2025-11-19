//! Core HeadlessVerifier implementation and WebDriver client management.

use crate::core::config::Config;
use crate::core::error::Result;
use crate::core::models::FoundEmailData;

use fantoccini::{Client, ClientBuilder};
use serde_json::map::Map as JsonMap;
use std::sync::Arc;

#[derive(Clone)]
#[allow(dead_code)]
pub struct HeadlessVerifier {
    config: Arc<Config>,
}
#[allow(dead_code)]
impl HeadlessVerifier {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    /// Creates a WebDriver client connection with appropriate capabilities.
    ///
    /// # Arguments
    /// * `webdriver_url` - URL of the running WebDriver instance
    ///
    /// # Returns
    /// A Result containing a connected WebDriver client or an error.
    pub async fn create_client(&self, webdriver_url: &str) -> Result<Client> {
        tracing::debug!(target: "verification_headless", "Connecting to WebDriver at {}...", webdriver_url);

        // Define Chrome capabilities
        let mut caps = JsonMap::new();
        let mut chrome_opts = JsonMap::new();

        let args = vec![
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--window-size=1024,768",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-translate",
            "--mute-audio",
            "--safebrowsing-disable-auto-update",
            "--ignore-certificate-errors",
            "--log-level=1",
        ];
        chrome_opts.insert("args".to_string(), serde_json::json!(args));

        caps.insert("browserName".to_string(), serde_json::json!("chrome"));
        caps.insert(
            "goog:chromeOptions".to_string(),
            serde_json::json!(chrome_opts),
        );

        tracing::trace!(target: "verification_headless", "WebDriver capabilities: {:?}", caps);

        let mut builder = ClientBuilder::native();

        builder.capabilities(caps);

        match builder.connect(webdriver_url).await {
            Ok(client) => {
                tracing::info!(target: "verification_headless", "WebDriver client connected successfully.");
                Ok(client)
            }
            Err(e) => {
                tracing::error!(target: "verification_headless", "Failed to connect to WebDriver at {}: {}", webdriver_url, e);
                Err(e.into())
            }
        }
    }

    /// Safely closes a client connection, logging any errors.
    ///
    /// # Arguments
    /// * `client` - The WebDriver client to close
    /// * `label` - A task label for logging
    pub async fn close_client(&self, client: Client, label: &str) {
        tracing::debug!(target: "verification_headless", "{} Closing WebDriver client...", label);
        if let Err(e) = client.close().await {
            tracing::warn!(target: "verification_headless", "{} Failed to close WebDriver client cleanly: {}", label, e);
        }
    }

    /// Verify an email address using the appropriate provider-specific check.
    ///
    /// # Arguments
    /// * `email` - The email address to verify
    /// * `webdriver_url` - URL of the running WebDriver instance
    ///
    /// # Returns
    /// A Result containing an optional FoundEmailData or an error.
    pub async fn verify_email(
        &self,
        email: &str,
        webdriver_url: &str,
    ) -> Result<Option<FoundEmailData>> {
        let domain = email.split('@').nth(1).unwrap_or("");

        match domain.to_lowercase().as_str() {
            "yahoo.com" | "ymail.com" => {
                tracing::info!(target: "verification_headless", "Detected Yahoo email, using Yahoo verification flow");
                super::providers::yahoo::check_yahoo_headless(email, webdriver_url).await
            }
            "hotmail.com" | "outlook.com" | "live.com" | "msn.com" => {
                tracing::info!(target: "verification_headless", "Detected Microsoft email, using Outlook verification flow");
                super::providers::microsoft::check_hotmail_headless(email, webdriver_url).await
            }
            _ => {
                tracing::info!(target: "verification_headless", "No specific headless verification method for domain: {}", domain);
                Ok(None)
            }
        }
    }

    /// Checks if headless verification is available based on config settings.
    pub fn is_available(&self) -> bool {
        self.config.enable_headless_checks && self.config.webdriver_url.is_some()
    }
}
