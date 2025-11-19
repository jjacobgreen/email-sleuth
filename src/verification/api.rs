//! Functions for verifying emails using provider-specific APIs (e.g., Microsoft Graph, OneDrive passive check).

use crate::core::config::Config;
use crate::core::error::{AppError, Result};
use crate::core::models::FoundEmailData;

use reqwest::Client;
use url::Url;

/// Generates the potential OneDrive for Business URL for a Microsoft 365 account.
///
/// This follows the pattern: `https://{tenant}-my.sharepoint.com/personal/{user_path}_{domain_path}/...`
/// Internal helper function.
fn generate_onedrive_url(email_address: &str) -> Result<Url> {
    tracing::trace!("Generating OneDrive URL for: {}", email_address);
    let parts: Vec<&str> = email_address.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(AppError::Initialization(format!(
            "Invalid email format for OneDrive URL generation: {}",
            email_address
        )));
    }
    let username = parts[0];
    let domain = parts[1];

    // Extract tenant name (part before the first dot, common pattern)
    // This might be inaccurate for complex domain setups.
    let tenant = domain.split('.').next().unwrap_or("");
    if tenant.is_empty() {
        return Err(AppError::Initialization(format!(
            "Could not extract tenant name from domain: {}",
            domain
        )));
    }

    // Sanitize username and domain parts for the URL path component.
    // Replace non-alphanumeric characters with underscores.
    let user_path = username
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>();
    let domain_path = domain
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>();

    // Construct the predicted OneDrive URL string
    let url_str = format!(
        "https://{}-my.sharepoint.com/personal/{}_{}/_layouts/15/onedrive.aspx",
        tenant, user_path, domain_path
    );
    tracing::trace!("Generated potential OneDrive URL: {}", url_str);

    // Parse the constructed string into a Url object
    Url::parse(&url_str).map_err(|e| {
        AppError::Initialization(format!(
            "Failed to parse generated OneDrive URL '{}': {}",
            url_str, e
        ))
    })
}

/// Checks Microsoft 365 email existence using the OneDrive passive enumeration technique.
///
/// Sends a HEAD request to the predicted OneDrive URL. Specific HTTP status codes
/// (like 403 Forbidden) can indicate user existence, while others (like 404 Not Found)
/// often indicate non-existence. The interpretation is based on observed behavior and
/// might change based on Microsoft's implementation.
///
/// This is an EXPERIMENTAL technique.
///
/// # Arguments
/// * `config` - The application configuration (used for timeouts).
/// * `email` - The M365 email address to check.
/// * `http_client` - A shared reqwest Client.
///
/// # Returns
/// * `Ok(Some(FoundEmailData))` if the check provides an indicator (positive or negative).
/// * `Ok(None)` if the check is inconclusive (e.g., unexpected status, network error, timeout).
/// * `Err(AppError)` only if a critical setup error occurs (like URL generation failure).
pub(crate) async fn check_m365_api(
    config: &Config,
    email: &str,
    http_client: &Client,
) -> Result<Option<FoundEmailData>> {
    let task_label = format!("[M365 API Check: {}]", email);
    tracing::debug!(target: "verification_api", "{} Starting check", task_label);

    let url = match generate_onedrive_url(email) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(target: "verification_api", "{} Failed to generate OneDrive URL: {}", task_label, e);
            return Ok(None);
        }
    };

    tracing::debug!(target: "verification_api", "{} Sending HEAD request to {}", task_label, url);

    match http_client
        .head(url.clone())
        .timeout(config.request_timeout)
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            tracing::info!(target: "verification_api", "{} Received status: {}", task_label, status);

            match status {
                reqwest::StatusCode::FORBIDDEN => {
                    tracing::info!(target: "verification_api", "{} Status 403 suggests user LIKELY EXISTS.", task_label);
                    Ok(Some(FoundEmailData {
                        email: email.to_string(),
                        confidence: 7,
                        source: "api_m365".to_string(),
                        is_generic: false,
                        verification_status: Some(true),
                        verification_message: "Verified via M365 API (403 Forbidden)".to_string(),
                    }))
                }
                reqwest::StatusCode::NOT_FOUND => {
                    tracing::info!(target: "verification_api", "{} Status 404 suggests user LIKELY DOES NOT EXIST.", task_label);
                    Ok(Some(FoundEmailData {
                        email: email.to_string(),
                        confidence: 0,
                        source: "api_m365".to_string(),
                        is_generic: false,
                        verification_status: Some(false),
                        verification_message: "Non-existent per M365 API (404 Not Found)"
                            .to_string(),
                    }))
                }
                reqwest::StatusCode::FOUND => {
                    tracing::warn!(target: "verification_api", "{} Status 302 Found is inconclusive.", task_label);
                    Ok(None)
                }
                reqwest::StatusCode::OK => {
                    tracing::warn!(target: "verification_api", "{} Status 200 OK is unexpected/inconclusive.", task_label);
                    Ok(None)
                }
                _ => {
                    tracing::warn!(target: "verification_api", "{} Status {} is inconclusive.", task_label, status);
                    Ok(None)
                }
            }
        }
        Err(e) => {
            if e.is_timeout() {
                tracing::warn!(target: "verification_api", "{} Request timed out: {}", task_label, e);
            } else {
                tracing::error!(target: "verification_api", "{} Request failed: {}", task_label, e);
            }
            Ok(None)
        }
    }
}
