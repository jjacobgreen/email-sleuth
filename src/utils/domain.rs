//! Utility functions for handling domain names and URLs.

use crate::core::error::{AppError, Result};
use url::Url;

/// Extracts the base domain name (e.g., "example.com") from a given URL or domain string.
///
/// Handles common variations:
/// - Adds `https://` scheme if missing.
/// - Parses the URL.
/// - Extracts the host.
/// - Removes common `www.` prefix.
/// - Converts to lowercase.
///
/// Returns `Err(AppError::DomainExtraction)` if the input is empty or a host cannot be parsed.
pub(crate) fn get_domain_from_url(website_url_or_domain: &str) -> Result<String> {
    let trimmed_input = website_url_or_domain.trim();
    if trimmed_input.is_empty() {
        tracing::warn!("Received empty input for domain extraction.");
        return Err(AppError::DomainExtraction(
            "Input string is empty".to_string(),
        ));
    }

    tracing::debug!("Attempting to extract domain from input: {}", trimmed_input);

    let url_str_with_scheme = if !trimmed_input.contains("://") {
        format!("https://{}", trimmed_input)
    } else {
        trimmed_input.to_string()
    };

    let url = match Url::parse(&url_str_with_scheme) {
        Ok(parsed_url) => parsed_url,
        Err(e) => {
            tracing::error!(
                "Failed to parse '{}' as URL (original: '{}'): {}",
                url_str_with_scheme,
                trimmed_input,
                e
            );
            if !trimmed_input.contains('/')
                && trimmed_input.contains('.')
                && !trimmed_input.starts_with('.')
                && !trimmed_input.ends_with('.')
            {
                tracing::warn!(
                    "Input '{}' failed URL parsing but looks like a domain, attempting direct use.",
                    trimmed_input
                );
                let host = trimmed_input.strip_prefix("www.").unwrap_or(trimmed_input);
                return Ok(host.to_lowercase());
            }
            return Err(AppError::UrlParse(e));
        }
    };

    let host = url.host_str().ok_or_else(|| {
        tracing::warn!("Could not extract host component from parsed URL: {}", url);
        AppError::DomainExtraction(format!("Could not extract host from parsed URL: {}", url))
    })?;

    let domain = host.strip_prefix("www.").unwrap_or(host);

    let final_domain = domain.to_lowercase();

    if !final_domain.contains('.') || final_domain.starts_with('.') || final_domain.ends_with('.') {
        tracing::error!("Extracted domain '{}' appears invalid.", final_domain);
        return Err(AppError::DomainExtraction(format!(
            "Extracted domain appears invalid: {}",
            final_domain
        )));
    }

    tracing::debug!(
        "Successfully extracted domain '{}' from '{}'",
        final_domain,
        trimmed_input
    );
    Ok(final_domain)
}

/// Parses the input website string into a valid `Url` object.
///
/// Adds `https://` scheme if missing. Useful for ensuring a base URL for scraping.
/// Returns `Err(AppError::UrlParse)` or `Err(AppError::InsufficientInput)` on failure.
/// This function is internal (`pub(crate)`).
pub(crate) fn normalize_url(website_url_str: &str) -> Result<Url> {
    let trimmed_input = website_url_str.trim();
    if trimmed_input.is_empty() {
        tracing::warn!("Received empty input for URL normalization.");
        return Err(AppError::InsufficientInput(
            "Website URL input is empty".to_string(),
        ));
    }

    tracing::debug!("Normalizing URL input: {}", trimmed_input);

    let url_str_with_scheme = if !trimmed_input.contains("://") {
        format!("https://{}", trimmed_input)
    } else {
        trimmed_input.to_string()
    };

    match Url::parse(&url_str_with_scheme) {
        Ok(url) => {
            if url.host_str().is_none() || url.host_str() == Some("") {
                tracing::error!("URL normalization resulted in URL without host: {}", url);
                Err(AppError::UrlParse(url::ParseError::EmptyHost))
            } else {
                tracing::debug!("Normalized URL: {}", url);
                Ok(url)
            }
        }
        Err(e) => {
            tracing::error!(
                "Failed to parse normalized URL '{}' (original: '{}'): {}",
                url_str_with_scheme,
                trimmed_input,
                e
            );
            Err(AppError::UrlParse(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_domain_from_url_valid() {
        assert_eq!(
            get_domain_from_url("https://www.example.com").unwrap(),
            "example.com"
        );
        assert_eq!(
            get_domain_from_url("http://example.com").unwrap(),
            "example.com"
        );
        assert_eq!(get_domain_from_url("example.com").unwrap(), "example.com");
        assert_eq!(
            get_domain_from_url("www.example.com").unwrap(),
            "example.com"
        );
        assert_eq!(
            get_domain_from_url("https://EXAMPLE.com/path?query=1").unwrap(),
            "example.com"
        );
        assert_eq!(
            get_domain_from_url("http://example.com:8080").unwrap(),
            "example.com"
        );
        assert_eq!(
            get_domain_from_url(" sub.domain.example.co.uk ").unwrap(),
            "sub.domain.example.co.uk"
        );
        assert_eq!(
            get_domain_from_url("http://www.sub.example.org/").unwrap(),
            "sub.example.org"
        );
        assert_eq!(get_domain_from_url("example.co").unwrap(), "example.co");
        assert_eq!(get_domain_from_url("domain.ai").unwrap(), "domain.ai");
    }

    #[test]
    fn test_get_domain_from_url_invalid() {
        assert!(get_domain_from_url("").is_err());
        assert!(get_domain_from_url("   ").is_err());
        assert!(get_domain_from_url("http://").is_err()); // No host
        assert!(get_domain_from_url("https://").is_err()); // No host
        assert!(get_domain_from_url("www.").is_err()); // No domain part
        assert!(get_domain_from_url(".com").is_err());
        assert!(get_domain_from_url("http://.com").is_err());
        assert!(get_domain_from_url("example").is_err()); // No TLD, get_domain_from_url adds scheme and checks final result
        assert!(get_domain_from_url("https://example.").is_err()); // Trailing dot on host might be invalid contextually here
    }

    #[test]
    fn test_normalize_url_valid() {
        assert_eq!(
            normalize_url("example.com").unwrap().as_str(),
            "https://example.com/"
        );
        assert_eq!(
            normalize_url("http://example.com").unwrap().as_str(),
            "http://example.com/"
        );
        assert_eq!(
            normalize_url("https://www.example.com/path")
                .unwrap()
                .as_str(),
            "https://www.example.com/path"
        );
        assert_eq!(
            normalize_url(" https://example.com ").unwrap().as_str(),
            "https://example.com/"
        );
    }

    #[test]
    fn test_normalize_url_invalid() {
        assert!(normalize_url("").is_err());
        assert!(normalize_url("   ").is_err());
        assert!(normalize_url("http://").is_err());
        assert!(normalize_url("https://").is_err());
    }
}
