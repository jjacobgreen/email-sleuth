//! # Email Sleuth Core Library
//!
//! This crate provides the core logic for discovering and verifying professional
//! email addresses based on contact names and company websites/domains.
//!
//! It is designed to be used either directly as a library or via the `email-sleuth`
//! command-line tool (which uses this library).

mod core;
mod utils;
mod verification;

pub use crate::core::config::{Config, ConfigBuilder, ConfigFile};
pub use crate::core::error::{AppError, Result};
pub use crate::core::models::{Contact, EmailResult, FoundEmailData, ProcessingResult};
pub use crate::core::sleuth::EmailSleuth;

use crate::core::models::ValidatedContact;
use crate::utils::smtp::test_smtp_connectivity;
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;

/// Initializes shared resources like HTTP client and DNS resolver.
/// Essential for creating an `EmailSleuth` instance.
pub async fn initialize_sleuth(config: &Config) -> Result<EmailSleuth> {
    EmailSleuth::new(config).await
}

/// Performs an early check for SMTP connectivity.
pub async fn check_smtp_connectivity() -> Result<()> {
    test_smtp_connectivity().await
}

/// Processes a single contact to find an email address.
///
/// This function encapsulates the validation, email finding, and result packaging
/// for one input `Contact`.
///
/// # Arguments
/// * `config` - The application configuration.
/// * `sleuth` - An initialized `EmailSleuth` instance.
/// * `contact` - The input contact details.
///
/// # Returns
/// * `ProcessingResult` containing the outcome.
pub async fn find_single_email(
    config: &Config,
    sleuth: &EmailSleuth,
    contact: Contact,
) -> ProcessingResult {
    let task_id = format!(
        "Contact: {} / {}",
        contact.full_name.as_deref().unwrap_or("N/A"),
        contact
            .domain
            .as_deref()
            .or(contact.company_domain.as_deref())
            .unwrap_or("N/A")
    );
    tracing::info!(target: "find_single_email", "[{}] Starting processing.", task_id);

    let validation_result = validate_contact_input(&contact);

    let validated_contact = match validation_result {
        Ok(vc) => vc,
        Err(reason) => {
            tracing::warn!(target: "find_single_email", "[{}] Skipping record. Reason: {}", task_id, reason);
            return ProcessingResult::skipped(contact, reason);
        }
    };

    tracing::debug!(target: "find_single_email", "[{}] Contact validated, proceeding to find_email.", task_id);

    let find_result: std::result::Result<EmailResult, AppError> =
        sleuth.find_email(config, &validated_contact).await;

    match find_result {
        Ok(results) => {
            let mut final_record = ProcessingResult::success(contact, results.clone(), config);
            if final_record.email.is_some() {
                tracing::info!(target: "find_single_email",
                    "[{}] ✓ Found likely email: {} (Confidence: {}/10)",
                    task_id, final_record.email.as_ref().unwrap(), final_record.email_confidence.unwrap_or(0)
                );
            } else {
                tracing::info!(target: "find_single_email", "[{}] No high-confidence email found.", task_id);
                if !results.found_emails.is_empty() {
                    final_record.email_verification_failed = true;
                }
            }
            tracing::info!(target: "find_single_email", "[{}] Finished processing.", task_id);
            final_record
        }
        Err(e) => {
            tracing::error!(target: "find_single_email",
                "[{}] !!! Error during core email finding: {}", task_id, e
            );
            ProcessingResult::error(contact, format!("Core processing error: {}", e))
        }
    }
}

///
/// # Arguments
/// * `config` - The application configuration.
/// * `sleuth` - An Arc-wrapped, initialized `EmailSleuth` instance for sharing.
/// * `contacts` - A vector of input `Contact` records.
///
/// # Returns
/// * `Vec<ProcessingResult>` containing outcomes for all input contacts.
pub async fn process_contacts(
    config: Arc<Config>,
    sleuth: Arc<EmailSleuth>,
    contacts: Vec<Contact>,
) -> Vec<ProcessingResult> {
    let total_records = contacts.len();
    if total_records == 0 {
        return Vec::new();
    }

    let mut tasks = FuturesUnordered::new();
    let mut results = Vec::with_capacity(total_records);

    for contact in contacts {
        let validation_result = validate_contact_input(&contact);

        if let Err(reason) = validation_result {
            results.push(ProcessingResult::skipped(contact, reason));
            continue;
        }

        while tasks.len() >= config.max_concurrency {
            if let Some(join_handle_result) = tasks.next().await {
                match join_handle_result {
                    Ok(processing_result) => {
                        results.push(processing_result);
                    }
                    Err(e) => {
                        tracing::error!("A processing task failed to join: {}", e);
                    }
                }
            } else {
                tracing::warn!("Task queue unexpectedly empty while limiting concurrency.");
                break;
            }
        }

        let sleuth_clone = Arc::clone(&sleuth);
        let config_clone = Arc::clone(&config);
        let valid_contact = contact;

        tasks.push(tokio::spawn(async move {
            find_single_email(&config_clone, &sleuth_clone, valid_contact).await
        }));
    }

    while let Some(join_handle_result) = tasks.next().await {
        match join_handle_result {
            Ok(processing_result) => {
                results.push(processing_result);
            }
            Err(e) => {
                tracing::error!("A processing task failed to join during final drain: {}", e);
            }
        }
    }

    results
}

fn validate_contact_input(record: &Contact) -> std::result::Result<ValidatedContact, String> {
    let mut first_name = record
        .first_name
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    let mut last_name = record.last_name.as_deref().unwrap_or("").trim().to_string();
    let original_full_name = record.full_name.as_deref().unwrap_or("").trim().to_string();
    let domain_input_str = record
        .domain
        .as_deref()
        .or(record.company_domain.as_deref())
        .unwrap_or("")
        .trim()
        .to_string();

    if (first_name.is_empty() || last_name.is_empty()) && !original_full_name.is_empty() {
        let name_parts: Vec<&str> = original_full_name.split_whitespace().collect();
        if name_parts.len() >= 2 {
            if first_name.is_empty() {
                first_name = name_parts[0].to_string();
            }
            if last_name.is_empty() {
                last_name = name_parts.last().unwrap_or(&"").to_string();
            }
        } else if name_parts.len() == 1 {
            if first_name.is_empty() && last_name.is_empty() {
                first_name = name_parts[0].to_string();
                last_name = name_parts[0].to_string();
            } else if first_name.is_empty() {
                first_name = name_parts[0].to_string();
            } else {
                last_name = name_parts[0].to_string();
            }
        }
    }

    let mut missing_parts = Vec::new();
    if first_name.is_empty() {
        missing_parts.push("first name");
    }
    if last_name.is_empty() {
        missing_parts.push("last name");
    }
    if domain_input_str.is_empty() {
        missing_parts.push("domain");
    }

    if !missing_parts.is_empty() {
        return Err(format!("Missing {}", missing_parts.join(", ")));
    }

    let domain = match crate::utils::domain::get_domain_from_url(&domain_input_str) {
        Ok(d) => d,
        Err(e) => {
            return Err(format!(
                "Cannot extract domain from '{}': {}",
                domain_input_str, e
            ))
        }
    };

    let website_url = match crate::utils::domain::normalize_url(&domain_input_str) {
        Ok(url) => url,
        Err(e) => return Err(format!("Invalid URL '{}': {}", domain_input_str, e)),
    };

    let final_full_name = if !original_full_name.is_empty() {
        original_full_name
    } else {
        format!("{} {}", first_name, last_name).trim().to_string()
    };

    Ok(ValidatedContact {
        first_name,
        last_name,
        full_name: final_full_name,
        website_url,
        domain,
        original_contact: record.clone(),
    })
}

impl ProcessingResult {
    fn skipped(contact: Contact, reason: String) -> Self {
        Self {
            contact_input: contact,
            email_discovery_results: None,
            email: None,
            email_confidence: None,
            email_verification_method: None,
            email_alternatives: vec![],
            email_finding_skipped: true,
            email_finding_reason: Some(reason),
            email_verification_failed: false,
            email_finding_error: None,
        }
    }

    fn error(contact: Contact, error_msg: String) -> Self {
        Self {
            contact_input: contact,
            email_discovery_results: None,
            email: None,
            email_confidence: None,
            email_verification_method: None,
            email_alternatives: vec![],
            email_finding_skipped: false,
            email_finding_reason: None,
            email_verification_failed: false,
            email_finding_error: Some(error_msg),
        }
    }

    fn success(contact: Contact, results: EmailResult, config: &Config) -> Self {
        let alternatives = results
            .found_emails
            .iter()
            .filter(|e| Some(&e.email) != results.most_likely_email.as_ref())
            .take(config.max_alternatives)
            .map(|e| e.email.clone())
            .collect();

        Self {
            contact_input: contact,
            email: results.most_likely_email.clone(),
            email_confidence: results
                .most_likely_email
                .as_ref()
                .map(|_| results.confidence_score),
            email_verification_method: Some(results.methods_used.join(", ")),
            email_alternatives: alternatives,
            email_discovery_results: Some(results),
            email_finding_skipped: false,
            email_finding_reason: None,
            email_verification_failed: false,
            email_finding_error: None,
        }
    }
}
