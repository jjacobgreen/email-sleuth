use crate::core::config::{get_random_sleep_duration, Config};
use crate::core::error::{AppError, Result};
use crate::core::models::{EmailResult, FoundEmailData, ValidatedContact};
use crate::utils::dns::{create_resolver, resolve_mail_server, MailServer};
use crate::utils::patterns::generate_email_patterns;
use crate::utils::smtp::SmtpVerifier;
use crate::verification::{api as verification_api, headless as verification_headless};

use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::time::sleep;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ProviderType {
    Gmail,
    HotmailB2C,
    M365,
    Yahoo,
    Other,
}

#[derive(Debug, Default)]
struct VerificationAttemptOutcome {
    status: Option<bool>,
    message: String,
    source: String,
    confidence_boost: i16,
    definitive: bool,
    is_catch_all: bool,
}

/// The main struct orchestrating the email discovery and verification process.
#[derive(Clone)]
pub struct EmailSleuth {
    http_client: Arc<Client>,
    dns_resolver: Arc<TokioAsyncResolver>,
    smtp_verifier: SmtpVerifier,
    catch_all_domains: Arc<parking_lot::RwLock<HashSet<String>>>,
}

impl EmailSleuth {
    /// Creates a new EmailSleuth instance.
    pub(crate) async fn new(config: &Config) -> Result<Self> {
        tracing::debug!("Initializing EmailSleuth components...");
        let http_client = Arc::new(
            Client::builder()
                .user_agent(&config.user_agent)
                .timeout(config.request_timeout)
                .build()
                .map_err(|e| {
                    AppError::Initialization(format!("Failed to build HTTP client: {}", e))
                })?,
        );
        tracing::debug!("HTTP client initialized.");
        let dns_resolver = Arc::new(create_resolver(config).await?);
        tracing::debug!("DNS resolver initialized.");

        let smtp_verifier = SmtpVerifier::new(Arc::new(config.clone()));
        tracing::debug!("SMTP verifier initialized.");

        tracing::info!("EmailSleuth initialized successfully.");
        Ok(Self {
            http_client,
            dns_resolver,
            smtp_verifier,
            catch_all_domains: Arc::new(parking_lot::RwLock::new(HashSet::new())),
        })
    }

    /// Finds and verifies email addresses for a given validated contact. (High Level)
    pub(crate) async fn find_email(
        &self,
        config: &Config,
        contact: &ValidatedContact,
    ) -> Result<EmailResult> {
        let task_label = format!("{}@{}", contact.full_name, contact.domain);
        tracing::info!(target: "find_email_task", "[{}] Starting email discovery", task_label);
        let start_time = Instant::now();

        let mut email_result = EmailResult::default();

        // Clear catch-all cache for this domain to ensure a fresh start FOR THIS TASK
        // Note: This ensures we don't carry over catch-all status from a *previous* contact
        // processed by the same EmailSleuth instance if that contact happened to have the same domain.
        // If multiple concurrent tasks process the *same* domain, they might still share the cache,
        // which is generally okay as catch-all status is domain-specific.
        {
            let mut cache = self.catch_all_domains.write();
            cache.remove(&contact.domain);
            tracing::trace!(target: "find_email_task", "[{}] Cleared catch-all status for domain from cache (if existed).", task_label);
        }

        let candidates = self.gather_candidates(config, contact, &mut email_result.methods_used);
        if candidates.is_empty() {
            tracing::warn!(target: "find_email_task", "[{}] No email candidates generated or found.", task_label);
            email_result
                .verification_log
                .insert(contact.domain.clone(), "No candidates found".to_string());
            return Ok(email_result);
        }
        tracing::info!(target: "find_email_task", "[{}] Combined {} unique candidates to assess.", task_label, candidates.len());
        tracing::trace!(target: "find_email_task", "[{}] Candidate list (ordered): {:?}", task_label, candidates);

        let (mail_server_info, provider_type) = self
            .resolve_and_identify_provider(&contact.domain, &mut email_result.verification_log)
            .await;

        let verified_data = self
            .evaluate_candidates(
                config,
                contact,
                &candidates,
                &mail_server_info,
                provider_type,
                &task_label,
                &mut email_result.verification_log,
                &mut email_result.methods_used,
            )
            .await?;

        email_result.found_emails = verified_data;
        self.finalize_results(config, &mut email_result);

        let total_duration = start_time.elapsed();
        tracing::info!(target: "find_email_task", "[{}] Email discovery finished in {:.2?}. Result: {:?}",
            task_label, total_duration, email_result.most_likely_email);

        Ok(email_result)
    }

    fn gather_candidates(
        &self,
        config: &Config,
        contact: &ValidatedContact,
        methods_used: &mut Vec<String>,
    ) -> Vec<String> {
        tracing::debug!(target: "find_email_task", "Gathering candidates for {}...", contact.full_name);
        let patterns = generate_email_patterns(
            config,
            &contact.first_name,
            &contact.last_name,
            &contact.domain,
        );
        if !patterns.is_empty() && !methods_used.contains(&"pattern_generation".to_string()) {
            methods_used.push("pattern_generation".to_string());
        }

        // #TODO: Let's look at here again.
        // I keep this here to not break back compatibility
        // But I think I'll remove this feature soon.
        let scraped_emails: Vec<String> = Vec::new();
        // if !scraped_emails.is_empty() && !methods_used.contains(&"website_scraping".to_string()) {
        //     methods_used.push("website_scraping".to_string());
        // }

        let mut all_candidates = Vec::new();
        let mut seen_candidates = HashSet::new();
        let first_lower = contact.first_name.to_lowercase();
        let last_lower = contact.last_name.to_lowercase();

        let add_candidate = |email: &str, list: &mut Vec<String>, seen: &mut HashSet<String>| {
            let lower_email = email.trim().to_lowercase();
            if lower_email.contains('@')
                && lower_email.contains('.')
                && !lower_email.starts_with('@')
                && !lower_email.ends_with('@')
                && seen.insert(lower_email.clone())
            {
                list.push(lower_email);
            }
        };

        for p in &patterns {
            if p.contains(&first_lower) || p.contains(&last_lower) {
                add_candidate(p, &mut all_candidates, &mut seen_candidates);
            }
        }
        for s in &scraped_emails {
            if s.contains(&first_lower) || s.contains(&last_lower) {
                add_candidate(s, &mut all_candidates, &mut seen_candidates);
            }
        }
        for p in &patterns {
            if !p.contains(&first_lower) && !p.contains(&last_lower) {
                add_candidate(p, &mut all_candidates, &mut seen_candidates);
            }
        }
        for s in &scraped_emails {
            if !s.contains(&first_lower) && !s.contains(&last_lower) {
                add_candidate(s, &mut all_candidates, &mut seen_candidates);
            }
        }

        all_candidates
    }

    async fn resolve_and_identify_provider(
        &self,
        domain: &str,
        verification_log: &mut HashMap<String, String>,
    ) -> (Option<MailServer>, Option<ProviderType>) {
        tracing::debug!(target: "find_email_task", "Resolving DNS MX for {}...", domain);
        let mail_server_info = match resolve_mail_server(&self.dns_resolver, domain).await {
            Ok(ms) => {
                tracing::info!(target: "find_email_task", "Using mail server {} for domain {}", ms.exchange, domain);
                Some(ms)
            }
            Err(e @ AppError::NxDomain(_)) | Err(e @ AppError::NoDnsRecords(_)) => {
                tracing::error!(target: "find_email_task", "DNS lookup failed (No MX/A or NXDOMAIN): {}. Cannot perform SMTP checks.", e);
                verification_log
                    .entry(domain.to_string())
                    .or_insert(format!("DNS resolution failed: {}", e));
                None
            }
            Err(e) => {
                tracing::warn!(target: "find_email_task", "DNS lookup warning: {}. SMTP checks might fail.", e);
                verification_log
                    .entry(domain.to_string())
                    .or_insert(format!("DNS resolution warning: {}", e));
                None
            }
        };

        let provider_type = mail_server_info
            .as_ref()
            .map(|ms| self.identify_provider(domain, &ms.exchange));
        if let Some(pt) = provider_type {
            tracing::debug!(target: "find_email_task", "Identified provider as: {:?}", pt);
        } else if mail_server_info.is_some() {
            tracing::debug!(target: "find_email_task", "Could not determine provider type (unknown MX pattern).");
        }

        (mail_server_info, provider_type)
    }

    /// Evaluates candidates, performing verification and scoring. Handles early termination.
    async fn evaluate_candidates(
        &self,
        config: &Config,
        contact: &ValidatedContact,
        candidates: &[String],
        mail_server_info: &Option<MailServer>,
        provider_type: Option<ProviderType>,
        task_label: &str,
        verification_log: &mut HashMap<String, String>,
        methods_used: &mut Vec<String>,
    ) -> Result<Vec<FoundEmailData>> {
        let mut verified_data = Vec::with_capacity(candidates.len());
        let total_candidates = candidates.len();

        tracing::info!(target: "find_email_task", "[{}] Starting verification/scoring loop for {} candidates...", task_label, total_candidates);

        let early_termination_threshold = config.early_termination_threshold;
        let mut found_high_confidence_match = false;

        for (index, email) in candidates.iter().enumerate() {
            let candidate_label = format!(
                "[{}:{}/{}] {}",
                task_label,
                index + 1,
                total_candidates,
                email
            );
            let start_verify_time = Instant::now();

            let is_known_catch_all_before_check = {
                let cache = self.catch_all_domains.read();
                cache.contains(&contact.domain)
            };

            let alternative_first = is_known_catch_all_before_check
                && (config.enable_api_checks
                    || (config.enable_headless_checks && config.webdriver_url.is_some()));

            match self
                .verify_and_score_candidate(
                    config,
                    contact,
                    email,
                    mail_server_info,
                    provider_type,
                    &candidate_label,
                    verification_log,
                    methods_used,
                    is_known_catch_all_before_check,
                    alternative_first,
                )
                .await
            {
                Ok(Some(data)) => {
                    let duration = start_verify_time.elapsed();
                    tracing::debug!(target: "find_email_task", "{} Stored: Conf={}, Status={:?}, Src={}, Msg='{}' (Took {:.2?})",
                        candidate_label, data.confidence, data.verification_status, data.source, data.verification_message, duration);

                    verified_data.push(data.clone());

                    // Check if we found a high-confidence match AND the domain is NOT considered catch-all
                    // Re-check the catch-all status *after* the verification, as it might have just been detected
                    let is_currently_catch_all =
                        self.catch_all_domains.read().contains(&contact.domain);

                    if data.confidence >= early_termination_threshold
                        && data.verification_status == Some(true)
                        && !is_currently_catch_all
                    {
                        tracing::info!(target: "find_email_task",
                            "{} Found high-confidence match (confidence: {}/10) on non-catch-all domain. Early termination triggered, skipping {} remaining candidates.",
                            candidate_label, data.confidence, total_candidates - (index + 1));

                        verification_log.entry("early_termination".to_string())
                            .or_insert(format!(
                                "Verification stopped early after finding high-confidence match on non-catch-all domain: {} (confidence: {}/10)",
                                email, data.confidence
                            ));

                        found_high_confidence_match = true;
                    }

                    let source = data.source.as_str();
                    let needs_sleep = source.starts_with("smtp")
                        || source.starts_with("headless")
                        || source.starts_with("api");
                    if needs_sleep && !found_high_confidence_match {
                        let sleep_dur = get_random_sleep_duration(config);
                        tracing::trace!(target: "find_email_task", "{} Sleeping {:?} after verification (Source: {})", candidate_label, sleep_dur, source);
                        sleep(sleep_dur).await;
                    }
                }
                Ok(None) => {
                    tracing::debug!(target: "find_email_task", "{} Discarded.", candidate_label);
                }
                Err(e) => {
                    tracing::error!(target: "find_email_task", "{} Critical error during verification: {}", candidate_label, e);
                    verification_log
                        .entry(email.to_string())
                        .or_insert(format!("Processing Error: {}", e));
                }
            }

            if found_high_confidence_match {
                break;
            }
        }

        if found_high_confidence_match {
            tracing::info!(target: "find_email_task",
                "[{}] Verification completed via early termination. Processed {}/{} candidates.",
                task_label, verified_data.len(), total_candidates);
        } else {
            tracing::info!(target: "find_email_task",
                "[{}] Verification completed. Processed all {} candidates (no early termination).",
                task_label, total_candidates);
        }

        Ok(verified_data)
    }

    fn finalize_results(&self, config: &Config, results: &mut EmailResult) {
        tracing::debug!(target: "find_email_task", "Sorting {} verified email data entries...", results.found_emails.len());

        results.found_emails.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.is_generic.cmp(&b.is_generic))
                .then_with(|| a.email.cmp(&b.email))
        });
        tracing::trace!(target: "find_email_task", "Sorted results: {:?}", results.found_emails);

        results.most_likely_email = None;
        results.confidence_score = 0;

        for email_data in &results.found_emails {
            if email_data.verification_status == Some(false) {
                continue;
            }

            let threshold = if email_data.is_generic {
                config.generic_confidence_threshold
            } else {
                config.confidence_threshold
            };

            if email_data.confidence >= threshold {
                results.most_likely_email = Some(email_data.email.clone());
                results.confidence_score = email_data.confidence;
                tracing::info!(target: "find_email_task", "Selected best candidate: {} (Conf: {}, Generic: {}, Src: {}, Status: {:?})",
                    email_data.email, email_data.confidence, email_data.is_generic, email_data.source, email_data.verification_status);
                break;
            }
        }

        if results.most_likely_email.is_none() {
            if !results.found_emails.is_empty() {
                tracing::info!(target: "find_email_task", "No candidate met confidence thresholds (Base: {}, Generic: {}).",
                    config.confidence_threshold, config.generic_confidence_threshold);
                if let Some(top) = results
                    .found_emails
                    .first()
                    .filter(|d| d.confidence > 0 || d.verification_status == Some(false))
                {
                    tracing::info!(target: "find_email_task", "Top candidate was '{}' (Conf: {}, Status: {:?})", top.email, top.confidence, top.verification_status);
                }
            } else {
                tracing::info!(target: "find_email_task", "No valid candidates were processed or scored.");
            }
        }
    }

    /// Verifies and scores a single email candidate.
    /// Takes `is_known_catch_all` which reflects the cache state *before* this check runs.
    async fn verify_and_score_candidate(
        &self,
        config: &Config,
        contact: &ValidatedContact,
        email: &str,
        mail_server_info: &Option<MailServer>,
        provider_type: Option<ProviderType>,
        candidate_label: &str,
        verification_log: &mut HashMap<String, String>,
        methods_used: &mut Vec<String>,
        is_known_catch_all: bool,
        alternative_first: bool,
    ) -> Result<Option<FoundEmailData>> {
        tracing::debug!(target: "find_email_task", "{}", candidate_label);

        if !config.email_regex.is_match(email) {
            verification_log
                .entry(email.to_string())
                .or_insert("Skipped: Invalid format".to_string());
            return Ok(None);
        }

        let email_domain = email.split('@').nth(1).unwrap_or("");
        let is_generic = self.is_generic_prefix(config, email);
        let name_in_email = self.check_name_in_email(contact, email);

        let mut current_status: Option<bool> = None;
        let mut current_message: String = "Verification pending".to_string();
        let mut current_source: String = "initial".to_string();
        let mut confidence_score: i16 = self.calculate_initial_confidence(
            name_in_email,
            is_generic,
            mail_server_info.is_some(),
        );
        let mut skip_smtp = false;

        let verification_steps = if alternative_first {
            vec!["alternative", "smtp"]
        } else {
            vec!["alternative", "smtp"]
        };

        tracing::trace!(target: "find_email_task", "{} Verification order: {:?}. Known Catch-all (prior): {}", candidate_label, verification_steps, is_known_catch_all);

        for step in verification_steps {
            match step {
                "alternative" => {
                    if let Some(alt_outcome) = self
                        .run_alternative_verifications(
                            config,
                            provider_type,
                            email,
                            methods_used,
                            candidate_label,
                        )
                        .await?
                    {
                        if current_status.is_none() || alt_outcome.definitive {
                            current_status = alt_outcome.status;
                            current_source = alt_outcome.source.clone();
                            if alt_outcome.definitive {
                                confidence_score = alt_outcome.confidence_boost;
                            } else {
                                confidence_score =
                                    (confidence_score + alt_outcome.confidence_boost).clamp(0, 10);
                            }
                        }
                        current_message = alt_outcome.message;

                        if alt_outcome.definitive {
                            skip_smtp = true;
                            tracing::debug!(target: "find_email_task", "{} Skipping subsequent SMTP based on definitive {} result.", candidate_label, current_source);
                            break;
                        }
                    }
                }
                "smtp" => {
                    // Skip SMTP if:
                    // - Already skipped by a definitive alternative result
                    // - The domain was known to be catch-all *before* this verification run
                    // - No mail server info is available
                    if skip_smtp {
                        tracing::debug!(target: "find_email_task", "{} SMTP check skipped (previous definitive result).", candidate_label);
                        continue;
                    }
                    if is_known_catch_all {
                        tracing::debug!(target: "find_email_task", "{} SMTP check skipped (domain known catch-all prior to check).", candidate_label);
                        if current_source != "skipped_smtp" {
                            current_message = format!(
                                "{}; SMTP: Skipped (Domain known catch-all)",
                                current_message
                            );
                            current_source = if current_source == "initial" {
                                "skipped_smtp_catchall".to_string()
                            } else {
                                current_source
                            };
                        }
                        skip_smtp = true;
                        continue;
                    }
                    if mail_server_info.is_none() {
                        tracing::debug!(target: "find_email_task", "{} SMTP check skipped (no mail server info).", candidate_label);
                        if current_source == "initial" {
                            current_message = "SMTP: Skipped (DNS Lookup Failed)".to_string();
                            current_source = "skipped_smtp_dns".to_string();
                            confidence_score = 0;
                        }
                        skip_smtp = true;
                        continue;
                    }

                    let smtp_outcome = self
                        .run_smtp_verification(
                            email,
                            email_domain,
                            mail_server_info.as_ref().unwrap(),
                            methods_used,
                            candidate_label,
                        )
                        .await;

                    if smtp_outcome.is_catch_all {
                        tracing::info!(target: "find_email_task", "{} SMTP detected domain as catch-all, marking cache.", candidate_label);
                        let mut cache = self.catch_all_domains.write();
                        cache.insert(contact.domain.clone());
                    }

                    if smtp_outcome.definitive || current_status.is_none() {
                        current_status = smtp_outcome.status;
                        current_source = smtp_outcome.source;
                        confidence_score =
                            (confidence_score + smtp_outcome.confidence_boost).clamp(0, 10);
                    } else {
                        confidence_score =
                            (confidence_score + smtp_outcome.confidence_boost).clamp(0, 10);
                    }
                    current_message = smtp_outcome.message;
                }
                _ => unreachable!("Invalid verification step"),
            }
        }

        verification_log.entry(email.to_string()).or_insert(format!(
            "{}: {} (Final Conf: {})",
            current_source, current_message, confidence_score
        ));

        let final_confidence = confidence_score as u8;
        if final_confidence > 0 || current_status == Some(false) {
            Ok(Some(FoundEmailData {
                email: email.to_string(),
                confidence: final_confidence,
                source: current_source,
                is_generic,
                verification_status: current_status,
                verification_message: current_message,
            }))
        } else {
            tracing::debug!(target: "find_email_task", "{} Discarding (Confidence: {}, Status: {:?})", candidate_label, final_confidence, current_status);
            Ok(None) // Discard
        }
    }

    /// Runs applicable alternative verification methods (API, Headless).
    async fn run_alternative_verifications(
        &self,
        config: &Config,
        provider_type: Option<ProviderType>,
        email: &str,
        methods_used: &mut Vec<String>,
        candidate_label: &str,
    ) -> Result<Option<VerificationAttemptOutcome>> {
        if let Some(pt) = provider_type {
            match pt {
                ProviderType::M365 => {
                    if config.enable_api_checks {
                        if !methods_used.contains(&"api_m365".to_string()) {
                            methods_used.push("api_m365".to_string());
                        }
                        tracing::debug!(target:"find_email_task", "{} Performing Microsoft 365 API check...", candidate_label);
                        match verification_api::check_m365_api(config, email, &self.http_client)
                            .await
                        {
                            Ok(Some(data)) => {
                                return Ok(Some(VerificationAttemptOutcome {
                                    status: data.verification_status,
                                    message: data.verification_message,
                                    source: data.source,
                                    confidence_boost: data.confidence as i16,
                                    definitive: data.verification_status.is_some(),
                                    is_catch_all: false,
                                }));
                            }
                            Ok(None) => {
                                tracing::debug!(target:"find_email_task", "{} Microsoft 365 API check inconclusive.", candidate_label);
                            }
                            Err(e) => {
                                tracing::error!(target:"find_email_task", "{} Microsoft 365 API failed: {}", candidate_label, e);
                                return Err(e);
                            }
                        }
                    } else {
                        tracing::trace!(target:"find_email_task", "{} Skipping Microsoft 365 API check (disabled in config).", candidate_label);
                    }

                    if config.enable_headless_checks {
                        if let Some(ref webdriver_url) = config.webdriver_url {
                            if !methods_used.contains(&"headless_microsoft".to_string()) {
                                methods_used.push("headless_microsoft".to_string());
                            }
                            tracing::debug!(target:"find_email_task", "{} Performing Microsoft 365 headless check...", candidate_label);
                            match verification_headless::check_hotmail_headless(
                                email,
                                webdriver_url,
                            )
                            .await
                            {
                                Ok(Some(data)) => {
                                    let mut modified_data = data.clone();
                                    modified_data.source = "headless_microsoft".to_string();
                                    modified_data.verification_message = modified_data
                                        .verification_message
                                        .replace("Microsoft Account", "Microsoft 365 Account");

                                    return Ok(Some(VerificationAttemptOutcome {
                                        status: modified_data.verification_status,
                                        message: modified_data.verification_message,
                                        source: modified_data.source,
                                        confidence_boost: modified_data.confidence as i16,
                                        definitive: modified_data.verification_status.is_some(),
                                        is_catch_all: false,
                                    }));
                                }
                                Ok(None) => {
                                    tracing::debug!(target:"find_email_task", "{} Microsoft 365 headless check inconclusive.", candidate_label);
                                }
                                Err(e) => {
                                    if let AppError::VerificationBlocked(reason) = e {
                                        tracing::warn!(target:"find_email_task", "{} Microsoft 365 headless check blocked: {}", candidate_label, reason);
                                        return Ok(None); // Treat as inconclusive if blocked
                                    } else {
                                        tracing::error!(target:"find_email_task", "{} Microsoft 365 headless failed critically: {}", candidate_label, e);
                                        return Err(e); // Propagate critical errors
                                    }
                                }
                            }
                        } else {
                            tracing::warn!(target:"find_email_task", "{} Skipping Microsoft 365 headless check - WebDriver URL missing.", candidate_label);
                        }
                    }
                }

                ProviderType::HotmailB2C if config.enable_headless_checks => {
                    if let Some(ref webdriver_url) = config.webdriver_url {
                        if !methods_used.contains(&"headless_hotmail".to_string()) {
                            methods_used.push("headless_hotmail".to_string());
                        }
                        tracing::debug!(target:"find_email_task", "{} Performing Microsoft consumer headless check...", candidate_label);
                        match verification_headless::check_hotmail_headless(email, webdriver_url)
                            .await
                        {
                            Ok(Some(data)) => {
                                return Ok(Some(VerificationAttemptOutcome {
                                    status: data.verification_status,
                                    message: data.verification_message,
                                    source: data.source,
                                    confidence_boost: data.confidence as i16,
                                    definitive: data.verification_status.is_some(),
                                    is_catch_all: false,
                                }))
                            }
                            Ok(None) => {
                                tracing::debug!(target:"find_email_task", "{} Microsoft consumer headless check inconclusive.", candidate_label);
                            }
                            Err(e) => {
                                if let AppError::VerificationBlocked(reason) = e {
                                    tracing::warn!(target:"find_email_task", "{} Microsoft consumer headless check blocked: {}", candidate_label, reason);
                                    return Ok(None); // Treat as inconclusive if blocked
                                } else {
                                    tracing::error!(target:"find_email_task", "{} Microsoft consumer headless failed critically: {}", candidate_label, e);
                                    return Err(e);
                                }
                            }
                        }
                    } else {
                        tracing::warn!(target:"find_email_task", "{} Skipping Microsoft consumer headless check - WebDriver URL missing.", candidate_label);
                    }
                }

                ProviderType::Yahoo if config.enable_headless_checks => {
                    if let Some(ref webdriver_url) = config.webdriver_url {
                        if !methods_used.contains(&"headless_yahoo".to_string()) {
                            methods_used.push("headless_yahoo".to_string());
                        }
                        tracing::debug!(target:"find_email_task", "{} Performing Yahoo headless check...", candidate_label);
                        match verification_headless::check_yahoo_headless(email, webdriver_url)
                            .await
                        {
                            Ok(Some(data)) => {
                                return Ok(Some(VerificationAttemptOutcome {
                                    status: data.verification_status,
                                    message: data.verification_message,
                                    source: data.source,
                                    confidence_boost: data.confidence as i16,
                                    definitive: data.verification_status.is_some(),
                                    is_catch_all: false,
                                }))
                            }
                            Ok(None) => {
                                tracing::debug!(target:"find_email_task", "{} Yahoo headless check inconclusive.", candidate_label);
                            }
                            Err(e) => {
                                if let AppError::VerificationBlocked(reason) = e {
                                    tracing::warn!(target:"find_email_task", "{} Yahoo headless check blocked: {}", candidate_label, reason);
                                    return Ok(None);
                                } else {
                                    tracing::error!(target:"find_email_task", "{} Yahoo headless failed critically: {}", candidate_label, e);
                                    return Err(e);
                                }
                            }
                        }
                    } else {
                        tracing::warn!(target:"find_email_task", "{} Skipping Yahoo headless check - WebDriver URL missing.", candidate_label);
                    }
                }

                ProviderType::Gmail => {
                    tracing::trace!(target:"find_email_task", "{} No specific alternative verification method for Google-hosted emails yet implemented.", candidate_label);
                }

                ProviderType::HotmailB2C => {
                    tracing::trace!(target:"find_email_task", "{} Skipping Microsoft consumer headless check (disabled in config or URL missing).", candidate_label);
                }
                ProviderType::Yahoo => {
                    tracing::trace!(target:"find_email_task", "{} Skipping Yahoo headless check (disabled in config or URL missing).", candidate_label);
                }
                ProviderType::Other => {
                    tracing::trace!(target:"find_email_task", "{} No specific alternative verification method for provider type 'Other'.", candidate_label);
                }
            }
        } else {
            tracing::debug!(target:"find_email_task", "{} Skipping alternative checks - Provider type unknown.", candidate_label);
        }

        Ok(None)
    }

    /// Runs SMTP verification.
    async fn run_smtp_verification(
        &self,
        email: &str,
        domain: &str,
        mail_server: &MailServer,
        methods_used: &mut Vec<String>,
        candidate_label: &str,
    ) -> VerificationAttemptOutcome {
        if !methods_used.contains(&"smtp_verification".to_string()) {
            methods_used.push("smtp_verification".to_string());
        }
        tracing::debug!(target: "find_email_task", "{} Performing SMTP check via {}...", candidate_label, mail_server.exchange);

        let (smtp_status, smtp_message) = self
            .smtp_verifier
            .verify_with_retries(email, domain, &mail_server.exchange)
            .await;

        let is_catch_all = smtp_message.to_lowercase().contains("catch-all");

        let confidence_boost = match smtp_status {
            Some(true) => {
                if is_catch_all {
                    1
                } else {
                    7
                }
            }
            Some(false) => -10,
            None => {
                if is_catch_all {
                    0
                } else {
                    0
                }
            }
        };

        VerificationAttemptOutcome {
            status: smtp_status,
            message: smtp_message,
            source: "smtp".to_string(),
            confidence_boost,
            definitive: smtp_status.is_some(),
            is_catch_all,
        }
    }

    /// Calculates the initial confidence score before specific network checks.
    fn calculate_initial_confidence(
        &self,
        name_in_email: bool,
        is_generic: bool,
        mx_exists: bool,
    ) -> i16 {
        // Base score + adjustments
        let mut score: i16 = 1; // Start with a minimal base score
        if mx_exists {
            score += 1;
        } else {
            score = 0;
        } // MX record is crucial
        if name_in_email {
            score += 1;
        }
        if is_generic {
            score = (score - 3).max(0);
        } // Penalize generic heavily
        score.clamp(0, 10)
    }

    /// Identifies the likely email provider based on domain and MX record.
    fn identify_provider(&self, domain: &str, mx_host: &str) -> ProviderType {
        let domain_lower = domain.trim().to_lowercase();
        let host_lower_no_dot = mx_host.trim().trim_end_matches('.').to_lowercase();
        let host_lower_with_dot = format!("{}.", host_lower_no_dot);

        match domain_lower.as_str() {
            "gmail.com" | "googlemail.com" => return ProviderType::Gmail,
            "outlook.com" | "hotmail.com" | "live.com" | "msn.com" => {
                return ProviderType::HotmailB2C
            }
            "yahoo.com" | "ymail.com" | "aol.com" => return ProviderType::Yahoo,
            _ => {}
        }

        if host_lower_with_dot.ends_with(".protection.outlook.com.") {
            return ProviderType::M365;
        }
        // Google Workspace (Common patterns for custom domains)
        else if host_lower_with_dot.ends_with(".google.com.") || // e.g., alt1.aspmx.l.google.com.
                host_lower_with_dot.ends_with(".googlemail.com.")
        {
            // e.g., gmr-smtp-in.l.google.com. (less common)
            return ProviderType::Gmail;
        }
        // Microsoft Consumer Services (Less common for custom domains, but possible)
        else if host_lower_with_dot.ends_with(".olc.protection.outlook.com.") {
            // Example: mail.olc.protection.outlook.com (seen for some partner setups)
            return ProviderType::HotmailB2C;
        }
        // Yahoo/Verizon Media (Check for common patterns)
        else if host_lower_with_dot.ends_with(".yahoodns.net.") || // e.g., mta5.am0.yahoodns.net.
                host_lower_with_dot.contains("mx.aol.com")
        {
            // AOL MX records
            return ProviderType::Yahoo;
        }
        // Catch generic outlook.com if not caught by protection.outlook.com. (Might indicate M365 or consumer)
        // This is broader, place after specific checks.
        else if host_lower_with_dot.contains("outlook.com") {
            // Could be M365 (less common direct MX) or potentially consumer routing. Default to M365?
            return ProviderType::M365;
        }
        // Catch generic yahoo.com if not caught by yahoodns.net (less common direct MX)
        else if host_lower_with_dot.contains("yahoo.com") {
            return ProviderType::Yahoo;
        }
        // Check for common Email Security Gateways (often indicate business email but not provider)
        else if host_lower_with_dot.ends_with(".mimecast.com.") ||
                host_lower_with_dot.ends_with(".pphosted.com.") || // Proofpoint Essentials
                host_lower_with_dot.ends_with(".ppe-hosted.com.") || // Proofpoint Essentials EU
                host_lower_with_dot.ends_with(".messagelabs.com.") || // Broadcom/Symantec Email Security
                host_lower_with_dot.contains("mxlogic.net")
        {
            // McAfee/Intel Security SaaS Email Protection (older)
            // Treat as 'Other' because the underlying provider isn't revealed by the gateway MX
            return ProviderType::Other;
        }

        // Default if no specific pattern matches
        ProviderType::Other
    }

    /// Checks if the contact's name parts are present in the email's local part.
    fn check_name_in_email(&self, contact: &ValidatedContact, email: &str) -> bool {
        if let Some(local_part) = email.split('@').next() {
            let local_lower = local_part.to_lowercase();
            let first_lower = contact.first_name.to_lowercase();
            let last_lower = contact.last_name.to_lowercase();
            (first_lower.len() > 1 && local_lower.contains(&first_lower))
                || (last_lower.len() > 1 && local_lower.contains(&last_lower))
        } else {
            false
        }
    }

    /// Checks if an email uses a known generic prefix.
    fn is_generic_prefix(&self, config: &Config, email: &str) -> bool {
        email.split('@').next().is_some_and(|local| {
            config
                .generic_email_prefixes
                .contains(&local.to_lowercase())
        })
    }
}
