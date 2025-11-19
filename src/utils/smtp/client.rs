//! Provides the SmtpVerifier client for validating email addresses via SMTP.

use super::error::handle_smtp_error;
use super::result::SmtpVerificationResult;
use crate::core::config::{get_random_sleep_duration, Config};
use crate::core::error::{AppError, Result};

use lettre::transport::smtp::client::SmtpConnection;
use lettre::transport::smtp::commands::{Ehlo, Mail, Rcpt};
use lettre::transport::smtp::response::{Code, Severity};
use lettre::Address;
use rand::Rng;
use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

/// Connection parameters for SMTP verification
struct ConnectionParams {
    socket_addr: std::net::SocketAddr,
    helo_name: lettre::transport::smtp::extension::ClientId,
    timeout: Duration,
    use_tls: bool,
}

/// Represents a client for verifying email addresses via SMTP.
#[derive(Clone)]
pub struct SmtpVerifier {
    config: Arc<Config>,
}

impl SmtpVerifier {
    /// Creates a new SmtpVerifier with the given configuration.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    /// Verifies an email using SMTP with retries for inconclusive results.
    ///
    /// # Arguments
    /// * `email` - The email address to verify.
    /// * `domain` - The domain part of the email address.
    /// * `mail_server` - The hostname or IP address of the mail server.
    ///
    /// # Returns
    /// * `(Option<bool>, String)`: Tuple containing the verification status (Some(true), Some(false), or None)
    ///   and a final descriptive message.
    pub async fn verify_with_retries(
        &self,
        email: &str,
        domain: &str,
        mail_server: &str,
    ) -> (Option<bool>, String) {
        let mut last_result: Option<bool> = None;
        let mut last_message = "SMTP check did not run or complete".to_string();
        let mut is_catch_all = false;

        for attempt in 0..self.config.max_verification_attempts {
            tracing::debug!(target: "smtp_task",
                "Attempt {}/{} to verify <{}> via SMTP server {}",
                attempt + 1,
                self.config.max_verification_attempts,
                email,
                mail_server
            );

            match self.verify_email(email, domain, mail_server).await {
                Ok(result) => {
                    last_result = result.exists;
                    last_message = result.message.clone();
                    is_catch_all = result.is_catch_all;

                    if result.exists.is_some() {
                        tracing::debug!(target: "smtp_task",
                            "SMTP check for <{}> conclusive (Result: {:?}, Catch-all: {}) on attempt {}.",
                            email, result.exists, is_catch_all, attempt + 1
                        );
                        break;
                    }

                    if result.is_catch_all {
                        tracing::info!(target: "smtp_task",
                            "SMTP check for <{}> determined domain is a catch-all on attempt {}. No need to retry.",
                            email, attempt + 1
                        );
                        break;
                    }

                    if !result.should_retry {
                        tracing::warn!(target: "smtp_task",
                            "SMTP check for <{}> failed with non-retriable status on attempt {}. Stopping. Msg: {}",
                            email, attempt + 1, result.message
                        );
                        break;
                    }

                    tracing::warn!(target: "smtp_task",
                        "SMTP check for <{}> inconclusive on attempt {}. Message: {}. Will retry if attempts remain.",
                        email, attempt + 1, result.message
                    );
                }
                Err(e) => {
                    tracing::error!(target: "smtp_task",
                        "Internal error during SMTP verification attempt {} for <{}>: {}", attempt + 1, email, e
                    );
                    last_message = format!("Internal error during SMTP check: {}", e);
                    last_result = None;
                    break;
                }
            }

            if attempt < self.config.max_verification_attempts - 1 && last_result.is_none() {
                let sleep_duration = get_random_sleep_duration(&self.config);
                tracing::debug!(target: "smtp_task",
                    "Sleeping {:?} before next SMTP attempt for <{}>.", sleep_duration, email);
                tokio::time::sleep(sleep_duration).await;
            }
        }

        if is_catch_all && !last_message.to_lowercase().contains("catch-all") {
            last_message = format!("{} (Domain is catch-all)", last_message);
        }

        tracing::info!(target: "smtp_task",
            "Final SMTP verification result for <{}> via {}: Status={:?}, Catch-all={}, Msg='{}'",
            email, mail_server, last_result, is_catch_all, last_message
        );

        (last_result, last_message)
    }

    /// Performs the SMTP RCPT TO check for a single email address.
    ///
    /// # Arguments
    /// * `email` - The email address to verify.
    /// * `domain` - The domain part of the email address.
    /// * `mail_server` - The hostname or IP address of the mail server.
    ///
    /// # Returns
    /// * `Result<SmtpVerificationResult>` indicating whether the email likely exists,
    ///   doesn't exist, or if the check was inconclusive.
    pub async fn verify_email(
        &self,
        email: &str,
        domain: &str,
        mail_server: &str,
    ) -> Result<SmtpVerificationResult> {
        tracing::debug!(target: "smtp_task",
            "Starting SMTP check for {} via {} (Domain: {})",
            email,
            mail_server,
            domain
        );

        let recipient_address = match Address::from_str(email) {
            Ok(addr) => addr,
            Err(e) => {
                tracing::error!(target: "smtp_task", "Invalid recipient email format '{}': {}", email, e);
                return Ok(SmtpVerificationResult::conclusive(
                    false,
                    format!("Invalid email format: {}", e),
                    false,
                ));
            }
        };

        let sender_address = Address::from_str(&self.config.smtp_sender_email)
            .map_err(|e| AppError::Config(format!("Invalid sender email in config: {}", e)))?;

        let skip_catch_all_check = false;
        if skip_catch_all_check {
            tracing::debug!(target: "smtp_task",
                "Will skip catch-all test for {} (provider rule SkipCatchAll matches)",
                domain
            );
        }

        let socket_addr = match (mail_server, 25_u16).to_socket_addrs()?.next() {
            Some(addr) => addr,
            None => {
                tracing::error!(target: "smtp_task", "Could not resolve mail server address: {}", mail_server);
                return Ok(SmtpVerificationResult::inconclusive_no_retry(format!(
                    "Could not resolve mail server address: {}",
                    mail_server
                )));
            }
        };

        let helo_name =
            lettre::transport::smtp::extension::ClientId::Domain("localhost".to_string());

        let params = ConnectionParams {
            socket_addr,
            helo_name,
            timeout: self.config.smtp_timeout,
            use_tls: false,
        };

        let connect_result = self
            .try_connection(
                &params,
                &sender_address,
                &recipient_address,
                email,
                domain,
                mail_server,
                skip_catch_all_check,
            )
            .await;

        match &connect_result {
            Ok(result) => {
                let msg = result.message.to_lowercase();
                if msg.contains("starttls")
                    || msg.contains("tls required")
                    || (msg.contains("530")
                        && msg.contains("5.7.0")
                        && !msg.contains("authentication required"))
                {
                    tracing::info!(target: "smtp_task",
                        "Server {} appears to require STARTTLS, retrying connection with TLS enabled", mail_server);

                    let tls_params = ConnectionParams {
                        socket_addr: params.socket_addr,
                        helo_name: params.helo_name,
                        timeout: params.timeout,
                        use_tls: true,
                    };

                    return self
                        .try_connection(
                            &tls_params,
                            &sender_address,
                            &recipient_address,
                            email,
                            domain,
                            mail_server,
                            skip_catch_all_check,
                        )
                        .await;
                }
            }
            Err(e) => {
                tracing::error!(target: "smtp_task",
                    "Error during initial non-TLS verification attempt for {}: {}", mail_server, e);
            }
        }

        connect_result
    }

    async fn try_connection(
        &self,
        params: &ConnectionParams,
        sender_address: &Address,
        recipient_address: &Address,
        email: &str,
        domain: &str,
        mail_server: &str,
        skip_catch_all_check: bool,
    ) -> Result<SmtpVerificationResult> {
        tracing::debug!(target: "smtp_task",
            "Attempting SMTP connection to {} at {} (TLS: {})",
            mail_server, params.socket_addr, params.use_tls
        );

        let tls_parameters = if params.use_tls {
            Some(
                lettre::transport::smtp::client::TlsParameters::new(mail_server.to_string())
                    .map_err(|e| {
                        AppError::SmtpTls(format!(
                            "Failed to create TLS parameters for {}: {}",
                            mail_server, e
                        ))
                    })?,
            )
        } else {
            None
        };

        let mut smtp_conn = match SmtpConnection::connect(
            params.socket_addr,
            Some(params.timeout),
            &params.helo_name,
            tls_parameters.as_ref(),
            None,
        ) {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(target: "smtp_task",
                    "SMTP connection failed for {} (TLS={}): {}",
                    mail_server, params.use_tls, e);

                let err_string = e.to_string();
                if err_string.contains("timed out")
                    || err_string.contains("connection refused")
                    || err_string.contains("Network is unreachable")
                {
                    tracing::error!(target: "smtp_task",
                        "Connection to {} on port 25 failed. This might indicate the port is blocked by an ISP, firewall, or network configuration. Consider testing outbound connectivity on port 25 or using a different network/VPN.",
                        mail_server);
                    return Ok(SmtpVerificationResult::inconclusive_no_retry(format!(
                        "Connection failed ({}): Port 25 access might be blocked.",
                        err_string
                    )));
                }

                return Ok(handle_smtp_error(&e, mail_server));
            }
        };

        tracing::debug!(target: "smtp_task",
            "Established {} connection to {}:{}",
            if params.use_tls { "TLS" } else { "plaintext" },
            mail_server,
            params.socket_addr.port());

        match smtp_conn.command(Ehlo::new(params.helo_name.clone())) {
            Ok(response) => {
                if response.is_positive() {
                    tracing::debug!(target: "smtp_task", "EHLO successful for {}: Code={}, Response: {:?}", mail_server, response.code(), response.message().collect::<Vec<&str>>());
                } else {
                    tracing::warn!(target: "smtp_task", "EHLO command rejected by {}: {} {}", mail_server, response.code(), response.message().collect::<Vec<&str>>().join(" "));
                }
            }
            Err(e) => {
                tracing::warn!(target: "smtp_task", "Error sending EHLO command to {}: {}", mail_server, e);
                return Ok(handle_smtp_error(&e, mail_server));
            }
        }

        tracing::debug!(target: "smtp_task", "Sending MAIL FROM:<{}> to {}...", &self.config.smtp_sender_email, mail_server);
        match smtp_conn.command(Mail::new(Some(sender_address.clone()), vec![])) {
            Ok(response) => {
                if response.is_positive() {
                    tracing::debug!(target: "smtp_task", "MAIL FROM accepted by {}: {:?}", mail_server, response);
                } else {
                    let message = response.message().collect::<Vec<&str>>().join(" ");
                    tracing::error!(target: "smtp_task",
                        "SMTP sender '{}' rejected by {}: {} {:?}",
                        &self.config.smtp_sender_email, mail_server, response.code(), message
                    );

                    if !params.use_tls
                        && (message.to_lowercase().contains("starttls")
                            || (response.code().to_string().starts_with("530")
                                && message.contains("5.7.0")))
                    {
                        tracing::warn!(target: "smtp_task", "MAIL FROM rejected by {}. Server might require STARTTLS, but current connection is plaintext.", mail_server);
                        smtp_conn.quit().ok();
                        return Ok(SmtpVerificationResult::inconclusive_retry(format!(
                            "Server requires STARTTLS: {} {}",
                            response.code(),
                            message
                        )));
                    }

                    smtp_conn.quit().ok();
                    return Ok(SmtpVerificationResult::inconclusive_no_retry(format!(
                        "MAIL FROM rejected: {} {}",
                        response.code(),
                        message
                    )));
                }
            }
            Err(e) => {
                tracing::error!(target: "smtp_task", "Error during MAIL FROM on {}: {}", mail_server, e);
                smtp_conn.quit().ok();
                return Ok(handle_smtp_error(&e, mail_server));
            }
        }

        tracing::debug!(target: "smtp_task", "Sending RCPT TO:<{}> to {}...", email, mail_server);
        let rcpt_result = smtp_conn.command(Rcpt::new(recipient_address.clone(), vec![]));

        let (target_code, target_message): (Code, String) = match rcpt_result {
            Ok(response) => {
                tracing::info!(target: "smtp_task",
                    "RCPT TO:<{}> initial response from {}: Code={}, Msg='{}'",
                    email, mail_server, response.code(), response.message().collect::<Vec<&str>>().join(" ")
                );
                (
                    response.code(),
                    response.message().collect::<Vec<&str>>().join(" "),
                )
            }
            Err(e) => {
                let err_string = e.to_string();
                let is_nonexistent_error = err_string.contains("550")
                    && (err_string.contains("does not exist")
                        || err_string.contains("no such user")
                        || err_string.contains("user unknown")
                        || err_string.contains("recipient not found")
                        || err_string.contains("invalid mailbox")
                        || err_string.contains("mailbox unavailable")
                        || err_string.contains("NoSuchUser"));

                if is_nonexistent_error {
                    tracing::info!(target: "smtp_task",
                        "RCPT TO rejected for <{}> by {}. Email likely does not exist. Error: {}",
                        email, mail_server, e);
                    smtp_conn.quit().ok();
                    return Ok(SmtpVerificationResult::conclusive(
                        false,
                        format!("SMTP Rejected (User Likely Unknown): {}", err_string),
                        false,
                    ));
                } else {
                    tracing::error!(target: "smtp_task",
                        "Error during RCPT TO for <{}> on {}: {}",
                        email, mail_server, e);
                    smtp_conn.quit().ok();
                    return Ok(handle_smtp_error(&e, mail_server));
                }
            }
        };

        let mut is_catch_all = false;
        let perform_catch_all_check: bool;

        if target_code.severity == Severity::PositiveCompletion {
            if skip_catch_all_check {
                tracing::debug!(target: "smtp_task",
                    "Skipping catch-all check for domain {} (MX: {}) based on provider rules.",
                    domain, mail_server
                );
                perform_catch_all_check = false;
            } else {
                tracing::debug!(target: "smtp_task", "Rule allows catch-all check for domain {} (MX: {}). Proceeding.", domain, mail_server);
                perform_catch_all_check = true;
            }
        } else {
            perform_catch_all_check = false;
        }

        if perform_catch_all_check {
            is_catch_all = self
                .perform_catch_all_check(domain, mail_server, &mut smtp_conn)
                .await;
        }
        let final_result = self.evaluate_smtp_response(target_code, target_message, is_catch_all);

        smtp_conn
            .quit()
            .map_err(|e| {
                tracing::warn!(target: "smtp_task", "Error during SMTP QUIT command on {}: {}", mail_server, e);
                AppError::Smtp(e)
            })
            .ok();

        Ok(final_result)
    }

    /// Performs a catch-all check by testing a random non-existent email address
    async fn perform_catch_all_check(
        &self,
        domain: &str,
        mail_server: &str,
        smtp_conn: &mut SmtpConnection,
    ) -> bool {
        let random_user = format!(
            "no-reply-does-not-exist-{}-{:x}@{}",
            rand::thread_rng().gen_range(10000..99999),
            rand::thread_rng().gen::<u32>(),
            domain
        );

        match Address::from_str(&random_user) {
            Ok(random_address) => {
                tracing::debug!(target: "smtp_task", "Performing catch-all check with: RCPT TO:<{}> on {}", random_user, mail_server);
                match smtp_conn.command(Rcpt::new(random_address, vec![])) {
                    Ok(response) if response.code().severity == Severity::PositiveCompletion => {
                        // If the random email is ALSO accepted, it's likely a catch-all
                        tracing::warn!(target: "smtp_task",
                            "Domain {} (MX: {}) appears to be a catch-all (accepted random user {} with code {})",
                            domain, mail_server, random_user, response.code()
                        );
                        true
                    }
                    Ok(response) => {
                        // If the random email is rejected, it's likely NOT a catch-all
                        tracing::debug!(target: "smtp_task",
                            "Catch-all check negative for {} (MX: {}). Random user {} rejected with code {}.",
                            domain, mail_server, random_user, response.code()
                        );
                        false
                    }
                    Err(e) => {
                        tracing::warn!(target: "smtp_task", "Error during catch-all RCPT TO check for {} on {} (ignoring catch-all result): {}", random_user, mail_server, e);
                        false
                    }
                }
            }
            Err(_) => {
                tracing::error!(target: "smtp_task", "Failed to parse generated random email for catch-all check: {}", random_user);
                false
            }
        }
    }

    /// Evaluates SMTP response codes and messages to determine email existence
    fn evaluate_smtp_response(
        &self,
        target_code: Code,
        target_message: String,
        is_catch_all: bool,
    ) -> SmtpVerificationResult {
        match target_code.severity {
            Severity::PositiveCompletion => {
                if is_catch_all {
                    SmtpVerificationResult::inconclusive_no_retry(format!(
                        "SMTP Accepted (Domain is Catch-All): {} {}",
                        target_code, target_message
                    ))
                } else {
                    SmtpVerificationResult::conclusive(
                        true,
                        format!("SMTP Verification OK: {} {}", target_code, target_message),
                        false,
                    )
                }
            }
            Severity::PositiveIntermediate => {
                // 2xx code, but not final positive completion (rare for RCPT TO)
                SmtpVerificationResult::inconclusive_retry(format!(
                    "SMTP Unexpected Intermediate Code: {} {}",
                    target_code, target_message
                ))
            }
            Severity::TransientNegativeCompletion => {
                // 4xx code - Temporary failure, greylisting, etc.
                SmtpVerificationResult::inconclusive_retry(format!(
                    "SMTP Temp Failure/Greylisted? (4xx): {} {}",
                    target_code, target_message
                ))
            }
            Severity::PermanentNegativeCompletion => {
                // 5xx code - Permanent failure
                let rejection_phrases = [
                    "unknown",
                    "no such",
                    "unavailable",
                    "rejected",
                    "doesn't exist",
                    "disabled",
                    "invalid address",
                    "recipient not found",
                    "user unknown",
                    "mailbox unavailable",
                    "no mailbox",
                    "address rejected",
                    "invalid recipient",
                    "policy violation",
                ];
                let message_lower = target_message.to_lowercase();
                let code_str = target_code.to_string();

                if ["550", "551", "553"].contains(&code_str.as_str())
                    || rejection_phrases.iter().any(|p| message_lower.contains(p))
                {
                    SmtpVerificationResult::conclusive(
                        false,
                        format!(
                            "SMTP Rejected (User Likely Unknown): {} {}",
                            target_code, target_message
                        ),
                        false,
                    )
                } else {
                    SmtpVerificationResult::conclusive(
                        false,
                        format!(
                            "SMTP Rejected (Policy/Other 5xx): {} {}",
                            target_code, target_message
                        ),
                        false,
                    )
                }
            }
        }
    }
}

/// Tests basic SMTP connectivity to a known reliable server (Google).
/// This helps diagnose if outbound port 25 is generally blocked.
pub async fn test_smtp_connectivity() -> Result<()> {
    tracing::info!("Testing outbound SMTP (port 25) connectivity to Google...");

    let test_server = "gmail-smtp-in.l.google.com";
    let test_port = 25u16;

    let socket_addr = match (test_server, test_port)
        .to_socket_addrs()
        .map_err(|e| AppError::Config(format!("DNS resolution failed for {}: {}", test_server, e)))?
        .next() // Get the first resolved address
    {
        Some(addr) => addr,
        None => {
            return Err(AppError::Config(format!(
                "Could not resolve any IP address for {}",
                test_server
            )));
        }
    };

    tracing::debug!("Attempting connection to {} ({})", test_server, socket_addr);

    let helo_name = lettre::transport::smtp::extension::ClientId::Domain("localhost".to_string());

    let timeout = Duration::from_secs(5);

    match tokio::time::timeout(timeout, async {
        SmtpConnection::connect(socket_addr, Some(timeout), &helo_name, None, None)
    })
    .await
    {
        Ok(Ok(mut conn)) => {
            tracing::info!(
                "SMTP connectivity test successful (connected to {}).",
                test_server
            );
            conn.quit().ok();
            Ok(())
        }
        Ok(Err(e)) => {
            tracing::error!(
                "SMTP connectivity test failed: Error connecting to {}: {}",
                test_server,
                e
            );
            let err_str = e.to_string().to_lowercase();
            if err_str.contains("connection refused") || err_str.contains("network is unreachable")
            {
                Err(AppError::SmtpInconclusive(format!(
                    "Connection to {} refused or network unreachable. Check firewall or network settings.", test_server
                )))
            } else {
                Err(AppError::Smtp(e))
            }
        }
        Err(_) => {
            tracing::error!(
                "SMTP connectivity test timed out connecting to {}. Outbound port 25 is likely blocked by ISP, firewall, or network provider.", test_server);
            Err(AppError::SmtpInconclusive(
                "SMTP connection timed out - port 25 is likely blocked.".to_string(),
            ))
        }
    }
}
