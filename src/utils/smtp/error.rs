//! Error handling utilities for SMTP verification operations.

use super::result::SmtpVerificationResult;
use lettre::transport::smtp::Error as SmtpError;

/// Interprets lettre::transport::smtp::Error into a structured SmtpVerificationResult
pub(crate) fn handle_smtp_error(error: &SmtpError, server: &str) -> SmtpVerificationResult {
    let err_string = error.to_string().to_lowercase();

    if err_string.contains("starttls")
        || (err_string.contains("530")
            && err_string.contains("5.7.0")
            && !err_string.contains("authentication required"))
    {
        tracing::warn!(target: "smtp_task", "SMTP error suggests STARTTLS is required by {}: {}", server, error);
        return SmtpVerificationResult::inconclusive_retry(format!(
            "SMTP requires TLS encryption: {}",
            error
        ));
    }

    if err_string.contains("550")
        && (err_string.contains("does not exist")
            || err_string.contains("no such user")
            || err_string.contains("user unknown")
            || err_string.contains("recipient not found")
            || err_string.contains("invalid mailbox")
            || err_string.contains("mailbox unavailable")
            || err_string.contains("address rejected")
            || err_string.contains("invalid recipient")
            || err_string.contains("nosuchuser"))
    {
        tracing::info!(target: "smtp_task", "SMTP error indicates user likely unknown on {}: {}", server, error);
        return SmtpVerificationResult::conclusive(
            false,
            format!("SMTP Rejected (User Likely Unknown): {}", error),
            false,
        );
    }

    if err_string.contains("timed out")
        || err_string.contains("connection refused")
        || err_string.contains("network is unreachable")
    {
        tracing::error!(target: "smtp_task",
            "SMTP connection failed for {}: {}. Port 25 may be blocked.", server, error);
        return SmtpVerificationResult::inconclusive_no_retry(format!(
            "Connection Failed ({}) - Port 25 Blocked?",
            error
        ));
    }

    if err_string.contains("4")
        && (err_string.contains("temporary")
            || err_string.contains("transient")
            || err_string.contains("greylisted"))
    {
        tracing::warn!(target: "smtp_task", "SMTP transient error from {}: {}", server, error);
        return SmtpVerificationResult::inconclusive_retry(format!(
            "SMTP Transient Error (4xx): {}",
            error
        ));
    }

    if err_string.contains("5")
        && (err_string.contains("permanent")
            || err_string.contains("rejected")
            || err_string.contains("denied"))
    {
        tracing::error!(target: "smtp_task", "SMTP permanent error from {}: {}", server, error);
        return SmtpVerificationResult::inconclusive_no_retry(format!(
            "SMTP Permanent Error (5xx): {}",
            error
        ));
    }

    // Check for TLS-specific errors during handshake etc.
    if err_string.contains("tls") {
        tracing::warn!(target: "smtp_task", "SMTP TLS Error for {}: {}", server, error);
        return SmtpVerificationResult::inconclusive_retry(format!("SMTP TLS Error: {}", error));
    }

    if err_string.contains("connection reset") {
        tracing::warn!(target: "smtp_task", "SMTP connection reset by {}: {}", server, error);
        return SmtpVerificationResult::inconclusive_retry(format!(
            "Connection reset by {} ({})",
            server, error
        ));
    }

    tracing::error!(target: "smtp_task", "Unhandled SMTP Error for {}: {}", server, error);
    SmtpVerificationResult::inconclusive_retry(format!("Unhandled SMTP Error: {}", error))
}
