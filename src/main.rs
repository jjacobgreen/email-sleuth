//! # Email Sleuth CLI
//!
//! Command-line interface for the Email Sleuth library (`email_sleuth_core`).
//! This binary parses arguments, sets up configuration, initializes the core sleuth logic,
//! processes contacts (either single or from a file), and handles output.

use email_sleuth_core::{
    check_smtp_connectivity, find_single_email, initialize_sleuth, process_contacts, Config,
    ConfigBuilder, Contact, EmailSleuth, ProcessingResult,
};

// Dependencies specific to the CLI binary
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter, FmtSubscriber};

mod service;

/// Verification modes that determine which verification methods are enabled
#[derive(Copy, Clone, Debug, ValueEnum)]
enum VerificationMode {
    /// Basic verification using SMTP only
    Basic,
    /// Enhanced verification using SMTP and API checks
    Enhanced,
    /// Comprehensive verification using all methods
    Comprehensive,
}

impl std::fmt::Display for VerificationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationMode::Basic => write!(f, "basic"),
            VerificationMode::Enhanced => write!(f, "enhanced"),
            VerificationMode::Comprehensive => write!(f, "comprehensive"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Discovers and verifies professional email addresses.",
    long_about = "Email Sleuth uses pattern generation, website scraping, and verification (SMTP, API, Headless) to find email addresses based on names and domains."
)]
struct AppArgs {
    /// Path to the input JSON file containing contacts (required in file mode).
    #[arg(short, long, default_value = "input.json", env = "EMAIL_SLEUTH_INPUT")]
    input: String,

    /// Path to the output JSON file where results will be saved.
    #[arg(
        short,
        long,
        default_value = "results.json",
        env = "EMAIL_SLEUTH_OUTPUT"
    )]
    output: String,

    /// Name of the person to find email for (enables single contact CLI mode). Requires --domain.
    #[arg(long, env = "EMAIL_SLEUTH_NAME", requires = "domain")]
    // Require domain if name is given
    name: Option<String>,

    /// Domain or website URL to search against (enables single contact CLI mode). Requires --name.
    #[arg(long, env = "EMAIL_SLEUTH_DOMAIN", requires = "name")]
    // Require name if domain is given
    domain: Option<String>,

    /// Output results to standard output instead of a file (only in single contact CLI mode).
    #[arg(long, default_value = "false", env = "EMAIL_SLEUTH_STDOUT")]
    stdout: bool,

    /// Path to a configuration file (TOML format) to load settings from. CLI args override file settings.
    #[arg(long, env = "EMAIL_SLEUTH_CONFIG")]
    config_file: Option<String>,

    /// Maximum number of concurrent processing tasks.
    #[arg(short, long, env = "EMAIL_SLEUTH_CONCURRENCY")]
    concurrency: Option<usize>,

    /// Sender email address for SMTP verification checks.
    #[arg(long, env = "EMAIL_SLEUTH_SMTP_SENDER")]
    smtp_sender: Option<String>,

    /// User agent string for HTTP scraping requests.
    #[arg(long, env = "EMAIL_SLEUTH_USER_AGENT")]
    user_agent: Option<String>,

    /// SMTP connection/command timeout in seconds.
    #[arg(long, env = "EMAIL_SLEUTH_SMTP_TIMEOUT")]
    smtp_timeout: Option<u64>,

    /// HTTP request timeout in seconds.
    #[arg(long, env = "EMAIL_SLEUTH_REQUEST_TIMEOUT")]
    request_timeout: Option<u64>,

    /// DNS resolution timeout in seconds.
    #[arg(long, env = "EMAIL_SLEUTH_DNS_TIMEOUT")]
    dns_timeout: Option<u64>,

    /// Comma-separated list of DNS servers to use for lookups.
    #[arg(long, value_delimiter = ',', env = "EMAIL_SLEUTH_DNS_SERVERS")]
    dns_servers: Option<Vec<String>>,

    /// Enable experimental API-based verification checks (e.g., M365).
    #[arg(long, action = clap::ArgAction::SetTrue, env = "EMAIL_SLEUTH_ENABLE_API_CHECKS")]
    enable_api_checks: Option<bool>,

    /// Enable experimental headless browser verification checks (e.g., Yahoo). Requires WebDriver.
    #[arg(long, action = clap::ArgAction::SetTrue, env = "EMAIL_SLEUTH_ENABLE_HEADLESS_CHECKS")]
    enable_headless_checks: Option<bool>,

    #[arg(long, env = "EMAIL_SLEUTH_EARLY_TERM_THRESHOLD")]
    early_termination_threshold: Option<u8>,

    /// URL of the running WebDriver instance (required if --enable-headless-checks is used).
    #[arg(long, env = "EMAIL_SLEUTH_WEBDRIVER_URL")]
    webdriver_url: Option<String>,

    /// Path to ChromeDriver executable. If not specified, will try to detect automatically.
    #[arg(long, env = "EMAIL_SLEUTH_CHROMEDRIVER_PATH")]
    chromedriver_path: Option<String>,

    /// Verification mode (determines which methods are enabled)
    #[arg(short, long, value_enum, default_value_t = VerificationMode::Basic)]
    mode: VerificationMode,

    /// Manage ChromeDriver service (start, stop, restart, status, logs)
    #[arg(long)]
    service: Option<String>,

    /// Number of log lines to show when using --service logs
    #[arg(long, default_value_t = 20)]
    log_lines: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .with_thread_names(true)
        .with_target(true)
        .with_span_events(FmtSpan::CLOSE)
        .compact()
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .context("Setting up tracing subscriber failed")?;

    tracing::info!(
        "Email Sleuth CLI v{} starting...",
        env!("CARGO_PKG_VERSION")
    );

    let args = AppArgs::parse();
    tracing::debug!("Parsed CLI arguments: {:?}", args);

    let mut config_builder = ConfigBuilder::new();

    if let Some(ref path) = args.config_file {
        config_builder = config_builder.config_file(path);
    }

    match args.mode {
        VerificationMode::Basic => {
            // Basic mode just uses SMTP (default behavior)
        }
        VerificationMode::Enhanced => {
            config_builder = config_builder.enable_api_checks(true);
            tracing::info!("Enhanced verification mode: Enabling API checks");
        }
        VerificationMode::Comprehensive => {
            config_builder = config_builder
                .enable_api_checks(true)
                .enable_headless_checks(true);

            if args.webdriver_url.is_none() {
                config_builder = config_builder.webdriver_url(Some("http://localhost:4444"));
                tracing::info!("Using default WebDriver URL: http://localhost:4444");
            }

            tracing::info!(
                "Comprehensive verification mode: Enabling API and headless browser checks"
            );
        }
    }

    if let Some(c) = args.concurrency {
        config_builder = config_builder.max_concurrency(c);
    }
    if let Some(ref s) = args.smtp_sender {
        config_builder = config_builder.smtp_sender_email(s);
    }
    if let Some(ref ua) = args.user_agent {
        config_builder = config_builder.user_agent(ua);
    }
    if let Some(t) = args.smtp_timeout {
        config_builder = config_builder.smtp_timeout(Duration::from_secs(t));
    }
    if let Some(t) = args.request_timeout {
        config_builder = config_builder.request_timeout(Duration::from_secs(t));
    }
    if let Some(t) = args.dns_timeout {
        config_builder = config_builder.dns_timeout(Duration::from_secs(t));
    }
    if let Some(ref servers) = args.dns_servers {
        if !servers.is_empty() {
            config_builder = config_builder.dns_servers(servers.clone());
        }
    }
    if args.enable_api_checks == Some(true) {
        config_builder = config_builder.enable_api_checks(true);
    }
    if args.enable_headless_checks == Some(true) {
        config_builder = config_builder.enable_headless_checks(true);
    }
    if let Some(threshold) = args.early_termination_threshold {
        config_builder = config_builder.early_termination_threshold(threshold);
    }
    if let Some(ref url) = args.webdriver_url {
        config_builder = config_builder.webdriver_url(Some(url));
    }
    if let Some(ref path) = args.chromedriver_path {
        config_builder = config_builder.chromedriver_path(Some(path));
    }

    let config = match config_builder.build() {
        Ok(cfg) => Arc::new(cfg),
        Err(e) => {
            tracing::error!("Configuration error: {}", e);
            return Err(anyhow::anyhow!("Failed to build configuration: {}", e));
        }
    };
    tracing::debug!("Effective configuration loaded: {:?}", *config);

    if let Some(service_cmd) = args.service.as_deref() {
        return handle_service_command(service_cmd, args.log_lines, &config).await;
    }

    if matches!(args.mode, VerificationMode::Comprehensive) {
        if let Err(e) = ensure_chromedriver_running(&config).await {
            tracing::warn!("ChromeDriver service issue: {}", e);
            if args.webdriver_url.is_none() {
                tracing::warn!("Comprehensive mode may not work fully due to ChromeDriver issues");
            }
        }
    }

    let sleuth = match initialize_sleuth(&config).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!("Initialization error: {}", e);
            return Err(anyhow::anyhow!(
                "Failed to initialize EmailSleuth core: {}",
                e
            ));
        }
    };

    match check_smtp_connectivity().await {
        Ok(_) => tracing::info!(
            "SMTP connectivity test to Google passed (outbound port 25 likely open)."
        ),
        Err(e) => {
            tracing::error!("SMTP connectivity test failed: {}", e);
            tracing::warn!("Standard SMTP verification (port 25) may fail or be unreliable.");
            tracing::warn!("Check firewall rules or ISP restrictions if SMTP checks are needed.");
        }
    }

    let is_cli_mode = args.name.is_some();
    let start_time = Instant::now();

    let execution_result = if is_cli_mode {
        process_cli_mode(&config, &sleuth, &args).await
    } else {
        process_file_mode(config.clone(), sleuth, &args, start_time).await
    };

    if let Err(e) = execution_result {
        tracing::error!("Execution failed: {}", e);
        return Err(e);
    }

    if !is_cli_mode {
        tracing::info!(
            "Processing finished successfully. Total duration: {:.2?}",
            start_time.elapsed()
        );
    }

    if matches!(args.mode, VerificationMode::Comprehensive) {
        if let Ok(running) = service::chromedriver::status(&config).await {
            if running {
                tracing::info!("ChromeDriver service is still running. You can stop it with: email-sleuth --service stop");
            }
        }
    }

    Ok(())
}

/// Ensures the ChromeDriver service is running for comprehensive mode
async fn ensure_chromedriver_running(config: &Config) -> Result<()> {
    if let Ok(running) = service::chromedriver::status(config).await {
        if running {
            tracing::info!("ChromeDriver service is already running");
            return Ok(());
        }
    }

    tracing::info!("Starting ChromeDriver service for comprehensive verification...");
    service::chromedriver::start(config)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start ChromeDriver: {}", e))
}

/// Handles service management commands
async fn handle_service_command(command: &str, log_lines: usize, config: &Config) -> Result<()> {
    match command {
        "start" => {
            service::chromedriver::start(config)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to start ChromeDriver service: {}", e))?;
            println!("ChromeDriver service started successfully");
        }
        "stop" => {
            service::chromedriver::stop(config)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to stop ChromeDriver service: {}", e))?;
            println!("ChromeDriver service stopped successfully");
        }
        "restart" => {
            service::chromedriver::restart(config)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to restart ChromeDriver service: {}", e))?;
            println!("ChromeDriver service restarted successfully");
        }
        "status" => {
            let running = service::chromedriver::status(config).await.map_err(|e| {
                anyhow::anyhow!("Failed to check ChromeDriver service status: {}", e)
            })?;

            if running {
                println!("ChromeDriver service is running and responsive");
            } else {
                println!("ChromeDriver service is not running or not responsive");
                return Err(anyhow::anyhow!(
                    "ChromeDriver service is not running or not responsive"
                ));
            }
        }
        "logs" => {
            let logs = service::chromedriver::logs(log_lines)
                .map_err(|e| anyhow::anyhow!("Failed to retrieve ChromeDriver logs: {}", e))?;

            println!("ChromeDriver Logs (last {} lines):", log_lines);
            println!("----------------------------------------");
            println!("{}", logs);
            println!("----------------------------------------");
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown service command: {}. Valid commands are: start, stop, restart, status, logs", command));
        }
    }

    Ok(())
}

async fn process_cli_mode(config: &Config, sleuth: &EmailSleuth, args: &AppArgs) -> Result<()> {
    tracing::info!("Running in Single Contact CLI mode.");
    let start_time = Instant::now();
    let name = args.name.as_ref().cloned().unwrap();
    let domain_input = args.domain.as_ref().cloned().unwrap();

    let name_parts: Vec<&str> = name.split_whitespace().collect();
    let first_name = name_parts.first().map(|s| s.to_string());
    let last_name = name_parts.last().map(|s| s.to_string());

    let contact = Contact {
        first_name,
        last_name,
        full_name: Some(name.clone()),
        domain: Some(domain_input.clone()),
        company_domain: None,
        other_fields: std::collections::HashMap::new(),
    };

    tracing::info!(
        "Finding email for Name='{}', Domain='{}' (Mode: {})",
        name,
        domain_input,
        args.mode
    );

    let result = find_single_email(config, sleuth, contact).await;

    if args.stdout {
        print_cli_results(&result, config);
    } else {
        tracing::info!("Saving result to '{}'...", args.output);
        save_results(&[result], &args.output)?;
        tracing::info!("Result saved successfully to '{}'.", args.output);
    }
    tracing::info!("CLI mode finished. Duration: {:.2?}", start_time.elapsed());
    Ok(())
}

async fn process_file_mode(
    config: Arc<Config>,
    sleuth: Arc<EmailSleuth>,
    args: &AppArgs,
    start_time: Instant,
) -> Result<()> {
    tracing::info!(
        "Running in File Processing mode. Input: '{}', Output: '{}' (Mode: {})",
        args.input,
        args.output,
        args.mode
    );
    let input_path = Path::new(&args.input);
    let output_path = Path::new(&args.output);

    if !input_path.exists() || !input_path.is_file() {
        return Err(anyhow::anyhow!(
            "Input file not found or is not a file: {}",
            args.input
        ));
    }
    if let Some(parent_dir) = output_path.parent() {
        if !parent_dir.as_os_str().is_empty() && !parent_dir.exists() {
            tracing::debug!("Creating output directory: {}", parent_dir.display());
            std::fs::create_dir_all(parent_dir).with_context(|| {
                format!(
                    "Failed to create output directory '{}'",
                    parent_dir.display()
                )
            })?;
        }
    }
    File::create(&args.output).with_context(|| {
        format!(
            "Cannot write to output file '{}'. Check permissions.",
            args.output
        )
    })?;
    tracing::debug!("Output path '{}' seems writable.", args.output);

    tracing::info!("Loading contacts from '{}'...", args.input);
    let contacts = load_contacts(&args.input)?;
    let total_records_loaded = contacts.len();
    if total_records_loaded == 0 {
        tracing::warn!(
            "Input file '{}' is empty or contains no valid contacts. Saving empty results file.",
            args.input
        );
        save_results(&[], &args.output)?;
        return Ok(());
    }
    tracing::info!("Loaded {} records from input file.", total_records_loaded);

    tracing::info!(
        "Starting email discovery for {} records (Concurrency: {})...",
        total_records_loaded,
        config.max_concurrency
    );
    let pb = ProgressBar::new(total_records_loaded as u64);
    pb.set_style(ProgressStyle::default_bar()
         .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) | ETA: {eta} | {msg}")
         .context("Failed to set progress bar template")?
         .progress_chars("=> "));
    pb.set_message("Processing contacts...");

    let processed_results_unordered = process_contacts(config.clone(), sleuth, contacts).await;

    pb.set_position(processed_results_unordered.len() as u64); // Ensure bar shows full completion
    pb.finish_with_message(format!(
        "Processed {} records",
        processed_results_unordered.len()
    ));

    let mut processed_results = processed_results_unordered;
    tracing::info!("Sorting {} results...", processed_results.len());
    processed_results.sort_by(|a, b| {
        let domain_a = a
            .contact_input
            .domain
            .as_deref()
            .or(a.contact_input.company_domain.as_deref())
            .unwrap_or("");
        let domain_b = b
            .contact_input
            .domain
            .as_deref()
            .or(b.contact_input.company_domain.as_deref())
            .unwrap_or("");
        let name_a = a.contact_input.full_name.as_deref().unwrap_or("");
        let name_b = b.contact_input.full_name.as_deref().unwrap_or("");
        let lname_a = a.contact_input.last_name.as_deref().unwrap_or("");
        let lname_b = b.contact_input.last_name.as_deref().unwrap_or("");
        let fname_a = a.contact_input.first_name.as_deref().unwrap_or("");
        let fname_b = b.contact_input.first_name.as_deref().unwrap_or("");

        (domain_a, lname_a, fname_a, name_a).cmp(&(domain_b, lname_b, fname_b, name_b))
    });

    tracing::info!("Saving results to '{}'...", args.output);
    save_results(&processed_results, &args.output)?;
    tracing::info!("Results saved successfully.");

    log_summary(
        &processed_results,
        total_records_loaded,
        start_time.elapsed(),
    );

    Ok(())
}

fn load_contacts(file_path: &str) -> Result<Vec<Contact>> {
    tracing::debug!("Opening input file: {}", file_path);
    let file = File::open(file_path)
        .with_context(|| format!("Failed to open input file '{}'", file_path))?;
    let reader = BufReader::new(file);

    tracing::debug!("Parsing JSON from file: {}", file_path);
    let records: Vec<Contact> = serde_json::from_reader(reader).with_context(|| {
        format!(
            "Failed to parse JSON from '{}'. Ensure it's an array of contact objects.",
            file_path
        )
    })?;

    Ok(records)
}

/// Saves the processed results to the specified JSON file.
/// Uses `serde_json` with pretty printing for human readability.
fn save_results(results: &[ProcessingResult], file_path: &str) -> Result<()> {
    tracing::debug!("Creating output file: {}", file_path);
    let file = File::create(file_path)
        .with_context(|| format!("Failed to create/truncate output file '{}'", file_path))?;
    let writer = BufWriter::new(file);

    tracing::debug!(
        "Writing {} results as JSON to file: {}",
        results.len(),
        file_path
    );
    serde_json::to_writer_pretty(writer, results)
        .with_context(|| format!("Failed to serialize results to JSON for '{}'", file_path))?;

    Ok(())
}

/// Logs a summary of the processing results to the console using `tracing::info`.
fn log_summary(processed_results: &[ProcessingResult], original_total: usize, duration: Duration) {
    let total_records_processed_or_skipped = processed_results.len();
    let successful_finds = processed_results
        .iter()
        .filter(|r| r.email.is_some())
        .count();
    let skipped_input = processed_results
        .iter()
        .filter(|r| r.email_finding_skipped)
        .count();
    let processing_errors = processed_results
        .iter()
        .filter(|r| r.email_finding_error.is_some())
        .count();
    let verification_failures = processed_results
        .iter()
        .filter(|r| {
            !r.email_finding_skipped && r.email_finding_error.is_none() && r.email.is_none()
        })
        .count();

    tracing::info!("-------------------- Processing Summary --------------------");
    tracing::info!("Total Records in Input File : {}", original_total);
    tracing::info!(
        "Records Processed/Attempted : {}",
        total_records_processed_or_skipped
    );
    tracing::info!("  - Likely Emails Found     : {}", successful_finds);
    tracing::info!("  - No Email Found/Verified : {}", verification_failures);
    tracing::info!("  - Skipped (Invalid Input) : {}", skipped_input);
    tracing::info!("  - Errors During Processing: {}", processing_errors);
    tracing::info!("Total Time Taken            : {:.2?}", duration);
    if duration.as_secs_f64() > 0.01 && total_records_processed_or_skipped > 0 {
        let rate = (total_records_processed_or_skipped as f64) / duration.as_secs_f64();
        tracing::info!("Processing Rate             : {:.2} records/sec", rate);
    }
    tracing::info!("----------------------------------------------------------");
}

/// Prints results for a single contact to standard output (CLI mode).
fn print_cli_results(result: &ProcessingResult, config: &Config) {
    const BLUE: &str = "\x1b[34m";
    const GREEN: &str = "\x1b[32m";
    const YELLOW: &str = "\x1b[33m";
    const RED: &str = "\x1b[31m";
    const RESET: &str = "\x1b[0m";

    println!("\n{BLUE}===== Email Sleuth Results ====={RESET}");
    println!(
        "Name:   {}",
        result.contact_input.full_name.as_deref().unwrap_or("N/A")
    );
    println!(
        "Domain: {}",
        result
            .contact_input
            .domain
            .as_deref()
            .or(result.contact_input.company_domain.as_deref())
            .unwrap_or("N/A")
    );

    if result.email_finding_skipped {
        println!("\n{YELLOW}Status: SKIPPED{RESET}");
        println!(
            "Reason: {}",
            result.email_finding_reason.as_deref().unwrap_or("Unknown")
        );
    } else if let Some(error) = &result.email_finding_error {
        println!("\n{RED}Status: ERROR{RESET}");
        println!("Error:  {}", error);
    } else if let Some(email) = &result.email {
        println!("\n{GREEN}Status: SUCCESS{RESET}");
        println!("Email:      {GREEN}{}{RESET}", email);
        println!("Confidence: {}/10", result.email_confidence.unwrap_or(0));
        if let Some(ref method) = result.email_verification_method {
            println!("Source:     {}", method);
        }
    } else {
        println!("\n{YELLOW}Status: NO EMAIL FOUND{RESET}");
        if result.email_verification_failed {
            println!(
                "Reason: No candidates met the required confidence threshold after verification."
            );
        } else if result
            .email_discovery_results
            .as_ref()
            .is_none_or(|r| r.found_emails.is_empty())
        {
            println!("Reason: No potential email candidates were generated or found.");
        } else {
            println!("Reason: Unknown (processed without error, but no email selected).");
        }
    }

    if !result.email_alternatives.is_empty() {
        println!(
            "\n{BLUE}Alternative Emails (Confidence > 0, up to {}):{RESET}",
            config.max_alternatives
        );
        for alt in result.email_alternatives.iter() {
            let details = result
                .email_discovery_results
                .as_ref()
                .and_then(|disc_res| {
                    disc_res
                        .found_emails
                        .iter()
                        .find(|fe| fe.email == *alt)
                        .map(|fe| format!(" (Conf: {}, Src: {})", fe.confidence, fe.source))
                })
                .unwrap_or_default();
            println!("- {}{}", alt, details);
        }
    }

    if let Some(ref discovery_results) = result.email_discovery_results {
        if !discovery_results.verification_log.is_empty() {
            println!("\n{BLUE}Verification Log:{RESET}");
            let mut log_entries: Vec<_> = discovery_results.verification_log.iter().collect();
            log_entries.sort_by_key(|(k, _)| *k);
            for (email, message) in log_entries {
                let cleaned_message = message
                    .replace('\n', " ")
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                println!("- {}: {}", email, cleaned_message);
            }
        }
    }

    println!("{BLUE}=============================={RESET}\n");
}
