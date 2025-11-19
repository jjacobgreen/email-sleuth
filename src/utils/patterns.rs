//! Generates potential email address patterns based on names and domain.

use crate::core::config::Config;
use std::collections::HashSet;

/// Removes most non-alphanumeric characters, whitespace, and converts to lowercase.
/// Designed to create usable parts for email local-part generation.
fn sanitize_name_part(part: &str) -> String {
    part.trim()
        .replace(
            |c: char| !(c.is_alphanumeric() || c == '\'' || c == '-'),
            "",
        )
        .to_lowercase()
}

/// Generates a list of common email address patterns for a given name and domain.
///
/// Uses the `email_regex` from the [`Config`] to validate generated patterns.
/// Returns an empty vector if names are empty after sanitization or if the domain is invalid.
pub(crate) fn generate_email_patterns(
    config: &Config,
    first_name: &str,
    last_name: &str,
    domain: &str,
) -> Vec<String> {
    tracing::debug!(
        "Generating patterns for '{} {}' @ '{}'",
        first_name,
        last_name,
        domain
    );

    let first = sanitize_name_part(first_name);
    let last = sanitize_name_part(last_name);

    if first.is_empty() || last.is_empty() {
        tracing::warn!(
            "Cannot generate patterns: Sanitized name parts are empty (Original: '{} {}')",
            first_name,
            last_name
        );
        return Vec::new();
    }
    if domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        tracing::warn!(
            "Cannot generate patterns: Invalid domain provided '{}'",
            domain
        );
        return Vec::new();
    }

    let first_initial = first.chars().next().unwrap_or_default();
    let last_initial = last.chars().next().unwrap_or_default();

    let mut patterns = HashSet::new();

    // Basic name patterns
    patterns.insert(first.clone()); // john
    patterns.insert(last.clone()); // doe
    patterns.insert(format!("{}{}", first, last)); // johndoe
    patterns.insert(format!("{}{}", last, first)); // doejohn
    patterns.insert(format!("{}{}", first_initial, last)); // jdoe
    patterns.insert(format!("{}{}", first, last_initial)); // johnd
    patterns.insert(format!("{}{}", first_initial, last_initial)); // jd

    // Dot separator patterns
    patterns.insert(format!("{}.{}", first, last)); // john.doe
    patterns.insert(format!("{}.{}", last, first)); // doe.john
    patterns.insert(format!("{}.{}", first_initial, last)); // j.doe
    patterns.insert(format!("{}.{}", first, last_initial)); // john.d
    patterns.insert(format!("{}.{}", first_initial, last_initial)); // j.d

    // Underscore separator patterns
    patterns.insert(format!("{}_{}", first, last)); // john_doe
    patterns.insert(format!("{}_{}", last, first)); // doe_john
    patterns.insert(format!("{}_{}", first_initial, last)); // j_doe
    patterns.insert(format!("{}_{}", first, last_initial)); // john_d

    // Dash separator patterns
    patterns.insert(format!("{}-{}", first, last)); // john-doe
    patterns.insert(format!("{}-{}", last, first)); // doe-john
    patterns.insert(format!("{}-{}", first_initial, last)); // j-doe
    patterns.insert(format!("{}-{}", first, last_initial)); // john-d

    // Substring patterns: first 3 letters of first + full last
    if first.chars().count() >= 3 {
        let first_three: String = first.chars().take(3).collect();
        patterns.insert(format!("{}{}", first_three, last));
    }

    // Single-initial patterns
    patterns.insert(first_initial.to_string());
    patterns.insert(last_initial.to_string());

    // Build full email addresses and validate against regex
    let final_patterns: Vec<String> = patterns
        .into_iter()
        .map(|local_part| format!("{}@{}", local_part, domain))
        .filter(|p| {
            let is_match = config.email_regex.is_match(p);
            if !is_match {
                tracing::trace!("Generated pattern failed regex validation: {}", p);
            }
            is_match
        })
        .collect();

    tracing::debug!(
        "Generated {} unique valid patterns for '{} {}' @ '{}'",
        final_patterns.len(),
        first_name,
        last_name,
        domain
    );
    final_patterns
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ConfigBuilder;

    fn test_config() -> Config {
        ConfigBuilder::new()
            .build()
            .expect("Failed to build default config for test")
    }

    #[test]
    fn test_generate_patterns_basic() {
        let config = test_config();
        let patterns = generate_email_patterns(&config, "John", "Doe", "example.com");
        assert!(!patterns.is_empty());
        assert!(patterns.contains(&"john.doe@example.com".to_string()));
        assert!(patterns.contains(&"jdoe@example.com".to_string()));
        assert!(patterns.contains(&"john@example.com".to_string())); // first@domain
        assert!(patterns.contains(&"doe@example.com".to_string())); // last@domain
        assert!(patterns.contains(&"doe.john@example.com".to_string()));
        assert!(patterns.contains(&"johnd@example.com".to_string()));
        assert!(patterns.contains(&"jd@example.com".to_string())); // initials@domain
        assert!(patterns.contains(&"j.d@example.com".to_string())); // initials.dot@domain
        assert!(patterns.len() > 10);
    }

    #[test]
    fn test_generate_patterns_with_hyphen_apostrophe() {
        let config = test_config();
        let patterns = generate_email_patterns(&config, "Jean-Luc", "O'Malley", "starfleet.org");
        assert!(patterns.contains(&"jean-luc.o'malley@starfleet.org".to_string()));
        assert!(patterns.contains(&"j.o'malley@starfleet.org".to_string())); // j<last>
        assert!(patterns.contains(&"jean-luco@starfleet.org".to_string())); // <first>l
        assert!(patterns.contains(&"j.o@starfleet.org".to_string()));
    }

    #[test]
    fn test_generate_patterns_sanitization() {
        let config = test_config();
        let patterns = generate_email_patterns(&config, "  John%$ ", " Doe JR.", "test.co.uk");
        assert!(patterns.contains(&"john.doejr@test.co.uk".to_string()));
        assert!(patterns.contains(&"jdoejr@test.co.uk".to_string()));
        assert!(patterns.contains(&"johnd@test.co.uk".to_string())); // john + d (from doejr)
        assert!(!patterns
            .iter()
            .any(|p| p.contains('%') || p.contains('$') || p.contains(' ')));
    }

    #[test]
    fn test_generate_patterns_empty_invalid_input() {
        let config = test_config();
        assert!(generate_email_patterns(&config, "", "Doe", "example.com").is_empty());
        assert!(generate_email_patterns(&config, "John", "", "example.com").is_empty());
        assert!(generate_email_patterns(&config, "John", "Doe", "").is_empty());
        assert!(generate_email_patterns(&config, "John", "Doe", ".com").is_empty());
        assert!(generate_email_patterns(&config, "John", "Doe", "example.").is_empty());
        assert!(generate_email_patterns(&config, "John", "Doe", "no-dot").is_empty());
        assert!(generate_email_patterns(&config, "  ", "Doe", "example.com").is_empty());
        assert!(generate_email_patterns(&config, "$%^", "Doe", "example.com").is_empty());
    }

    #[test]
    fn test_generate_patterns_duplicates_handled() {
        let config = test_config();
        // If first = last
        let patterns = generate_email_patterns(&config, "Test", "Test", "test.com");
        let count_test_test_dot = patterns
            .iter()
            .filter(|&p| p == "test.test@test.com")
            .count();
        assert_eq!(
            count_test_test_dot, 1,
            "Duplicate pattern 'test.test' should appear once"
        );
        let count_test_test_nodot = patterns
            .iter()
            .filter(|&p| p == "testtest@test.com")
            .count();
        assert_eq!(
            count_test_test_nodot, 1,
            "Duplicate pattern 'testtest' should appear once"
        );
        let count_t_test = patterns.iter().filter(|&p| p == "ttest@test.com").count();
        assert_eq!(
            count_t_test, 1,
            "Duplicate pattern 'ttest' should appear once"
        );
        let count_test_t = patterns.iter().filter(|&p| p == "testt@test.com").count();
        assert_eq!(
            count_test_t, 1,
            "Duplicate pattern 'testt' should appear once"
        );
        let count_t = patterns.iter().filter(|&p| p == "t@test.com").count();
        assert_eq!(
            count_t, 1,
            "Duplicate pattern 't' (initial-only) should appear once"
        );
        let count_tt = patterns.iter().filter(|&p| p == "tt@test.com").count();
        assert_eq!(
            count_tt, 1,
            "Duplicate pattern 'tt' (initials only) should appear once"
        );

        let expected_unique_local_parts = HashSet::from([
            "test",
            "testtest",
            "ttest",
            "testt",
            "tt",
            "t",
            "test.test",
            "t.test",
            "test.t",
            "t.t",
            "test_test",
            "t_test",
            "test_t",
            "test-test",
            "t-test",
            "test-t",
            "testest",
        ]);
        assert_eq!(patterns.len(), expected_unique_local_parts.len());
    }
}
