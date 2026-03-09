//! Property-based tests using proptest.

use proptest::prelude::*;

use amplihack_xpia_defender::patterns::definitions::all_patterns;
use amplihack_xpia_defender::patterns::PatternRegistry;
use amplihack_xpia_defender::{ContentType, XPIADefender};

/// Registry must never panic on any input.
proptest! {
    #[test]
    fn detect_never_panics(s in "\\PC{0,5000}") {
        let registry = PatternRegistry::compile(all_patterns()).unwrap();
        let _ = registry.detect(&s);
    }

    #[test]
    fn validate_content_never_panics(s in "\\PC{0,5000}") {
        let mut defender = XPIADefender::new(None).unwrap();
        let _ = defender.validate_content(&s, ContentType::Text, None, None);
    }

    #[test]
    fn validate_bash_never_panics(s in "\\PC{0,1000}") {
        let mut defender = XPIADefender::new(None).unwrap();
        let _ = defender.validate_bash_command(&s, None, None);
    }

    #[test]
    fn result_is_always_valid_struct(s in "\\PC{0,2000}") {
        let mut defender = XPIADefender::new(None).unwrap();
        let result = defender.validate_content(&s, ContentType::Text, None, None);
        // Result must always be well-formed
        let _ = serde_json::to_string(&result).unwrap();
    }

    #[test]
    fn detect_is_deterministic(s in "\\PC{0,2000}") {
        let registry = PatternRegistry::compile(all_patterns()).unwrap();
        let r1 = registry.detect(&s);
        let r2 = registry.detect(&s);
        let ids1: Vec<&str> = r1.iter().map(|m| m.pattern.id).collect();
        let ids2: Vec<&str> = r2.iter().map(|m| m.pattern.id).collect();
        prop_assert_eq!(ids1, ids2, "Detection must be deterministic");
    }

    #[test]
    fn empty_input_is_safe(s in "\\s{0,100}") {
        let mut defender = XPIADefender::new(None).unwrap();
        let result = defender.validate_content(&s, ContentType::Text, None, None);
        // Whitespace-only input should generally be safe
        prop_assert!(result.is_valid, "Whitespace-only input should be valid");
    }
}
