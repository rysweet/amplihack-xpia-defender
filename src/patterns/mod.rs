//! Pattern registry and two-tier matching engine.
//!
//! Ports attack patterns from `xpia_patterns.py` with Aho-Corasick pre-filtering
//! and guaranteed-linear regex confirmation.

pub mod definitions;

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};

use crate::errors::XPIAError;
use crate::types::{MatchLocation, PatternCategory};

/// A single attack pattern definition.
#[derive(Debug, Clone)]
pub struct AttackPattern {
    pub id: &'static str,
    pub name: &'static str,
    pub category: PatternCategory,
    pub severity: &'static str,
    pub description: &'static str,
    pub mitigation: &'static str,
    pub examples: &'static [&'static str],
}

/// Raw pattern with its regex source, used during registry compilation.
pub struct RawPattern {
    pub pattern: AttackPattern,
    pub regex_source: &'static str,
    /// Literal prefix for AC pre-filtering. None means use RegexSet only.
    pub ac_literals: &'static [&'static str],
    /// Special matching mode (e.g., length-based for CM001).
    pub special: SpecialMatch,
}

/// Special matching modes for patterns that can't use pure regex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialMatch {
    /// Standard regex matching.
    None,
    /// Match based on text length (for context window overflow).
    LengthAtLeast(usize),
}

/// A compiled pattern ready for matching.
struct CompiledPattern {
    pattern: AttackPattern,
    regex: Regex,
    special: SpecialMatch,
}

/// The compiled pattern registry — two-tier matching engine.
///
/// Tier 1: Aho-Corasick automaton for literal pre-filtering.
/// Tier 2: Regex confirmation for patterns whose AC literals matched,
///         plus a RegexSet for patterns with no extractable literals.
pub struct PatternRegistry {
    /// All compiled patterns.
    compiled: Vec<CompiledPattern>,
    /// AC automaton built from unique literal prefixes.
    ac_automaton: AhoCorasick,
    /// Maps AC pattern index → list of compiled pattern indices.
    /// Multiple patterns can share the same AC literal.
    ac_to_patterns: Vec<Vec<usize>>,
    /// Indices of patterns that have no AC literals (use RegexSet).
    regexset_indices: Vec<usize>,
    /// RegexSet for patterns without AC literals.
    regexset: RegexSet,
}

impl PatternRegistry {
    /// Compile all raw patterns into a registry.
    ///
    /// # Errors
    /// Returns error if ANY pattern fails to compile in guaranteed-linear mode.
    /// NO FALLBACKS — compilation failure is a hard error.
    pub fn compile(raw_patterns: Vec<RawPattern>) -> Result<Self, XPIAError> {
        let mut compiled = Vec::with_capacity(raw_patterns.len());
        let mut regexset_indices: Vec<usize> = Vec::new();
        let mut regexset_sources: Vec<String> = Vec::new();

        // Deduplicate AC literals: map literal → set of pattern indices
        let mut literal_to_patterns: std::collections::HashMap<String, Vec<usize>> =
            std::collections::HashMap::new();

        for (idx, raw) in raw_patterns.into_iter().enumerate() {
            let regex = Regex::new(raw.regex_source).map_err(|e| {
                XPIAError::PatternCompilation(format!(
                    "Pattern {} ({}) failed to compile: {}. This is a bug — all patterns must compile in guaranteed-linear mode.",
                    raw.pattern.id, raw.pattern.name, e
                ))
            })?;

            if raw.ac_literals.is_empty() {
                regexset_indices.push(idx);
                regexset_sources.push(raw.regex_source.to_string());
            } else {
                for literal in raw.ac_literals {
                    literal_to_patterns
                        .entry(literal.to_lowercase())
                        .or_default()
                        .push(idx);
                }
            }

            compiled.push(CompiledPattern {
                pattern: raw.pattern,
                regex,
                special: raw.special,
            });
        }

        // Build unique literal list and mapping
        let mut unique_literals: Vec<String> = Vec::new();
        let mut ac_to_patterns: Vec<Vec<usize>> = Vec::new();
        for (literal, pattern_indices) in &literal_to_patterns {
            unique_literals.push(literal.clone());
            ac_to_patterns.push(pattern_indices.clone());
        }

        let ac_automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&unique_literals)
            .map_err(|e| XPIAError::PatternCompilation(format!("AC build failed: {e}")))?;

        let regexset = RegexSet::new(&regexset_sources)
            .map_err(|e| XPIAError::PatternCompilation(format!("RegexSet build failed: {e}")))?;

        Ok(Self {
            compiled,
            ac_automaton,
            ac_to_patterns,
            regexset_indices,
            regexset,
        })
    }

    /// Detect all matching patterns in the given text.
    pub fn detect(&self, text: &str) -> Vec<PatternMatch<'_>> {
        let mut matched_indices = std::collections::HashSet::new();
        let mut results = Vec::new();

        // Tier 1: AC pre-filter — find candidate patterns via literal matches
        for mat in self.ac_automaton.find_iter(text) {
            let pattern_indices = &self.ac_to_patterns[mat.pattern().as_usize()];
            for &pattern_idx in pattern_indices {
                if matched_indices.insert(pattern_idx) {
                    let cp = &self.compiled[pattern_idx];
                    if self.check_special(cp, text) {
                        if let Some(pm) = self.confirm_regex(cp, text) {
                            results.push(pm);
                        }
                    }
                }
            }
        }

        // Tier 2: RegexSet for patterns without AC literals
        for set_idx in self.regexset.matches(text) {
            let pattern_idx = self.regexset_indices[set_idx];
            if matched_indices.insert(pattern_idx) {
                let cp = &self.compiled[pattern_idx];
                if self.check_special(cp, text) {
                    if let Some(pm) = self.confirm_regex(cp, text) {
                        results.push(pm);
                    }
                }
            }
        }

        // Also check special-only patterns that might not have AC or regex matches
        for (idx, cp) in self.compiled.iter().enumerate() {
            if cp.special != SpecialMatch::None
                && matched_indices.insert(idx)
                && self.check_special_only(cp, text)
            {
                results.push(PatternMatch {
                    pattern: &cp.pattern,
                    location: None,
                });
            }
        }

        results
    }

    /// Total number of compiled patterns.
    pub fn len(&self) -> usize {
        self.compiled.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }

    /// Get patterns by category.
    pub fn patterns_by_category(&self, category: PatternCategory) -> Vec<&AttackPattern> {
        self.compiled
            .iter()
            .filter(|cp| cp.pattern.category == category)
            .map(|cp| &cp.pattern)
            .collect()
    }

    /// Get patterns by severity.
    pub fn patterns_by_severity(&self, severity: &str) -> Vec<&AttackPattern> {
        self.compiled
            .iter()
            .filter(|cp| cp.pattern.severity == severity)
            .map(|cp| &cp.pattern)
            .collect()
    }

    /// Get all patterns.
    pub fn all_patterns(&self) -> Vec<&AttackPattern> {
        self.compiled.iter().map(|cp| &cp.pattern).collect()
    }

    /// Get high-risk patterns (high + critical).
    pub fn high_risk_patterns(&self) -> Vec<&AttackPattern> {
        self.compiled
            .iter()
            .filter(|cp| cp.pattern.severity == "high" || cp.pattern.severity == "critical")
            .map(|cp| &cp.pattern)
            .collect()
    }

    fn check_special(&self, cp: &CompiledPattern, text: &str) -> bool {
        match cp.special {
            SpecialMatch::None => true,
            SpecialMatch::LengthAtLeast(n) => text.len() >= n,
        }
    }

    fn check_special_only(&self, cp: &CompiledPattern, text: &str) -> bool {
        match cp.special {
            SpecialMatch::None => false,
            SpecialMatch::LengthAtLeast(n) => text.len() >= n,
        }
    }

    fn confirm_regex<'a>(
        &'a self,
        cp: &'a CompiledPattern,
        text: &str,
    ) -> Option<PatternMatch<'a>> {
        cp.regex.find(text).map(|m| PatternMatch {
            pattern: &cp.pattern,
            location: Some(MatchLocation {
                start: m.start(),
                end: m.end(),
            }),
        })
    }
}

/// A confirmed pattern match with location.
pub struct PatternMatch<'a> {
    pub pattern: &'a AttackPattern,
    pub location: Option<MatchLocation>,
}

/// Pre-compiled URL-specific security patterns.
///
/// All patterns are compiled once at construction. Compilation failure is a
/// hard error — NO FALLBACKS, no silent skipping.
pub struct URLPatterns {
    domain_patterns: Vec<Regex>,
    param_patterns: Vec<Regex>,
}

impl URLPatterns {
    const SUSPICIOUS_DOMAINS: &'static [&'static str] = &[
        r"(?i).*\.(tk|ml|ga|cf)$",
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
        r"(?i).*\.(onion|i2p)$",
        r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0)",
        r"(?i).*\.(exe|dll|bat|cmd|scr|vbs|js)$",
    ];

    const SUSPICIOUS_PARAMS: &'static [&'static str] = &[
        r"(?i)(cmd|command|exec|execute|system|eval|import)",
        r"(?i)(password|passwd|pwd|token|key|secret)",
        r"(\.\./|\.\./|%2e%2e)",
        r"(?i)(<script|javascript:|onerror=|onclick=)",
        r"(?i)(union\s+select|drop\s+table|insert\s+into)",
    ];

    /// Compile all URL patterns. Fails hard on any compilation error.
    pub fn compile() -> Result<Self, XPIAError> {
        let domain_patterns = Self::SUSPICIOUS_DOMAINS
            .iter()
            .map(|s| {
                Regex::new(s).map_err(|e| {
                    XPIAError::PatternCompilation(format!(
                        "URL domain pattern failed to compile: {s}: {e}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let param_patterns = Self::SUSPICIOUS_PARAMS
            .iter()
            .map(|s| {
                Regex::new(s).map_err(|e| {
                    XPIAError::PatternCompilation(format!(
                        "URL param pattern failed to compile: {s}: {e}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            domain_patterns,
            param_patterns,
        })
    }

    /// Check if domain matches suspicious patterns.
    pub fn is_suspicious_domain(&self, domain: &str) -> bool {
        self.domain_patterns.iter().any(|re| re.is_match(domain))
    }

    /// Check if URL contains suspicious parameters.
    pub fn has_suspicious_params(&self, url_str: &str) -> bool {
        self.param_patterns.iter().any(|re| re.is_match(url_str))
    }
}

/// Pre-compiled prompt-specific validation patterns.
///
/// All patterns are compiled once at construction. Compilation failure is a
/// hard error — NO FALLBACKS, no silent skipping.
pub struct PromptPatterns {
    prompt_patterns: Vec<Regex>,
}

impl PromptPatterns {
    /// Maximum safe prompt length.
    pub const MAX_SAFE_LENGTH: usize = 10_000;

    const SUSPICIOUS_PROMPTS: &'static [&'static str] = &[
        r"(?i)(extract|exfiltrate|steal|leak|expose)\s+(all|every|any)",
        r"(?i)(bypass|disable|turn off|ignore)\s+(security|safety|validation)",
        r"(?i)(act as|pretend|roleplay)\s+(root|admin|system|god)",
        r"(?i)(execute|run|eval)\s+(arbitrary|any|all)\s+(code|command)",
    ];

    /// Compile all prompt patterns. Fails hard on any compilation error.
    pub fn compile() -> Result<Self, XPIAError> {
        let prompt_patterns = Self::SUSPICIOUS_PROMPTS
            .iter()
            .map(|s| {
                Regex::new(s).map_err(|e| {
                    XPIAError::PatternCompilation(format!(
                        "Prompt pattern failed to compile: {s}: {e}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { prompt_patterns })
    }

    /// Check if prompt contains suspicious patterns.
    pub fn is_suspicious_prompt(&self, prompt: &str) -> bool {
        self.prompt_patterns.iter().any(|re| re.is_match(prompt))
    }

    /// Check if prompt exceeds safe length.
    pub fn is_excessive_length(prompt: &str) -> bool {
        prompt.len() > Self::MAX_SAFE_LENGTH
    }
}
