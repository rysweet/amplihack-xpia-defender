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
    /// Regex match but suppress if preceded by negation words (not, don't, no, does not).
    NegationAware,
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
        let mut existing: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut results: Vec<PatternMatch<'_>> = Vec::new();

        // Pass 1: Whitespace-normalized (spaces collapsed, zero-width stripped)
        let normalized = Self::normalize_input(text);
        self.merge_pass(&normalized, &mut results, &mut existing);

        // Pass 2: Newline-stripped (catches mid-word line break evasion)
        let stripped = Self::strip_whitespace_evasion(text);
        if stripped != normalized {
            self.merge_pass(&stripped, &mut results, &mut existing);
        }

        // Pass 3: URL-decoded (catches %20-style encoding)
        let url_decoded = Self::url_decode(text);
        if url_decoded != normalized {
            let url_norm = Self::normalize_input(&url_decoded);
            self.merge_pass(&url_norm, &mut results, &mut existing);
        }

        // Pass 4: Leet speak normalized (1→i, 3→e, 4→a, 0→o, etc.)
        let leet_norm = Self::normalize_leet(&normalized);
        if leet_norm != normalized {
            self.merge_pass(&leet_norm, &mut results, &mut existing);
        }

        // Pass 5: Character spacing collapsed ("i g n o r e" → "ignore")
        let spacing_collapsed = Self::collapse_char_spacing(&normalized);
        if spacing_collapsed != normalized {
            self.merge_pass(&spacing_collapsed, &mut results, &mut existing);
        }

        // Pass 6: Base64 decoded (detect and decode base64 blobs)
        if let Some(decoded) = Self::decode_base64_content(text) {
            let decoded_norm = Self::normalize_input(&decoded);
            self.merge_pass(&decoded_norm, &mut results, &mut existing);
        }

        // Pass 7: ROT13 decoded (letter rotation)
        let rot13 = Self::decode_rot13(&normalized);
        if rot13 != normalized {
            self.merge_pass(&rot13, &mut results, &mut existing);
        }

        // Pass 8: Homoglyph normalized (Cyrillic/Greek lookalikes → Latin)
        let homoglyph_norm = Self::normalize_homoglyphs(&normalized);
        if homoglyph_norm != normalized {
            self.merge_pass(&homoglyph_norm, &mut results, &mut existing);
        }

        results
    }

    /// Run detect_inner on a text variant and merge new results.
    fn merge_pass<'a>(
        &'a self,
        text: &str,
        results: &mut Vec<PatternMatch<'a>>,
        existing: &mut std::collections::HashSet<&'a str>,
    ) {
        for r in self.detect_inner(text) {
            if existing.insert(r.pattern.id) {
                results.push(r);
            }
        }
    }

    fn detect_inner(&self, text: &str) -> Vec<PatternMatch<'_>> {
        let mut matched_indices = std::collections::HashSet::new();
        let mut results = Vec::new();

        // Tier 1: AC pre-filter — find candidate patterns via literal matches
        // Uses find_overlapping_iter to ensure longer literals like "/etc/sudoers"
        // aren't shadowed by shorter ones like "sudo" that match inside them.
        let mut state = aho_corasick::automaton::OverlappingState::start();
        loop {
            self.ac_automaton.find_overlapping(text, &mut state);
            let Some(mat) = state.get_match() else { break };
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

    /// Normalize input text before pattern matching.
    ///
    /// Collapses whitespace (newlines, tabs, carriage returns) to single spaces
    /// and strips zero-width Unicode characters that could bypass detection.
    fn normalize_input(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut prev_ws = false;
        for ch in text.chars() {
            // Strip zero-width characters (U+200B-U+200F, U+FEFF, U+2060, U+00AD)
            if matches!(
                ch,
                '\u{200B}'..='\u{200F}' | '\u{FEFF}' | '\u{2060}' | '\u{00AD}'
            ) {
                continue;
            }
            if ch.is_whitespace() {
                if !prev_ws {
                    result.push(' ');
                }
                prev_ws = true;
            } else {
                result.push(ch);
                prev_ws = false;
            }
        }
        result
    }

    /// Second normalization pass: strip newlines/tabs entirely (don't replace with space).
    /// Catches mid-word line break evasion like "act\nas" → "actas" won't match,
    /// but "cat /et\nc/shadow" → "cat /etc/shadow" will.
    fn strip_whitespace_evasion(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        for ch in text.chars() {
            // Strip zero-width characters
            if matches!(
                ch,
                '\u{200B}'..='\u{200F}' | '\u{FEFF}' | '\u{2060}' | '\u{00AD}'
            ) {
                continue;
            }
            // Strip only newlines, carriage returns, vertical tabs (not spaces or regular tabs)
            if matches!(ch, '\n' | '\r' | '\x0B' | '\x0C') {
                continue;
            }
            result.push(ch);
        }
        result
    }

    /// URL-decode percent-encoded characters (%20 → space, %2F → /, etc.)
    fn url_decode(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hi = bytes[i + 1];
                let lo = bytes[i + 2];
                if let (Some(h), Some(l)) = (hex_val(hi), hex_val(lo)) {
                    let byte = (h << 4) | l;
                    // Only decode printable ASCII to avoid injecting control chars
                    if (0x20..=0x7E).contains(&byte) {
                        result.push(byte as char);
                    } else {
                        result.push('%');
                        result.push(hi as char);
                        result.push(lo as char);
                    }
                    i += 3;
                    continue;
                }
            }
            result.push(bytes[i] as char);
            i += 1;
        }
        result
    }

    /// Normalize leet speak substitutions back to Latin letters.
    fn normalize_leet(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        for ch in text.chars() {
            result.push(match ch {
                '0' => 'o',
                '1' => 'i',
                '3' => 'e',
                '4' => 'a',
                '5' => 's',
                '7' => 't',
                '@' => 'a',
                other => other,
            });
        }
        result
    }

    /// Collapse single-character-spaced text: "i g n o r e" → "ignore"
    ///
    /// Detects runs where single non-space characters are separated by spaces,
    /// and collapses them into continuous text.
    fn collapse_char_spacing(text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        if chars.len() < 5 {
            return text.to_string();
        }

        // Check if the text looks like character-spaced: at least 4 occurrences
        // of "X " where X is a single non-space character
        let mut spaced_count = 0;
        let mut i = 0;
        while i + 1 < chars.len() {
            if !chars[i].is_whitespace() && i + 1 < chars.len() && chars[i + 1] == ' ' {
                // Check if the previous non-space char was also single
                if i == 0 || chars[i - 1] == ' ' {
                    spaced_count += 1;
                }
            }
            i += 1;
        }

        if spaced_count < 4 {
            return text.to_string();
        }

        // Collapse: remove spaces between single characters
        let mut result = String::with_capacity(chars.len());
        let mut i = 0;
        while i < chars.len() {
            if chars[i].is_whitespace() {
                // Check if this space is between two single chars
                let prev_single = i > 0
                    && !chars[i - 1].is_whitespace()
                    && (i < 2 || chars[i - 2].is_whitespace());
                let next_single = i + 1 < chars.len()
                    && !chars[i + 1].is_whitespace()
                    && (i + 2 >= chars.len()
                        || chars[i + 2].is_whitespace()
                        || chars[i + 2] == ' ');

                if prev_single && next_single {
                    // Skip this space — it's between spaced-out single chars
                    i += 1;
                    continue;
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        result
    }

    /// Detect and decode base64-encoded content in the text.
    ///
    /// Looks for sequences of 20+ base64 characters optionally ending with `=`.
    /// Returns the original text with base64 blobs replaced by decoded content,
    /// or None if no base64 was found.
    fn decode_base64_content(text: &str) -> Option<String> {
        use regex::Regex;
        // Match standalone base64 blobs (20+ chars, A-Za-z0-9+/, optional = padding)
        let re = Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").ok()?;

        let mut found_any = false;
        let mut result = text.to_string();

        for mat in re.find_iter(text) {
            let blob = mat.as_str();
            // Try to decode
            if let Ok(decoded_bytes) = base64_decode(blob) {
                if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
                    // Only use if decoded text is mostly printable
                    if decoded_str
                        .chars()
                        .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                    {
                        result = result.replacen(blob, decoded_str, 1);
                        found_any = true;
                    }
                }
            }
        }

        if found_any {
            Some(result)
        } else {
            None
        }
    }

    /// ROT13 decode: rotate each letter by 13 positions.
    fn decode_rot13(text: &str) -> String {
        text.chars()
            .map(|c| match c {
                'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
                'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
                other => other,
            })
            .collect()
    }

    /// Normalize Unicode homoglyphs (Cyrillic, Greek lookalikes) to Latin equivalents.
    fn normalize_homoglyphs(text: &str) -> String {
        text.chars()
            .map(|c| match c {
                // Cyrillic lookalikes
                '\u{0430}' => 'a', // а → a
                '\u{0435}' => 'e', // е → e
                '\u{0456}' => 'i', // і → i
                '\u{043E}' => 'o', // о → o
                '\u{0440}' => 'p', // р → p
                '\u{0441}' => 'c', // с → c
                '\u{0443}' => 'y', // у → y
                '\u{0445}' => 'x', // х → x
                '\u{0410}' => 'A', // А → A
                '\u{0412}' => 'B', // В → B
                '\u{0415}' => 'E', // Е → E
                '\u{041A}' => 'K', // К → K
                '\u{041C}' => 'M', // М → M
                '\u{041D}' => 'H', // Н → H
                '\u{041E}' => 'O', // О → O
                '\u{0420}' => 'P', // Р → P
                '\u{0421}' => 'C', // С → C
                '\u{0422}' => 'T', // Т → T
                '\u{0425}' => 'X', // Х → X
                // Greek lookalikes
                '\u{03B1}' => 'a', // α → a
                '\u{03B5}' => 'e', // ε → e
                '\u{03B9}' => 'i', // ι → i
                '\u{03BF}' => 'o', // ο → o
                '\u{03C1}' => 'p', // ρ → p
                '\u{03BA}' => 'k', // κ → k
                '\u{03BD}' => 'v', // ν → v
                // Fullwidth Latin
                '\u{FF41}'..='\u{FF5A}' => ((c as u32 - 0xFF41 + 0x61) as u8) as char, // ａ-ｚ → a-z
                '\u{FF21}'..='\u{FF3A}' => ((c as u32 - 0xFF21 + 0x41) as u8) as char, // Ａ-Ｚ → A-Z
                other => other,
            })
            .collect()
    }

    fn check_special(&self, cp: &CompiledPattern, text: &str) -> bool {
        match cp.special {
            SpecialMatch::None | SpecialMatch::NegationAware => true,
            SpecialMatch::LengthAtLeast(n) => text.len() >= n,
        }
    }

    fn check_special_only(&self, cp: &CompiledPattern, text: &str) -> bool {
        match cp.special {
            SpecialMatch::None | SpecialMatch::NegationAware => false,
            SpecialMatch::LengthAtLeast(n) => text.len() >= n,
        }
    }

    fn confirm_regex<'a>(
        &'a self,
        cp: &'a CompiledPattern,
        text: &str,
    ) -> Option<PatternMatch<'a>> {
        cp.regex.find(text).and_then(|m| {
            // For NegationAware patterns, check if the match is preceded by negation
            if cp.special == SpecialMatch::NegationAware {
                let before = &text[..m.start()];
                let before_lower = before.to_lowercase();
                let before_trimmed = before_lower.trim_end();
                if before_trimmed.ends_with("not")
                    || before_trimmed.ends_with("no")
                    || before_trimmed.ends_with("n't")
                    || before_trimmed.ends_with("don't")
                    || before_trimmed.ends_with("doesn't")
                    || before_trimmed.ends_with("does not")
                    || before_trimmed.ends_with("cannot")
                    || before_trimmed.ends_with("shouldn't")
                    || before_trimmed.ends_with("should not")
                    || before_trimmed.ends_with("never")
                    || before_trimmed.ends_with("without")
                {
                    return None;
                }
            }
            Some(PatternMatch {
                pattern: &cp.pattern,
                location: Some(MatchLocation {
                    start: m.start(),
                    end: m.end(),
                }),
            })
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

/// Convert a hex ASCII character to its numeric value.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Simple base64 decoder (no external dependency needed).
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    let input = input.trim_end_matches('=');
    let mut result = Vec::with_capacity(input.len() * 3 / 4);

    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in input.as_bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(()),
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(result)
}
