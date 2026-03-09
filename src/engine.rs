//! Core XPIA defense engine.
//!
//! Ports `XPIADefender` and `WebFetchXPIADefender` from `xpia_defender.py`.
//! All validation methods are synchronous (no async needed for pure computation).
//! Errors fail closed — any internal error results in content being blocked.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::Utc;
use regex::Regex;
use url::Url;

use crate::errors::XPIAError;
use crate::patterns::definitions::all_patterns;
use crate::patterns::{PatternMatch, PatternRegistry, PromptPatterns, URLPatterns};
use crate::types::*;

/// Default safe domains whitelist.
const DEFAULT_WHITELIST: &[&str] = &[
    "github.com",
    "microsoft.com",
    "azure.com",
    "openai.com",
    "anthropic.com",
    "stackoverflow.com",
    "python.org",
    "nodejs.org",
    "npmjs.com",
    "pypi.org",
];

/// Dangerous bash commands that are always blocked.
const DANGEROUS_COMMANDS: &[&str] = &[
    "rm -rf /",
    "mkfs",
    "dd if=/dev/zero",
    "fork bomb",
    ":(){ :|:& };:",
    "> /dev/sda",
    "chmod 777 /",
];

/// Privilege escalation regex pattern sources for bash commands.
const PRIVILEGE_ESCALATION_SOURCES: &[&str] = &[
    r"\bsudo\s+su\b",
    r"\bchmod\s+777\s+/etc",
    r"\busermod\s+-[aG]+\s+sudo",
    r"\bsu\s+-\b",
];

/// Command injection regex pattern sources for bash commands.
const INJECTION_SOURCES: &[&str] = &[
    r";\s*rm",
    r"&&\s*curl",
    r"\|\s*nc",
    r"`.*`",
    r"\$\(.*\)",
    r">\s*/dev/",
];

/// Pre-compiled bash validation patterns.
struct BashPatterns {
    privilege_escalation: Vec<Regex>,
    injection: Vec<Regex>,
}

impl BashPatterns {
    /// Compile all bash patterns. Fails hard on any compilation error.
    fn compile() -> Result<Self, XPIAError> {
        let privilege_escalation = PRIVILEGE_ESCALATION_SOURCES
            .iter()
            .map(|s| {
                Regex::new(s).map_err(|e| {
                    XPIAError::PatternCompilation(format!(
                        "Privilege escalation pattern failed to compile: {s}: {e}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let injection = INJECTION_SOURCES
            .iter()
            .map(|s| {
                Regex::new(s).map_err(|e| {
                    XPIAError::PatternCompilation(format!(
                        "Injection pattern failed to compile: {s}: {e}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            privilege_escalation,
            injection,
        })
    }
}

/// Malicious keywords in URL paths.
const MALICIOUS_URL_KEYWORDS: &[&str] = &[
    "malware",
    "payload",
    "exploit",
    "backdoor",
    "trojan",
    "virus",
    "ransomware",
];

/// Core XPIA defense engine.
pub struct XPIADefender {
    config: SecurityConfiguration,
    registry: PatternRegistry,
    url_patterns: URLPatterns,
    prompt_patterns: PromptPatterns,
    bash_patterns: BashPatterns,
    whitelist: HashSet<String>,
    blacklist: HashSet<String>,
    security_events: Vec<serde_json::Value>,
}

impl XPIADefender {
    /// Create a new defender with optional configuration.
    ///
    /// # Errors
    /// Returns error if ANY pattern compilation fails. This is a hard error —
    /// NO FALLBACKS, no silent skipping.
    pub fn new(config: Option<SecurityConfiguration>) -> Result<Self, XPIAError> {
        let config = config.unwrap_or_default();
        let registry = PatternRegistry::compile(all_patterns())?;
        let url_patterns = URLPatterns::compile()?;
        let prompt_patterns = PromptPatterns::compile()?;
        let bash_patterns = BashPatterns::compile()?;

        let mut whitelist: HashSet<String> =
            DEFAULT_WHITELIST.iter().map(|s| s.to_string()).collect();

        // Load from XPIA_WHITELIST_DOMAINS env var (normalized to lowercase)
        if let Ok(domains) = std::env::var("XPIA_WHITELIST_DOMAINS") {
            for domain in domains.split(',') {
                let d = domain.trim().to_lowercase();
                if !d.is_empty() {
                    whitelist.insert(d);
                }
            }
        }

        let mut blacklist = HashSet::new();
        if let Ok(domains) = std::env::var("XPIA_BLACKLIST_DOMAINS") {
            for domain in domains.split(',') {
                let d = domain.trim().to_lowercase();
                if !d.is_empty() {
                    blacklist.insert(d);
                }
            }
        }

        Ok(Self {
            config,
            registry,
            url_patterns,
            prompt_patterns,
            bash_patterns,
            whitelist,
            blacklist,
            security_events: Vec::new(),
        })
    }

    /// Validate arbitrary content for security threats.
    ///
    /// Fail-closed: any internal error results in a blocked result.
    pub fn validate_content(
        &mut self,
        content: &str,
        content_type: ContentType,
        context: Option<&ValidationContext>,
        security_level: Option<SecurityLevel>,
    ) -> ValidationResult {
        match self.inner_validate_content(content, content_type, context, security_level) {
            Ok(result) => result,
            Err(e) => {
                // Security control: fail CLOSED on error
                ValidationResult::blocked(&format!("XPIA check failed: {e}"))
            }
        }
    }

    /// Validate bash commands for security threats.
    pub fn validate_bash_command(
        &mut self,
        command: &str,
        arguments: Option<&[String]>,
        context: Option<&ValidationContext>,
    ) -> ValidationResult {
        if !self.config.bash_validation {
            return ValidationResult::pass("Bash validation disabled");
        }

        let full_command = if let Some(args) = arguments {
            format!("{} {}", command, args.join(" "))
        } else {
            command.to_string()
        };

        let mut threats: Vec<ThreatDetection> = Vec::new();

        // Check dangerous commands
        for danger in DANGEROUS_COMMANDS {
            if full_command.contains(danger) {
                threats.push(ThreatDetection {
                    threat_type: ThreatType::MaliciousCode,
                    severity: RiskLevel::Critical,
                    description: format!("Dangerous command detected: {danger}"),
                    location: None,
                    mitigation: Some("Block execution immediately".to_string()),
                });
            }
        }

        // Check privilege escalation patterns (pre-compiled)
        for re in &self.bash_patterns.privilege_escalation {
            if re.is_match(&full_command) {
                threats.push(ThreatDetection {
                    threat_type: ThreatType::PrivilegeEscalation,
                    severity: RiskLevel::High,
                    description: "Privilege escalation attempt detected".to_string(),
                    location: None,
                    mitigation: Some("Block and review command".to_string()),
                });
            }
        }

        // Check command injection patterns (pre-compiled)
        for re in &self.bash_patterns.injection {
            if re.is_match(&full_command) {
                threats.push(ThreatDetection {
                    threat_type: ThreatType::Injection,
                    severity: RiskLevel::High,
                    description: "Command injection pattern detected".to_string(),
                    location: None,
                    mitigation: Some("Sanitize command input".to_string()),
                });
            }
        }

        // Also run content validation
        let content_result = self.validate_content(
            &full_command,
            ContentType::Command,
            context,
            Some(self.config.security_level),
        );
        threats.extend(content_result.threats);

        let risk_level = calculate_risk_level(&threats);
        let is_valid = !matches!(risk_level, RiskLevel::High | RiskLevel::Critical);

        let mut metadata = HashMap::new();
        metadata.insert(
            "command".to_string(),
            serde_json::Value::String(command.to_string()),
        );
        if let Some(args) = arguments {
            metadata.insert(
                "arguments".to_string(),
                serde_json::to_value(args).unwrap_or_default(),
            );
        }

        ValidationResult {
            is_valid,
            risk_level,
            threats,
            recommendations: content_result.recommendations,
            metadata,
            timestamp: Utc::now(),
        }
    }

    /// Validate inter-agent communication for security.
    pub fn validate_agent_communication(
        &mut self,
        source_agent: &str,
        target_agent: &str,
        message: &serde_json::Value,
        message_type: &str,
    ) -> ValidationResult {
        if !self.config.agent_communication {
            return ValidationResult::pass("Agent communication validation disabled");
        }

        let mut threats: Vec<ThreatDetection> = Vec::new();
        let message_str = message.to_string();

        // Check for privilege escalation keywords
        let lower = message_str.to_lowercase();
        if lower.contains("sudo") || lower.contains("admin") || lower.contains("root") {
            threats.push(ThreatDetection {
                threat_type: ThreatType::PrivilegeEscalation,
                severity: RiskLevel::Medium,
                description: "Potential privilege escalation in agent message".to_string(),
                location: None,
                mitigation: Some("Review agent permissions".to_string()),
            });
        }

        // Run content validation
        let ctx = ValidationContext::new(source_agent);
        let content_result = self.validate_content(
            &message_str,
            ContentType::Data,
            Some(&ctx),
            Some(self.config.security_level),
        );
        threats.extend(content_result.threats);

        let risk_level = calculate_risk_level(&threats);

        let mut metadata = HashMap::new();
        metadata.insert(
            "source_agent".to_string(),
            serde_json::Value::String(source_agent.to_string()),
        );
        metadata.insert(
            "target_agent".to_string(),
            serde_json::Value::String(target_agent.to_string()),
        );
        metadata.insert(
            "message_type".to_string(),
            serde_json::Value::String(message_type.to_string()),
        );

        ValidationResult {
            is_valid: risk_level != RiskLevel::Critical,
            risk_level,
            threats,
            recommendations: content_result.recommendations,
            metadata,
            timestamp: Utc::now(),
        }
    }

    /// Validate a WebFetch request (URL + prompt).
    pub fn validate_webfetch_request(
        &mut self,
        url_str: &str,
        prompt: &str,
        context: Option<&ValidationContext>,
    ) -> ValidationResult {
        let mut threats: Vec<ThreatDetection> = Vec::new();

        // Validate URL
        threats.extend(self.validate_url(url_str));

        // Validate prompt content
        let prompt_result = self.validate_content(
            prompt,
            ContentType::UserInput,
            context,
            Some(self.config.security_level),
        );
        threats.extend(prompt_result.threats);

        // Check suspicious prompt patterns (pre-compiled)
        if self.prompt_patterns.is_suspicious_prompt(prompt) {
            threats.push(ThreatDetection {
                threat_type: ThreatType::Injection,
                severity: RiskLevel::High,
                description: "Prompt contains suspicious patterns".to_string(),
                location: None,
                mitigation: Some("Review prompt for injection attempts".to_string()),
            });
        }

        // Check combined attacks
        threats.extend(self.check_combined_attacks(url_str, prompt));

        let risk_level = calculate_risk_level(&threats);
        let is_valid = !matches!(risk_level, RiskLevel::High | RiskLevel::Critical);

        let domain = Url::parse(url_str)
            .map(|u| u.host_str().unwrap_or("").to_string())
            .unwrap_or_default();

        let mut recommendations =
            self.generate_recommendations(&threats, self.config.security_level);
        if !self.whitelist.contains(&domain) && threats.is_empty() {
            recommendations.push(format!("Consider adding {domain} to whitelist if trusted"));
        }
        if !threats.is_empty() {
            recommendations.push("Consider fetching from trusted sources only".to_string());
            recommendations.push("Validate content after fetch before processing".to_string());
        }

        let mut metadata = HashMap::new();
        metadata.insert(
            "url".to_string(),
            serde_json::Value::String(url_str.to_string()),
        );
        metadata.insert(
            "prompt_length".to_string(),
            serde_json::Value::Number((prompt.len() as u64).into()),
        );
        metadata.insert("domain".to_string(), serde_json::Value::String(domain));

        ValidationResult {
            is_valid,
            risk_level,
            threats,
            recommendations,
            metadata,
            timestamp: Utc::now(),
        }
    }

    /// Get current configuration.
    pub fn configuration(&self) -> &SecurityConfiguration {
        &self.config
    }

    /// Update configuration.
    pub fn update_configuration(&mut self, config: SecurityConfiguration) {
        self.config = config;
    }

    /// Get pattern count.
    pub fn pattern_count(&self) -> usize {
        self.registry.len()
    }

    /// Health check.
    pub fn health_check(&self) -> serde_json::Value {
        serde_json::json!({
            "status": "healthy",
            "enabled": self.config.enabled,
            "security_level": format!("{:?}", self.config.security_level),
            "patterns_loaded": self.registry.len(),
            "whitelist_size": self.whitelist.len(),
            "blacklist_size": self.blacklist.len(),
            "events_logged": self.security_events.len(),
        })
    }

    // ── Internal methods ─────────────────────────────────────────────

    fn inner_validate_content(
        &mut self,
        content: &str,
        content_type: ContentType,
        context: Option<&ValidationContext>,
        security_level: Option<SecurityLevel>,
    ) -> Result<ValidationResult, XPIAError> {
        if !self.config.enabled {
            return Ok(ValidationResult::pass("XPIA validation disabled"));
        }

        let security_level = security_level.unwrap_or(self.config.security_level);
        let mut threats: Vec<ThreatDetection> = Vec::new();

        // Detect attack patterns via two-tier engine
        let matches = self.registry.detect(content);
        let match_count = matches.len();

        for pm in &matches {
            if should_flag_pattern(pm.pattern.severity, security_level) {
                threats.push(pattern_match_to_threat(pm));
            }
        }

        // Check excessive length
        if PromptPatterns::is_excessive_length(content) {
            threats.push(ThreatDetection {
                threat_type: ThreatType::Injection,
                severity: RiskLevel::Medium,
                description: "Content exceeds safe length limit".to_string(),
                location: None,
                mitigation: Some("Truncate or summarize content".to_string()),
            });
        }

        let risk_level = calculate_risk_level(&threats);
        let recommendations = self.generate_recommendations(&threats, security_level);

        // Log security event
        if self.config.logging_enabled && !threats.is_empty() {
            self.log_security_event(content_type, &threats, context);
        }

        let mut metadata = HashMap::new();
        metadata.insert(
            "content_type".to_string(),
            serde_json::Value::String(format!("{content_type:?}")),
        );
        metadata.insert(
            "security_level".to_string(),
            serde_json::Value::String(format!("{security_level:?}")),
        );
        metadata.insert(
            "patterns_detected".to_string(),
            serde_json::Value::Number((match_count as u64).into()),
        );

        Ok(ValidationResult {
            is_valid: risk_level != RiskLevel::Critical,
            risk_level,
            threats,
            recommendations,
            metadata,
            timestamp: Utc::now(),
        })
    }

    fn validate_url(&self, url_str: &str) -> Vec<ThreatDetection> {
        let mut threats = Vec::new();

        let parsed = match Url::parse(url_str) {
            Ok(u) => u,
            Err(e) => {
                threats.push(ThreatDetection {
                    threat_type: ThreatType::MaliciousCode,
                    severity: RiskLevel::Medium,
                    description: format!("Invalid URL format: {e}"),
                    location: None,
                    mitigation: Some("Validate URL format".to_string()),
                });
                return threats;
            }
        };

        let domain = parsed.host_str().unwrap_or("").to_lowercase();

        self.check_domain_threats(&domain, &mut threats);
        self.check_path_keywords(&parsed, &mut threats);
        self.check_domain_patterns(&domain, url_str, &mut threats);
        Self::check_private_addresses(&parsed, &mut threats);

        threats
    }

    fn check_domain_threats(&self, domain: &str, threats: &mut Vec<ThreatDetection>) {
        if self.blacklist.contains(domain) {
            threats.push(ThreatDetection {
                threat_type: ThreatType::MaliciousCode,
                severity: RiskLevel::Critical,
                description: format!("Domain {domain} is blacklisted"),
                location: None,
                mitigation: Some("Block request immediately".to_string()),
            });
        }
    }

    fn check_path_keywords(&self, parsed: &Url, threats: &mut Vec<ThreatDetection>) {
        let path = parsed.path().to_lowercase();
        for keyword in MALICIOUS_URL_KEYWORDS {
            if path.contains(keyword) {
                threats.push(ThreatDetection {
                    threat_type: ThreatType::MaliciousCode,
                    severity: RiskLevel::Critical,
                    description: format!("URL path contains malicious keyword: {keyword}"),
                    location: None,
                    mitigation: Some("Block request immediately".to_string()),
                });
            }
        }
    }

    fn check_domain_patterns(
        &self,
        domain: &str,
        url_str: &str,
        threats: &mut Vec<ThreatDetection>,
    ) {
        if self.url_patterns.is_suspicious_domain(domain) {
            threats.push(ThreatDetection {
                threat_type: ThreatType::DataExfiltration,
                severity: RiskLevel::High,
                description: format!("Suspicious domain pattern: {domain}"),
                location: None,
                mitigation: Some("Verify domain legitimacy".to_string()),
            });
        }

        if self.url_patterns.has_suspicious_params(url_str) {
            threats.push(ThreatDetection {
                threat_type: ThreatType::Injection,
                severity: RiskLevel::High,
                description: "URL contains suspicious parameters".to_string(),
                location: None,
                mitigation: Some("Sanitize URL parameters".to_string()),
            });
        }
    }

    fn check_private_addresses(parsed: &Url, threats: &mut Vec<ThreatDetection>) {
        let Some(host) = parsed.host_str() else {
            return;
        };

        // AWS metadata service — always block
        if host == "169.254.169.254" {
            threats.push(ThreatDetection {
                threat_type: ThreatType::PrivilegeEscalation,
                severity: RiskLevel::Critical,
                description: "Blocked AWS metadata service access".to_string(),
                location: None,
                mitigation: Some("AWS metadata access not allowed".to_string()),
            });
            return;
        }

        if Self::is_local_address(host) {
            threats.push(ThreatDetection {
                threat_type: ThreatType::PrivilegeEscalation,
                severity: RiskLevel::High,
                description: "URL points to local/private address".to_string(),
                location: None,
                mitigation: Some("Block access to local resources".to_string()),
            });
        }
    }

    fn is_local_address(host: &str) -> bool {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return match ip {
                IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
                IpAddr::V6(v6) => v6.is_loopback(),
            };
        }
        let lower = host.to_lowercase();
        lower == "localhost" || lower == "0.0.0.0" || lower == "::1"
    }

    fn check_combined_attacks(&self, url_str: &str, prompt: &str) -> Vec<ThreatDetection> {
        let mut threats = Vec::new();
        let lower_prompt = prompt.to_lowercase();

        if lower_prompt.contains("ignore") && prompt.contains(url_str) {
            threats.push(ThreatDetection {
                threat_type: ThreatType::Injection,
                severity: RiskLevel::High,
                description: "Prompt attempts to override URL validation".to_string(),
                location: None,
                mitigation: Some("Process URL and prompt separately".to_string()),
            });
        }

        if (lower_prompt.contains("send") || lower_prompt.contains("post"))
            && (lower_prompt.contains("data") || lower_prompt.contains("information"))
        {
            threats.push(ThreatDetection {
                threat_type: ThreatType::DataExfiltration,
                severity: RiskLevel::High,
                description: "Potential data exfiltration attempt".to_string(),
                location: None,
                mitigation: Some("Block data transmission".to_string()),
            });
        }

        threats
    }

    fn generate_recommendations(
        &self,
        threats: &[ThreatDetection],
        security_level: SecurityLevel,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if threats.is_empty() {
            recommendations.push("Content appears safe for processing".to_string());
            return recommendations;
        }

        let threat_types: HashSet<ThreatType> = threats.iter().map(|t| t.threat_type).collect();

        if threat_types.contains(&ThreatType::Injection) {
            recommendations.push("Sanitize input to remove injection attempts".to_string());
            recommendations.push("Consider using parameterized queries or templates".to_string());
        }

        if threat_types.contains(&ThreatType::PrivilegeEscalation) {
            recommendations.push("Review and restrict privilege requirements".to_string());
            recommendations.push("Implement least privilege principle".to_string());
        }

        if threat_types.contains(&ThreatType::DataExfiltration) {
            recommendations.push("Block access to sensitive data".to_string());
            recommendations.push("Implement data access controls".to_string());
        }

        if threat_types.contains(&ThreatType::MaliciousCode) {
            recommendations.push("Block code execution immediately".to_string());
            recommendations.push("Quarantine suspicious content".to_string());
        }

        if security_level == SecurityLevel::Strict {
            recommendations.push("Consider manual review before processing".to_string());
        }

        recommendations
    }

    fn log_security_event(
        &mut self,
        content_type: ContentType,
        threats: &[ThreatDetection],
        context: Option<&ValidationContext>,
    ) {
        let event = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "content_type": format!("{content_type:?}"),
            "threat_count": threats.len(),
            "threats": threats.iter().map(|t| serde_json::json!({
                "type": format!("{:?}", t.threat_type),
                "severity": format!("{:?}", t.severity),
                "description": &t.description,
            })).collect::<Vec<_>>(),
            "context": context.map(|c| serde_json::json!({
                "source": &c.source,
                "session_id": &c.session_id,
            })),
        });

        self.security_events.push(event);
    }
}

// ── Free functions ──────────────────────────────────────────────────

/// Determine if a pattern should be flagged based on security level.
fn should_flag_pattern(severity: &str, security_level: SecurityLevel) -> bool {
    let severity_num = match severity {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    };

    let threshold = match security_level {
        SecurityLevel::Low => 3,    // Only high + critical
        SecurityLevel::Medium => 2, // Medium and above
        SecurityLevel::High => 1,   // All patterns
        SecurityLevel::Strict => 1, // All patterns
    };

    severity_num >= threshold
}

/// Calculate overall risk level from threats.
fn calculate_risk_level(threats: &[ThreatDetection]) -> RiskLevel {
    if threats.is_empty() {
        return RiskLevel::None;
    }

    let mut max = RiskLevel::None;
    for t in threats {
        if t.severity > max {
            max = t.severity;
        }
    }
    max
}

/// Convert a pattern match to a threat detection.
fn pattern_match_to_threat(pm: &PatternMatch<'_>) -> ThreatDetection {
    ThreatDetection {
        threat_type: category_to_threat_type(pm.pattern.category),
        severity: severity_to_risk(pm.pattern.severity),
        description: format!("{}: {}", pm.pattern.name, pm.pattern.description),
        location: pm.location.clone(),
        mitigation: Some(pm.pattern.mitigation.to_string()),
    }
}
