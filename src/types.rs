//! Core type definitions for XPIA defense.
//!
//! Ports all enums and structs from `xpia_defense_interface.py`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security validation levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Strict,
}

/// Risk assessment levels, ordered from none to critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Types of security threats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    Injection,
    PrivilegeEscalation,
    DataExfiltration,
    MaliciousCode,
    SocialEngineering,
    ResourceAbuse,
}

/// Content types for validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    Text,
    Code,
    Command,
    Data,
    UserInput,
}

/// Context information for validation requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationContext {
    /// Source of the content: "user", "agent", "system".
    pub source: String,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
    pub working_directory: Option<String>,
    pub environment: Option<HashMap<String, String>>,
}

impl ValidationContext {
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            session_id: None,
            agent_id: None,
            working_directory: None,
            environment: None,
        }
    }
}

/// Match location within scanned content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchLocation {
    pub start: usize,
    pub end: usize,
}

/// Individual threat detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub threat_type: ThreatType,
    pub severity: RiskLevel,
    pub description: String,
    pub location: Option<MatchLocation>,
    pub mitigation: Option<String>,
}

/// Result of security validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use = "validation results must be checked — ignoring them bypasses security"]
pub struct ValidationResult {
    pub is_valid: bool,
    pub risk_level: RiskLevel,
    pub threats: Vec<ThreatDetection>,
    pub recommendations: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

impl ValidationResult {
    /// Whether content should be blocked based on risk level.
    pub fn should_block(&self) -> bool {
        matches!(self.risk_level, RiskLevel::High | RiskLevel::Critical)
    }

    /// Whether an alert should be generated.
    pub fn should_alert(&self) -> bool {
        self.risk_level != RiskLevel::None
    }

    /// Create a passing result (no threats).
    pub fn pass(reason: &str) -> Self {
        let mut metadata = HashMap::new();
        metadata.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
        Self {
            is_valid: true,
            risk_level: RiskLevel::None,
            threats: vec![],
            recommendations: vec![reason.to_string()],
            metadata,
            timestamp: Utc::now(),
        }
    }

    /// Create a blocked result (fail-closed on error).
    pub fn blocked(reason: &str) -> Self {
        let mut metadata = HashMap::new();
        metadata.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
        Self {
            is_valid: false,
            risk_level: RiskLevel::Critical,
            threats: vec![ThreatDetection {
                threat_type: ThreatType::Injection,
                severity: RiskLevel::Critical,
                description: reason.to_string(),
                location: None,
                mitigation: Some("Review and retry".to_string()),
            }],
            recommendations: vec!["Content blocked due to validation error".to_string()],
            metadata,
            timestamp: Utc::now(),
        }
    }
}

/// XPIA Defense configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfiguration {
    pub security_level: SecurityLevel,
    pub enabled: bool,
    pub bash_validation: bool,
    pub agent_communication: bool,
    pub content_scanning: bool,
    pub real_time_monitoring: bool,
    pub block_threshold: RiskLevel,
    pub alert_threshold: RiskLevel,
    pub bash_tool_integration: bool,
    pub agent_framework_integration: bool,
    pub logging_enabled: bool,
}

impl Default for SecurityConfiguration {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Medium,
            enabled: true,
            bash_validation: true,
            agent_communication: true,
            content_scanning: true,
            real_time_monitoring: false,
            block_threshold: RiskLevel::High,
            alert_threshold: RiskLevel::Medium,
            bash_tool_integration: true,
            agent_framework_integration: true,
            logging_enabled: true,
        }
    }
}

/// Pattern categories for attack classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternCategory {
    PromptOverride,
    InstructionInjection,
    ContextManipulation,
    DataExfiltration,
    SystemEscape,
    RoleHijacking,
    EncodingBypass,
    ChainAttacks,
}

/// Severity string to RiskLevel mapping.
pub fn severity_to_risk(severity: &str) -> RiskLevel {
    match severity {
        "low" => RiskLevel::Low,
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        _ => RiskLevel::Medium,
    }
}

/// Map PatternCategory to ThreatType.
pub fn category_to_threat_type(category: PatternCategory) -> ThreatType {
    match category {
        PatternCategory::PromptOverride => ThreatType::Injection,
        PatternCategory::InstructionInjection => ThreatType::Injection,
        PatternCategory::ContextManipulation => ThreatType::Injection,
        PatternCategory::DataExfiltration => ThreatType::DataExfiltration,
        PatternCategory::SystemEscape => ThreatType::PrivilegeEscalation,
        PatternCategory::RoleHijacking => ThreatType::SocialEngineering,
        PatternCategory::EncodingBypass => ThreatType::Injection,
        PatternCategory::ChainAttacks => ThreatType::Injection,
    }
}

/// Check if a validation result contains critical threats.
pub fn is_threat_critical(result: &ValidationResult) -> bool {
    result
        .threats
        .iter()
        .any(|t| t.severity == RiskLevel::Critical)
}

/// Get human-readable threat summary.
pub fn get_threat_summary(result: &ValidationResult) -> String {
    if result.threats.is_empty() {
        return "No threats detected".to_string();
    }

    let mut counts: HashMap<RiskLevel, usize> = HashMap::new();
    for threat in &result.threats {
        *counts.entry(threat.severity).or_insert(0) += 1;
    }

    let parts: Vec<String> = counts
        .iter()
        .map(|(severity, count)| format!("{count} {severity:?}"))
        .collect();

    format!("Threats detected: {}", parts.join(", "))
}
