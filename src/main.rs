//! CLI binary for amplihack-xpia-defender.
//!
//! Provides subcommands that mirror the Python XPIA defense interface,
//! outputting JSON to stdout for subprocess consumption.

use std::io::{self, Read};
use std::process;

use clap::{Parser, Subcommand, ValueEnum};

use amplihack_xpia_defender::{
    check_xpia_health, ContentType, SecurityConfiguration, SecurityLevel, ValidationContext,
    XPIADefender,
};
use std::path::Path;

#[derive(Parser)]
#[command(
    name = "xpia-defend",
    about = "XPIA (Cross-Prompt Injection Attack) defense CLI",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate arbitrary text content for injection attacks
    ValidateContent {
        /// Content to validate (reads from stdin if omitted)
        #[arg(long)]
        content: Option<String>,
        /// Content type
        #[arg(long, default_value = "user-input")]
        content_type: CliContentType,
        /// Security level
        #[arg(long, default_value = "medium")]
        security_level: CliSecurityLevel,
        /// Source identifier for audit trail
        #[arg(long, default_value = "cli")]
        source: String,
    },
    /// Validate a bash command before execution
    ValidateBash {
        /// The command string to validate
        #[arg(long)]
        command: String,
        /// Security level
        #[arg(long, default_value = "medium")]
        security_level: CliSecurityLevel,
        /// Source identifier for audit trail
        #[arg(long, default_value = "cli")]
        source: String,
    },
    /// Validate a web fetch request (URL + prompt)
    ValidateWebfetch {
        /// URL to validate
        #[arg(long)]
        url: String,
        /// Prompt used for the fetch
        #[arg(long)]
        prompt: String,
        /// Security level
        #[arg(long, default_value = "medium")]
        security_level: CliSecurityLevel,
        /// Source identifier for audit trail
        #[arg(long, default_value = "cli")]
        source: String,
    },
    /// Validate agent-to-agent communication
    ValidateAgent {
        /// Source agent ID
        #[arg(long)]
        source_agent: String,
        /// Target agent ID
        #[arg(long)]
        target_agent: String,
        /// Message content (reads from stdin if omitted)
        #[arg(long)]
        message: Option<String>,
        /// Security level
        #[arg(long, default_value = "medium")]
        security_level: CliSecurityLevel,
    },
    /// Run XPIA health check
    Health {
        /// Path to settings.json
        #[arg(long)]
        settings_path: Option<String>,
    },
    /// List all registered attack patterns
    Patterns,
    /// Show current security configuration
    Config {
        /// Security level
        #[arg(long, default_value = "medium")]
        security_level: CliSecurityLevel,
    },
}

#[derive(Clone, ValueEnum)]
enum CliSecurityLevel {
    Low,
    Medium,
    High,
    Strict,
}

impl From<CliSecurityLevel> for SecurityLevel {
    fn from(level: CliSecurityLevel) -> Self {
        match level {
            CliSecurityLevel::Low => SecurityLevel::Low,
            CliSecurityLevel::Medium => SecurityLevel::Medium,
            CliSecurityLevel::High => SecurityLevel::High,
            CliSecurityLevel::Strict => SecurityLevel::Strict,
        }
    }
}

#[derive(Clone, ValueEnum)]
enum CliContentType {
    Text,
    Code,
    Command,
    Data,
    #[value(name = "user-input")]
    UserInput,
}

impl From<CliContentType> for ContentType {
    fn from(ct: CliContentType) -> Self {
        match ct {
            CliContentType::Text => ContentType::Text,
            CliContentType::Code => ContentType::Code,
            CliContentType::Command => ContentType::Command,
            CliContentType::Data => ContentType::Data,
            CliContentType::UserInput => ContentType::UserInput,
        }
    }
}

/// Read content from stdin when not provided via --content/--message.
fn read_stdin() -> Result<String, io::Error> {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

/// Build a SecurityConfiguration with the given level.
fn make_config(level: CliSecurityLevel) -> SecurityConfiguration {
    SecurityConfiguration {
        security_level: level.into(),
        ..SecurityConfiguration::default()
    }
}

/// Build a minimal ValidationContext.
fn make_context(source: &str) -> ValidationContext {
    ValidationContext::new(source)
}

/// Write JSON to stdout and exit with appropriate code.
/// Exit 0 = valid, Exit 1 = blocked/invalid, Exit 2 = internal error.
fn emit(result: &amplihack_xpia_defender::ValidationResult) -> ! {
    let json = serde_json::to_string(result).unwrap_or_else(|e| {
        eprintln!("XPIA: serialization error: {e}");
        process::exit(2);
    });
    println!("{json}");
    if result.is_valid {
        process::exit(0);
    } else {
        process::exit(1);
    }
}

/// Write arbitrary JSON to stdout and exit 0.
fn emit_json(value: &serde_json::Value) -> ! {
    let json = serde_json::to_string(value).unwrap_or_else(|e| {
        eprintln!("XPIA: serialization error: {e}");
        process::exit(2);
    });
    println!("{json}");
    process::exit(0);
}

/// Fatal error: write JSON error object to stdout and exit 2.
fn fatal(msg: &str) -> ! {
    let err = serde_json::json!({
        "error": true,
        "message": msg,
        "is_valid": false,
        "risk_level": "critical"
    });
    let json = serde_json::to_string(&err)
        .unwrap_or_else(|_| format!(r#"{{"error":true,"message":"{}","is_valid":false}}"#, msg));
    println!("{json}");
    process::exit(2);
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::ValidateContent {
            content,
            content_type,
            security_level,
            source,
        } => {
            let text = content.unwrap_or_else(|| {
                read_stdin().unwrap_or_else(|e| fatal(&format!("Failed to read stdin: {e}")))
            });
            let config = make_config(security_level);
            let mut defender = XPIADefender::new(Some(config))
                .unwrap_or_else(|e| fatal(&format!("Failed to initialize defender: {e}")));
            let ctx = make_context(&source);
            let result = defender.validate_content(&text, content_type.into(), Some(&ctx), None);
            emit(&result);
        }
        Commands::ValidateBash {
            command,
            security_level,
            source,
        } => {
            let config = make_config(security_level);
            let mut defender = XPIADefender::new(Some(config))
                .unwrap_or_else(|e| fatal(&format!("Failed to initialize defender: {e}")));
            let ctx = make_context(&source);
            let result = defender.validate_bash_command(&command, None, Some(&ctx));
            emit(&result);
        }
        Commands::ValidateWebfetch {
            url,
            prompt,
            security_level,
            source,
        } => {
            let config = make_config(security_level);
            let mut defender = XPIADefender::new(Some(config))
                .unwrap_or_else(|e| fatal(&format!("Failed to initialize defender: {e}")));
            let ctx = make_context(&source);
            let result = defender.validate_webfetch_request(&url, &prompt, Some(&ctx));
            emit(&result);
        }
        Commands::ValidateAgent {
            source_agent,
            target_agent,
            message,
            security_level,
        } => {
            let msg = message.unwrap_or_else(|| {
                read_stdin().unwrap_or_else(|e| fatal(&format!("Failed to read stdin: {e}")))
            });
            let msg_value = serde_json::Value::String(msg);
            let config = make_config(security_level);
            let mut defender = XPIADefender::new(Some(config))
                .unwrap_or_else(|e| fatal(&format!("Failed to initialize defender: {e}")));
            let result = defender.validate_agent_communication(
                &source_agent,
                &target_agent,
                &msg_value,
                "text",
            );
            emit(&result);
        }
        Commands::Health { settings_path } => {
            let path = settings_path.as_deref().map(Path::new);
            let report = check_xpia_health(path);
            let json = serde_json::to_value(&report).unwrap_or_else(|e| {
                fatal(&format!("Failed to serialize health report: {e}"));
            });
            emit_json(&json);
        }
        Commands::Patterns => {
            let defender = XPIADefender::new(None)
                .unwrap_or_else(|e| fatal(&format!("Failed to initialize defender: {e}")));
            let patterns = defender.list_patterns();
            let json = serde_json::to_value(patterns).unwrap_or_else(|e| {
                fatal(&format!("Failed to serialize patterns: {e}"));
            });
            emit_json(&json);
        }
        Commands::Config { security_level } => {
            let config = make_config(security_level);
            let json = serde_json::to_value(&config).unwrap_or_else(|e| {
                fatal(&format!("Failed to serialize config: {e}"));
            });
            emit_json(&json);
        }
    }
}
