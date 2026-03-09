//! Health check and monitoring for XPIA security system.
//!
//! Ports health checks from `xpia_health.py`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Subdirectory under $HOME for Claude configuration.
const CLAUDE_CONFIG_DIR: &str = ".claude";

/// Subdirectory path for XPIA hooks under $HOME.
const XPIA_HOOKS_SUBPATH: &[&str] = &[".amplihack", ".claude", "tools", "xpia", "hooks"];

/// Health check result for a single component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Summary of health check results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub total_checks: usize,
    pub passed_checks: usize,
    pub failed_checks: usize,
    pub warnings: usize,
}

/// Complete health report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub timestamp: String,
    pub overall_status: String,
    pub components: HashMap<String, serde_json::Value>,
    pub summary: HealthSummary,
    pub recommendations: Vec<String>,
}

/// Check if a hook file exists and is executable (Unix) or exists (non-Unix).
pub fn check_hook_file_exists(hook_path: &str) -> ComponentHealth {
    let path = PathBuf::from(shellexpand::tilde(hook_path).as_ref());

    if !path.exists() {
        return ComponentHealth {
            status: "missing".to_string(),
            message: format!("Hook file not found: {}", path.display()),
            path: Some(path.display().to_string()),
            error: None,
        };
    }

    if !path.is_file() {
        return ComponentHealth {
            status: "not_file".to_string(),
            message: format!("Hook path is not a file: {}", path.display()),
            path: Some(path.display().to_string()),
            error: None,
        };
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(&path) {
            let mode = meta.permissions().mode();
            if mode & 0o111 == 0 {
                return ComponentHealth {
                    status: "not_executable".to_string(),
                    message: format!("Hook file not executable: {}", path.display()),
                    path: Some(path.display().to_string()),
                    error: None,
                };
            }
        }
    }

    ComponentHealth {
        status: "ok".to_string(),
        message: "Hook file exists and is executable".to_string(),
        path: Some(path.display().to_string()),
        error: None,
    }
}

/// Check if XPIA hooks are configured in settings.json.
pub fn check_settings_json_hooks(settings_path: Option<&Path>) -> serde_json::Value {
    let default_path = dirs::home_dir()
        .unwrap_or_default()
        .join(CLAUDE_CONFIG_DIR)
        .join("settings.json");
    let path = settings_path.unwrap_or(&default_path);

    if !path.exists() {
        return serde_json::json!({
            "status": "no_settings",
            "message": "No settings.json found",
        });
    }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return serde_json::json!({
                "status": "error",
                "error": e.to_string(),
                "message": format!("Error reading settings.json: {e}"),
            });
        }
    };

    let settings: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "status": "invalid_json",
                "error": e.to_string(),
                "message": "settings.json is not valid JSON",
            });
        }
    };

    let hooks = settings
        .get("hooks")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let expected_hooks = [
        ("SessionStart", "session_start.py"),
        ("PostToolUse", "post_tool_use.py"),
        ("PreToolUse", "pre_tool_use.py"),
    ];

    let found: Vec<serde_json::Value> = expected_hooks
        .iter()
        .flat_map(|(hook_type, hook_file)| find_xpia_hooks(&hooks, hook_type, hook_file))
        .collect();

    let found_count = found.len();
    let expected_count = expected_hooks.len();
    let status = if found_count == expected_count {
        "ok"
    } else {
        "missing_hooks"
    };

    serde_json::json!({
        "status": status,
        "hooks_found": found,
        "total_found": found_count,
        "expected_count": expected_count,
        "message": format!("Found {found_count} of {expected_count} expected XPIA hooks"),
    })
}

/// Extract matching XPIA hooks from a settings.json hooks section.
fn find_xpia_hooks(
    hooks: &serde_json::Value,
    hook_type: &str,
    hook_file: &str,
) -> Vec<serde_json::Value> {
    let Some(entries) = hooks.get(hook_type).and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    entries
        .iter()
        .filter_map(|entry| entry.get("hooks").and_then(|v| v.as_array()))
        .flatten()
        .filter_map(|hook| hook.get("command").and_then(|v| v.as_str()))
        .filter(|command| command.contains("xpia") && command.contains(hook_file))
        .map(|command| {
            serde_json::json!({
                "type": hook_type,
                "file": hook_file,
                "command": command,
                "status": "configured",
            })
        })
        .collect()
}

/// Check if XPIA log directory exists and is writable.
pub fn check_xpia_log_directory() -> ComponentHealth {
    let log_dir = dirs::home_dir()
        .unwrap_or_default()
        .join(CLAUDE_CONFIG_DIR)
        .join("logs")
        .join("xpia");

    if !log_dir.exists() {
        match fs::create_dir_all(&log_dir) {
            Ok(()) => {
                return ComponentHealth {
                    status: "created".to_string(),
                    message: "XPIA log directory created successfully".to_string(),
                    path: Some(log_dir.display().to_string()),
                    error: None,
                };
            }
            Err(e) => {
                return ComponentHealth {
                    status: "creation_failed".to_string(),
                    message: format!("Failed to create XPIA log directory: {e}"),
                    path: Some(log_dir.display().to_string()),
                    error: Some(e.to_string()),
                };
            }
        }
    }

    if !log_dir.is_dir() {
        return ComponentHealth {
            status: "not_directory".to_string(),
            message: "XPIA log path exists but is not a directory".to_string(),
            path: Some(log_dir.display().to_string()),
            error: None,
        };
    }

    // Test write permission
    let test_file = log_dir.join("health_check_test.tmp");
    match fs::write(&test_file, "test") {
        Ok(()) => {
            let _ = fs::remove_file(&test_file);
            ComponentHealth {
                status: "ok".to_string(),
                message: "XPIA log directory is writable".to_string(),
                path: Some(log_dir.display().to_string()),
                error: None,
            }
        }
        Err(e) => ComponentHealth {
            status: "not_writable".to_string(),
            message: format!("XPIA log directory not writable: {e}"),
            path: Some(log_dir.display().to_string()),
            error: Some(e.to_string()),
        },
    }
}

/// Get expected XPIA hook file paths.
pub fn get_xpia_hook_paths() -> Vec<String> {
    let home = dirs::home_dir().unwrap_or_default();
    let mut hook_base = home;
    for segment in XPIA_HOOKS_SUBPATH {
        hook_base = hook_base.join(segment);
    }

    vec![
        hook_base.join("session_start.py").display().to_string(),
        hook_base.join("post_tool_use.py").display().to_string(),
        hook_base.join("pre_tool_use.py").display().to_string(),
    ]
}

/// Run comprehensive XPIA health check.
pub fn check_xpia_health(settings_path: Option<&Path>) -> HealthReport {
    let mut report = HealthReport {
        timestamp: Utc::now().to_rfc3339(),
        overall_status: "unknown".to_string(),
        components: HashMap::new(),
        summary: HealthSummary {
            total_checks: 0,
            passed_checks: 0,
            failed_checks: 0,
            warnings: 0,
        },
        recommendations: Vec::new(),
    };

    let settings_status = audit_settings_hooks(&mut report, settings_path);
    let hooks_ok = audit_hook_files(&mut report);
    let log_ok = audit_log_directory(&mut report);

    report.overall_status = determine_overall_status(&report.summary);
    build_recommendations(&mut report, &settings_status, hooks_ok, log_ok);

    report
}

fn audit_settings_hooks(report: &mut HealthReport, settings_path: Option<&Path>) -> String {
    let settings_check = check_settings_json_hooks(settings_path);
    let status = settings_check["status"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    report
        .components
        .insert("settings_hooks".to_string(), settings_check);
    report.summary.total_checks += 1;
    match status.as_str() {
        "ok" => report.summary.passed_checks += 1,
        "missing_hooks" => report.summary.failed_checks += 1,
        _ => report.summary.warnings += 1,
    }
    status
}

fn audit_hook_files(report: &mut HealthReport) -> bool {
    let hook_paths = get_xpia_hook_paths();
    let mut hook_statuses: Vec<serde_json::Value> = Vec::new();
    let mut all_ok = true;
    for hook_path in &hook_paths {
        let check = check_hook_file_exists(hook_path);
        report.summary.total_checks += 1;
        if check.status == "ok" {
            report.summary.passed_checks += 1;
        } else {
            report.summary.failed_checks += 1;
            all_ok = false;
        }
        hook_statuses.push(serde_json::to_value(&check).unwrap_or_default());
    }
    report.components.insert(
        "hook_files".to_string(),
        serde_json::json!({
            "status": if all_ok { "ok" } else { "issues_found" },
            "files": hook_statuses,
            "message": format!("Checked {} hook files", hook_paths.len()),
        }),
    );
    all_ok
}

fn audit_log_directory(report: &mut HealthReport) -> bool {
    let log_check = check_xpia_log_directory();
    report.summary.total_checks += 1;
    let ok = matches!(log_check.status.as_str(), "ok" | "created");
    if ok {
        report.summary.passed_checks += 1;
    } else {
        report.summary.failed_checks += 1;
    }
    report.components.insert(
        "log_directory".to_string(),
        serde_json::to_value(&log_check).unwrap_or_default(),
    );
    ok
}

fn determine_overall_status(summary: &HealthSummary) -> String {
    if summary.failed_checks == 0 {
        if summary.warnings == 0 {
            "healthy".to_string()
        } else {
            "healthy_with_warnings".to_string()
        }
    } else if summary.passed_checks > summary.failed_checks {
        "partially_functional".to_string()
    } else {
        "unhealthy".to_string()
    }
}

fn build_recommendations(
    report: &mut HealthReport,
    settings_status: &str,
    hooks_ok: bool,
    log_ok: bool,
) {
    if settings_status == "missing_hooks" {
        report
            .recommendations
            .push("Run installation process to configure XPIA hooks in settings.json".to_string());
    }
    if !hooks_ok {
        report
            .recommendations
            .push("Verify XPIA hook files are installed and executable".to_string());
    }
    if !log_ok {
        report
            .recommendations
            .push("Fix XPIA log directory permissions".to_string());
    }
}
