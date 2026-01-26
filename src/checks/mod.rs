use serde::{Deserialize, Serialize};

pub mod csp;
pub mod cors;
pub mod hsts;
pub mod xframe;
pub mod cookies;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    pub fn color(&self) -> colored::Color {
        use colored::Color;
        match self {
            Severity::Critical => Color::BrightRed,
            Severity::High => Color::Red,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::BrightYellow,
            Severity::Info => Color::Cyan,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub category: String,
    pub severity: Severity,
    pub message: String,
    pub recommendation: String,
}
#[derive(Clone)]
pub struct ScanResult {
    pub url: String,
    pub status: u16,
    pub issues: Vec<SecurityIssue>,
}

impl ScanResult {
    pub fn count_by_severity(&self, severity: &Severity) -> usize {
        self.issues.iter().filter(|i| {
            matches!(
                (&i.severity, severity),
                (Severity::Critical, Severity::Critical)
                | (Severity::High, Severity::High)
                | (Severity::Medium, Severity::Medium)
                | (Severity::Low, Severity::Low)
                | (Severity::Info, Severity::Info)
            )
        }).count()
    }

    pub fn has_critical(&self) -> bool {
        self.issues.iter().any(|i| matches!(i.severity, Severity::Critical))
    }
}
