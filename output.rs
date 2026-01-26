use crate::checks::{ScanResult, Severity};
use clap::ValueEnum;
use colored::*;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
    Minimal,
}

pub fn print_result(result: &ScanResult, format: &OutputFormat) {
    match format {
        OutputFormat::Pretty => print_pretty(result),
        OutputFormat::Json => print_json(result),
        OutputFormat::Minimal => print_minimal(result),
    }
}

fn print_pretty(result: &ScanResult) {
    println!("  {} {}", "Status:".bright_black(), result.status);
    
    if result.issues.is_empty() {
        println!("  {} No security issues found!", "✓".green().bold());
        return;
    }

    // Count by severity
    let critical = result.count_by_severity(&Severity::Critical);
    let high = result.count_by_severity(&Severity::High);
    let medium = result.count_by_severity(&Severity::Medium);
    let low = result.count_by_severity(&Severity::Low);
    let info = result.count_by_severity(&Severity::Info);

    println!("  {} Issues found:", "⚠".yellow().bold());
    
    if critical > 0 {
        println!("    {} Critical", format!("{}", critical).color(Severity::Critical.color()).bold());
    }
    if high > 0 {
        println!("    {} High", format!("{}", high).color(Severity::High.color()).bold());
    }
    if medium > 0 {
        println!("    {} Medium", format!("{}", medium).color(Severity::Medium.color()));
    }
    if low > 0 {
        println!("    {} Low", format!("{}", low).color(Severity::Low.color()));
    }
    if info > 0 {
        println!("    {} Info", format!("{}", info).color(Severity::Info.color()));
    }

    println!();

    // Print issues grouped by severity
    for severity in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info] {
        let issues: Vec<_> = result.issues.iter()
            .filter(|i| matches!((&i.severity, &severity), 
                (Severity::Critical, Severity::Critical) |
                (Severity::High, Severity::High) |
                (Severity::Medium, Severity::Medium) |
                (Severity::Low, Severity::Low) |
                (Severity::Info, Severity::Info)))
            .collect();

        if issues.is_empty() {
            continue;
        }

        for issue in issues {
            let severity_badge = format!("[{}]", issue.severity.as_str())
                .color(issue.severity.color())
                .bold();
            
            println!("  {} {}: {}", 
                severity_badge,
                issue.category.bright_white().bold(),
                issue.message
            );
            
            println!("    {} {}", 
                "→".bright_black(),
                issue.recommendation.bright_black()
            );
            println!();
        }
    }
}

fn print_json(result: &ScanResult) {
    match serde_json::to_string_pretty(result) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error serializing to JSON: {}", e),
    }
}

fn print_minimal(result: &ScanResult) {
    let critical = result.count_by_severity(&Severity::Critical);
    let high = result.count_by_severity(&Severity::High);
    let medium = result.count_by_severity(&Severity::Medium);
    
    let status_symbol = if result.has_critical() {
        "✖".red()
    } else if high > 0 {
        "⚠".yellow()
    } else if medium > 0 {
        "●".bright_yellow()
    } else {
        "✓".green()
    };

    println!("  {} C:{} H:{} M:{} L:{}", 
        status_symbol,
        critical,
        high,
        medium,
        result.count_by_severity(&Severity::Low)
    );
}

pub fn save_to_file(
    results: &[ScanResult],
    path: &PathBuf,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = match format {
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct Output {
                scan_time: String,
                total_scanned: usize,
                results: Vec<ScanResult>,
            }

            let output = Output {
                scan_time: chrono::Utc::now().to_rfc3339(),
                total_scanned: results.len(),
                results: results.to_vec(),
            };

            serde_json::to_string_pretty(&output)?
        }
        OutputFormat::Pretty | OutputFormat::Minimal => {
            let mut content = String::new();
            content.push_str(&format!("CSPy Security Scan Report\n"));
            content.push_str(&format!("Generated: {}\n", chrono::Utc::now().to_rfc3339()));
            content.push_str(&format!("Total Scanned: {}\n\n", results.len()));
            content.push_str(&"=".repeat(80));
            content.push_str("\n\n");

            for result in results {
                content.push_str(&format!("URL: {}\n", result.url));
                content.push_str(&format!("Status: {}\n", result.status));
                content.push_str(&format!("Issues: {}\n\n", result.issues.len()));

                for issue in &result.issues {
                    content.push_str(&format!("[{}] {}\n", issue.severity.as_str(), issue.category));
                    content.push_str(&format!("  Message: {}\n", issue.message));
                    content.push_str(&format!("  Fix: {}\n\n", issue.recommendation));
                }

                content.push_str(&"-".repeat(80));
                content.push_str("\n\n");
            }

            content
        }
    };

    std::fs::write(path, content)?;
    Ok(())
}

// Add chrono dependency for timestamps
