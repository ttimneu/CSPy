use super::{SecurityIssue, Severity};
use reqwest::header::HeaderMap;

pub fn check(headers: &HeaderMap) -> Vec<SecurityIssue> {
    let mut issues = Vec::new();

    let xframe = headers.get("x-frame-options");
    let csp = headers.get("content-security-policy");

    // Check if frame-ancestors is set in CSP
    let has_frame_ancestors = csp
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("frame-ancestors"))
        .unwrap_or(false);

    match xframe {
        Some(value) => {
            let xframe_str = match value.to_str() {
                Ok(s) => s.to_uppercase(),
                Err(_) => return issues,
            };

            // Check for insecure values
            if xframe_str.contains("ALLOWALL") || xframe_str.contains("ALLOW-ALL") {
                issues.push(SecurityIssue {
                    category: "X-Frame-Options".to_string(),
                    severity: Severity::High,
                    message: "X-Frame-Options is set to ALLOWALL".to_string(),
                    recommendation: "Change to DENY or SAMEORIGIN to prevent clickjacking".to_string(),
                });
            }

            // Check if using ALLOW-FROM (deprecated)
            if xframe_str.contains("ALLOW-FROM") {
                issues.push(SecurityIssue {
                    category: "X-Frame-Options".to_string(),
                    severity: Severity::Medium,
                    message: "X-Frame-Options uses deprecated ALLOW-FROM directive".to_string(),
                    recommendation: "Replace with CSP frame-ancestors directive for better browser support".to_string(),
                });
            }

            // Info: CSP frame-ancestors takes precedence
            if has_frame_ancestors {
                issues.push(SecurityIssue {
                    category: "X-Frame-Options".to_string(),
                    severity: Severity::Info,
                    message: "Both X-Frame-Options and CSP frame-ancestors are set".to_string(),
                    recommendation: "CSP frame-ancestors takes precedence in modern browsers. Consider removing X-Frame-Options for simplicity.".to_string(),
                });
            }
        }
        None => {
            // Missing X-Frame-Options
            if !has_frame_ancestors {
                issues.push(SecurityIssue {
                    category: "X-Frame-Options".to_string(),
                    severity: Severity::Medium,
                    message: "Missing X-Frame-Options header".to_string(),
                    recommendation: "Add 'X-Frame-Options: DENY' or use CSP 'frame-ancestors 'none'' to prevent clickjacking".to_string(),
                });
            }
        }
    }

    // Analyze CSP frame-ancestors if present
    if let Some(csp_value) = csp {
        if let Ok(csp_str) = csp_value.to_str() {
            if let Some(frame_ancestors) = extract_frame_ancestors(csp_str) {
                // Check for wildcard
                if frame_ancestors.contains('*') {
                    issues.push(SecurityIssue {
                        category: "CSP frame-ancestors".to_string(),
                        severity: Severity::High,
                        message: "CSP frame-ancestors allows all sources (*)".to_string(),
                        recommendation: "Restrict frame-ancestors to specific trusted domains or use 'none'".to_string(),
                    });
                }

                // Check for HTTP sources
                if frame_ancestors.contains("http://") {
                    issues.push(SecurityIssue {
                        category: "CSP frame-ancestors".to_string(),
                        severity: Severity::Medium,
                        message: "CSP frame-ancestors allows HTTP (unencrypted) sources".to_string(),
                        recommendation: "Only allow HTTPS sources in frame-ancestors".to_string(),
                    });
                }
            }
        }
    }

    issues
}

fn extract_frame_ancestors(csp: &str) -> Option<String> {
    for directive in csp.split(';') {
        let trimmed = directive.trim();
        if trimmed.starts_with("frame-ancestors") {
            // Extract everything after "frame-ancestors"
            if let Some(value) = trimmed.strip_prefix("frame-ancestors") {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_frame_ancestors() {
        let csp = "default-src 'self'; frame-ancestors 'self' https://example.com; script-src 'self'";
        assert_eq!(
            extract_frame_ancestors(csp),
            Some("'self' https://example.com".to_string())
        );

        let csp2 = "frame-ancestors 'none'";
        assert_eq!(
            extract_frame_ancestors(csp2),
            Some("'none'".to_string())
        );
    }

    #[test]
    fn test_allowall_detection() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-frame-options",
            reqwest::header::HeaderValue::from_static("ALLOWALL")
        );
        
        let issues = check(&headers);
        assert!(issues.iter().any(|i| matches!(i.severity, Severity::High)));
    }
}
