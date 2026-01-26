use super::{SecurityIssue, Severity};
use regex::Regex;
use reqwest::header::HeaderMap;

pub fn check(headers: &HeaderMap) -> Vec<SecurityIssue> {
    let mut issues = Vec::new();

    // Check if CSP exists
    let csp_header = headers
        .get("content-security-policy")
        .or_else(|| headers.get("x-content-security-policy"));

    let csp = match csp_header {
        Some(value) => match value.to_str() {
            Ok(v) => v,
            Err(_) => {
                issues.push(SecurityIssue {
                    category: "CSP".to_string(),
                    severity: Severity::Medium,
                    message: "Content-Security-Policy header has invalid encoding".to_string(),
                    recommendation: "Ensure CSP header contains valid UTF-8 characters".to_string(),
                });
                return issues;
            }
        },
        None => {
            issues.push(SecurityIssue {
                category: "CSP".to_string(),
                severity: Severity::High,
                message: "Missing Content-Security-Policy header".to_string(),
                recommendation: "Implement CSP to prevent XSS and other injection attacks".to_string(),
            });
            return issues;
        }
    };

    // Check for unsafe-inline
    if csp.contains("'unsafe-inline'") {
        issues.push(SecurityIssue {
            category: "CSP".to_string(),
            severity: Severity::High,
            message: "CSP allows 'unsafe-inline'".to_string(),
            recommendation: "Remove 'unsafe-inline' and use nonces or hashes for inline scripts/styles".to_string(),
        });
    }

    // Check for unsafe-eval
    if csp.contains("'unsafe-eval'") {
        issues.push(SecurityIssue {
            category: "CSP".to_string(),
            severity: Severity::High,
            message: "CSP allows 'unsafe-eval'".to_string(),
            recommendation: "Remove 'unsafe-eval' to prevent dynamic code execution".to_string(),
        });
    }

    // Check for wildcard in script-src
    if let Some(script_src) = extract_directive(csp, "script-src") {
        if script_src.contains(" * ") || script_src.ends_with(" *") || script_src == "*" {
            issues.push(SecurityIssue {
                category: "CSP".to_string(),
                severity: Severity::Critical,
                message: "CSP script-src allows all sources (*)".to_string(),
                recommendation: "Restrict script-src to specific trusted domains only".to_string(),
            });
        }

        // Check for data: in script-src
        if script_src.contains("data:") {
            issues.push(SecurityIssue {
                category: "CSP".to_string(),
                severity: Severity::High,
                message: "CSP script-src allows 'data:' URIs".to_string(),
                recommendation: "Remove 'data:' from script-src to prevent base64 encoded script execution".to_string(),
            });
        }

        // Check for overly permissive https:
        if script_src.contains("https:") && !script_src.contains("'unsafe-inline'") {
            issues.push(SecurityIssue {
                category: "CSP".to_string(),
                severity: Severity::Medium,
                message: "CSP script-src allows all HTTPS sources".to_string(),
                recommendation: "Restrict to specific HTTPS domains instead of allowing all HTTPS".to_string(),
            });
        }
    }

    // Check for wildcard in default-src
    if let Some(default_src) = extract_directive(csp, "default-src") {
        if default_src.contains(" * ") || default_src.ends_with(" *") || default_src == "*" {
            issues.push(SecurityIssue {
                category: "CSP".to_string(),
                severity: Severity::High,
                message: "CSP default-src allows all sources (*)".to_string(),
                recommendation: "Restrict default-src to specific trusted domains".to_string(),
            });
        }
    } else {
        issues.push(SecurityIssue {
            category: "CSP".to_string(),
            severity: Severity::Medium,
            message: "CSP missing 'default-src' directive".to_string(),
            recommendation: "Add 'default-src' as a fallback for other directives".to_string(),
        });
    }

    // Check for object-src
    if let Some(object_src) = extract_directive(csp, "object-src") {
        if object_src != "'none'" {
            issues.push(SecurityIssue {
                category: "CSP".to_string(),
                severity: Severity::Medium,
                message: "CSP object-src is not set to 'none'".to_string(),
                recommendation: "Set object-src to 'none' to prevent Flash/plugin-based attacks".to_string(),
            });
        }
    } else {
        issues.push(SecurityIssue {
            category: "CSP".to_string(),
            severity: Severity::Low,
            message: "CSP missing 'object-src' directive".to_string(),
            recommendation: "Add 'object-src 'none'' to prevent plugin execution".to_string(),
        });
    }

    // Check for base-uri
    if !csp.contains("base-uri") {
        issues.push(SecurityIssue {
            category: "CSP".to_string(),
            severity: Severity::Medium,
            message: "CSP missing 'base-uri' directive".to_string(),
            recommendation: "Add 'base-uri 'self'' to prevent base tag injection".to_string(),
        });
    }

    // Check for upgrade-insecure-requests
    if !csp.contains("upgrade-insecure-requests") && !headers.contains_key("strict-transport-security") {
        issues.push(SecurityIssue {
            category: "CSP".to_string(),
            severity: Severity::Info,
            message: "CSP missing 'upgrade-insecure-requests' directive".to_string(),
            recommendation: "Consider adding 'upgrade-insecure-requests' to upgrade HTTP to HTTPS".to_string(),
        });
    }

    issues
}

fn extract_directive(csp: &str, directive: &str) -> Option<String> {
    let pattern = format!(r"{}\s+([^;]+)", regex::escape(directive));
    let re = Regex::new(&pattern).ok()?;
    
    re.captures(csp)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_directive() {
        let csp = "default-src 'self'; script-src 'self' cdn.example.com; object-src 'none'";
        
        assert_eq!(
            extract_directive(csp, "script-src"),
            Some("'self' cdn.example.com".to_string())
        );
        
        assert_eq!(
            extract_directive(csp, "default-src"),
            Some("'self'".to_string())
        );
    }
}
