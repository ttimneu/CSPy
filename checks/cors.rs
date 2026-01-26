use super::{SecurityIssue, Severity};
use reqwest::header::HeaderMap;

pub fn check(headers: &HeaderMap) -> Vec<SecurityIssue> {
    let mut issues = Vec::new();

    let origin = headers.get("access-control-allow-origin");
    let credentials = headers.get("access-control-allow-credentials");

    match origin {
        Some(origin_value) => {
            let origin_str = match origin_value.to_str() {
                Ok(s) => s,
                Err(_) => return issues,
            };

            // Check for wildcard with credentials (CRITICAL vulnerability)
            if origin_str == "*" {
                if let Some(cred) = credentials {
                    if let Ok(cred_str) = cred.to_str() {
                        if cred_str.to_lowercase() == "true" {
                            issues.push(SecurityIssue {
                                category: "CORS".to_string(),
                                severity: Severity::Critical,
                                message: "CORS allows all origins (*) with credentials".to_string(),
                                recommendation: "NEVER use wildcard (*) with Access-Control-Allow-Credentials: true. This allows any website to make authenticated requests.".to_string(),
                            });
                        }
                    }
                }

                // Wildcard without credentials is still a concern
                issues.push(SecurityIssue {
                    category: "CORS".to_string(),
                    severity: Severity::Medium,
                    message: "CORS allows all origins (*)".to_string(),
                    recommendation: "Restrict Access-Control-Allow-Origin to specific trusted domains".to_string(),
                });
            }

            // Check for null origin
            if origin_str == "null" {
                issues.push(SecurityIssue {
                    category: "CORS".to_string(),
                    severity: Severity::High,
                    message: "CORS allows 'null' origin".to_string(),
                    recommendation: "Remove 'null' from allowed origins - it can be exploited via sandboxed iframes".to_string(),
                });
            }

            // Check for overly permissive patterns
            if origin_str.starts_with("http://") {
                issues.push(SecurityIssue {
                    category: "CORS".to_string(),
                    severity: Severity::Medium,
                    message: "CORS allows HTTP origin (unencrypted)".to_string(),
                    recommendation: "Only allow HTTPS origins to prevent MitM attacks".to_string(),
                });
            }
        }
        None => {
            // No CORS headers - this is actually the most secure for most apps
            // Only flag if other CORS headers are present
            if headers.contains_key("access-control-allow-methods") 
                || headers.contains_key("access-control-allow-headers") {
                issues.push(SecurityIssue {
                    category: "CORS".to_string(),
                    severity: Severity::Low,
                    message: "CORS headers present but Access-Control-Allow-Origin is missing".to_string(),
                    recommendation: "Either remove all CORS headers or properly configure Access-Control-Allow-Origin".to_string(),
                });
            }
        }
    }

    // Check Access-Control-Allow-Methods
    if let Some(methods) = headers.get("access-control-allow-methods") {
        if let Ok(methods_str) = methods.to_str() {
            let methods_upper = methods_str.to_uppercase();
            
            // Check for dangerous methods
            if methods_upper.contains("*") {
                issues.push(SecurityIssue {
                    category: "CORS".to_string(),
                    severity: Severity::High,
                    message: "CORS allows all HTTP methods (*)".to_string(),
                    recommendation: "Explicitly specify only the required HTTP methods".to_string(),
                });
            }

            if methods_upper.contains("DELETE") || methods_upper.contains("PUT") {
                issues.push(SecurityIssue {
                    category: "CORS".to_string(),
                    severity: Severity::Info,
                    message: "CORS allows potentially dangerous methods (DELETE/PUT)".to_string(),
                    recommendation: "Ensure these methods are required and properly secured".to_string(),
                });
            }
        }
    }

    // Check Access-Control-Allow-Headers
    if let Some(allowed_headers) = headers.get("access-control-allow-headers") {
        if let Ok(headers_str) = allowed_headers.to_str() {
            if headers_str.contains("*") {
                issues.push(SecurityIssue {
                    category: "CORS".to_string(),
                    severity: Severity::Medium,
                    message: "CORS allows all headers (*)".to_string(),
                    recommendation: "Explicitly specify only the required headers".to_string(),
                });
            }
        }
    }

    // Check Access-Control-Max-Age
    if let Some(max_age) = headers.get("access-control-max-age") {
        if let Ok(age_str) = max_age.to_str() {
            if let Ok(age) = age_str.parse::<i32>() {
                if age > 86400 {  // More than 24 hours
                    issues.push(SecurityIssue {
                        category: "CORS".to_string(),
                        severity: Severity::Low,
                        message: "CORS preflight cache time is very long".to_string(),
                        recommendation: "Consider reducing Access-Control-Max-Age to allow faster policy updates".to_string(),
                    });
                }
            }
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn test_wildcard_with_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        headers.insert("access-control-allow-credentials", HeaderValue::from_static("true"));
        
        let issues = check(&headers);
        assert!(issues.iter().any(|i| matches!(i.severity, Severity::Critical)));
    }

    #[test]
    fn test_null_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("access-control-allow-origin", HeaderValue::from_static("null"));
        
        let issues = check(&headers);
        assert!(issues.iter().any(|i| matches!(i.severity, Severity::High)));
    }
}
