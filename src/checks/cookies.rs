use super::{SecurityIssue, Severity};
use reqwest::header::HeaderMap;

pub fn check(headers: &HeaderMap) -> Vec<SecurityIssue> {
    let mut issues = Vec::new();

    // Get all Set-Cookie headers
    let cookies: Vec<&str> = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();

    if cookies.is_empty() {
        // No cookies set - this is fine, not an issue
        return issues;
    }

    for cookie in cookies {
        let cookie_name = extract_cookie_name(cookie);
        
        // Check for Secure flag
        if !cookie.to_lowercase().contains("secure") {
            issues.push(SecurityIssue {
                category: "Cookie Security".to_string(),
                severity: Severity::Medium,
                message: format!("Cookie '{}' missing Secure flag", cookie_name),
                recommendation: "Add 'Secure' flag to ensure cookie is only sent over HTTPS".to_string(),
            });
        }

        // Check for HttpOnly flag
        if !cookie.to_lowercase().contains("httponly") {
            // Only flag as issue for session-like cookies
            if is_sensitive_cookie(&cookie_name) {
                issues.push(SecurityIssue {
                    category: "Cookie Security".to_string(),
                    severity: Severity::Medium,
                    message: format!("Cookie '{}' missing HttpOnly flag", cookie_name),
                    recommendation: "Add 'HttpOnly' flag to prevent JavaScript access and XSS attacks".to_string(),
                });
            } else {
                issues.push(SecurityIssue {
                    category: "Cookie Security".to_string(),
                    severity: Severity::Low,
                    message: format!("Cookie '{}' missing HttpOnly flag", cookie_name),
                    recommendation: "Consider adding 'HttpOnly' flag unless JavaScript access is required".to_string(),
                });
            }
        }

        // Check for SameSite
        let samesite_info = extract_samesite(cookie);
        match samesite_info {
            SameSite::None => {
                issues.push(SecurityIssue {
                    category: "Cookie Security".to_string(),
                    severity: Severity::Medium,
                    message: format!("Cookie '{}' has SameSite=None", cookie_name),
                    recommendation: "SameSite=None requires Secure flag and allows cross-site requests. Use Lax or Strict if possible.".to_string(),
                });
            }
            SameSite::Lax => {
                // Lax is acceptable for most use cases
            }
            SameSite::Strict => {
                // Strict is the most secure
            }
            SameSite::Missing => {
                issues.push(SecurityIssue {
                    category: "Cookie Security".to_string(),
                    severity: Severity::Low,
                    message: format!("Cookie '{}' missing SameSite attribute", cookie_name),
                    recommendation: "Add 'SameSite=Lax' or 'SameSite=Strict' to prevent CSRF attacks".to_string(),
                });
            }
        }

        // Check for overly long expiration
        if let Some(max_age) = extract_max_age(cookie) {
            if max_age > 31536000 {  // More than 1 year
                issues.push(SecurityIssue {
                    category: "Cookie Security".to_string(),
                    severity: Severity::Info,
                    message: format!("Cookie '{}' has very long expiration (>1 year)", cookie_name),
                    recommendation: "Consider shorter expiration times for sensitive cookies".to_string(),
                });
            }
        }

        // Check for __Host- and __Secure- prefixes
        if cookie_name.starts_with("__Secure-") || cookie_name.starts_with("__Host-") {
            if !cookie.to_lowercase().contains("secure") {
                issues.push(SecurityIssue {
                    category: "Cookie Security".to_string(),
                    severity: Severity::High,
                    message: format!("Cookie '{}' uses security prefix but missing Secure flag", cookie_name),
                    recommendation: "Cookies with __Secure- or __Host- prefix MUST have Secure flag".to_string(),
                });
            }

            if cookie_name.starts_with("__Host-") {
                if cookie.to_lowercase().contains("domain=") {
                    issues.push(SecurityIssue {
                        category: "Cookie Security".to_string(),
                        severity: Severity::High,
                        message: format!("Cookie '{}' uses __Host- prefix but has Domain attribute", cookie_name),
                        recommendation: "__Host- cookies must NOT have Domain attribute".to_string(),
                    });
                }
                
                if !cookie.to_lowercase().contains("path=/") {
                    issues.push(SecurityIssue {
                        category: "Cookie Security".to_string(),
                        severity: Severity::High,
                        message: format!("Cookie '{}' uses __Host- prefix but Path is not /", cookie_name),
                        recommendation: "__Host- cookies must have Path=/".to_string(),
                    });
                }
            }
        }
    }

    issues
}

fn extract_cookie_name(cookie: &str) -> String {
    cookie
        .split('=')
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_string()
}

fn is_sensitive_cookie(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    name_lower.contains("session")
        || name_lower.contains("auth")
        || name_lower.contains("token")
        || name_lower.contains("csrf")
        || name_lower.contains("xsrf")
        || name_lower.starts_with("__secure-")
        || name_lower.starts_with("__host-")
}

enum SameSite {
    None,
    Lax,
    Strict,
    Missing,
}

fn extract_samesite(cookie: &str) -> SameSite {
    let cookie_lower = cookie.to_lowercase();
    
    if cookie_lower.contains("samesite=none") {
        SameSite::None
    } else if cookie_lower.contains("samesite=lax") {
        SameSite::Lax
    } else if cookie_lower.contains("samesite=strict") {
        SameSite::Strict
    } else {
        SameSite::Missing
    }
}

fn extract_max_age(cookie: &str) -> Option<i64> {
    for part in cookie.split(';') {
        let trimmed = part.trim().to_lowercase();
        if trimmed.starts_with("max-age") {
            if let Some(value) = trimmed.split('=').nth(1) {
                return value.trim().parse::<i64>().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cookie_name() {
        assert_eq!(extract_cookie_name("session=abc123"), "session");
        assert_eq!(extract_cookie_name("token=xyz; Secure; HttpOnly"), "token");
    }

    #[test]
    fn test_is_sensitive_cookie() {
        assert!(is_sensitive_cookie("sessionid"));
        assert!(is_sensitive_cookie("auth_token"));
        assert!(is_sensitive_cookie("__Secure-ID"));
        assert!(!is_sensitive_cookie("theme"));
    }

    #[test]
    fn test_extract_samesite() {
        assert!(matches!(extract_samesite("session=123; SameSite=Strict"), SameSite::Strict));
        assert!(matches!(extract_samesite("session=123; SameSite=Lax"), SameSite::Lax));
        assert!(matches!(extract_samesite("session=123; SameSite=None"), SameSite::None));
        assert!(matches!(extract_samesite("session=123"), SameSite::Missing));
    }
}
