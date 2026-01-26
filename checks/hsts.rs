use super::{SecurityIssue, Severity};
use reqwest::header::HeaderMap;

const SIX_MONTHS_SECONDS: i64 = 15768000;  // 6 months in seconds
const ONE_YEAR_SECONDS: i64 = 31536000;    // 1 year in seconds

pub fn check(headers: &HeaderMap) -> Vec<SecurityIssue> {
    let mut issues = Vec::new();

    let hsts = match headers.get("strict-transport-security") {
        Some(value) => match value.to_str() {
            Ok(v) => v,
            Err(_) => return issues,
        },
        None => {
            issues.push(SecurityIssue {
                category: "HSTS".to_string(),
                severity: Severity::Medium,
                message: "Missing Strict-Transport-Security header".to_string(),
                recommendation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS".to_string(),
            });
            return issues;
        }
    };

    // Extract max-age value
    let max_age = extract_max_age(hsts);

    match max_age {
        Some(age) => {
            if age < SIX_MONTHS_SECONDS {
                issues.push(SecurityIssue {
                    category: "HSTS".to_string(),
                    severity: Severity::Medium,
                    message: format!("HSTS max-age is too short ({} seconds, ~{} days)", age, age / 86400),
                    recommendation: "Increase max-age to at least 6 months (15768000 seconds) or preferably 1 year".to_string(),
                });
            }

            if age < ONE_YEAR_SECONDS {
                issues.push(SecurityIssue {
                    category: "HSTS".to_string(),
                    severity: Severity::Info,
                    message: "HSTS max-age is less than 1 year".to_string(),
                    recommendation: "Consider increasing to 1 year (31536000) for stronger protection".to_string(),
                });
            }
        }
        None => {
            issues.push(SecurityIssue {
                category: "HSTS".to_string(),
                severity: Severity::High,
                message: "HSTS header missing max-age directive".to_string(),
                recommendation: "Add max-age directive: max-age=31536000".to_string(),
            });
        }
    }

    // Check for includeSubDomains
    if !hsts.to_lowercase().contains("includesubdomains") {
        issues.push(SecurityIssue {
            category: "HSTS".to_string(),
            severity: Severity::Low,
            message: "HSTS missing 'includeSubDomains' directive".to_string(),
            recommendation: "Add 'includeSubDomains' to protect all subdomains with HSTS".to_string(),
        });
    }

    // Check for preload
    if !hsts.to_lowercase().contains("preload") {
        issues.push(SecurityIssue {
            category: "HSTS".to_string(),
            severity: Severity::Info,
            message: "HSTS missing 'preload' directive".to_string(),
            recommendation: "Consider adding 'preload' and submitting to hstspreload.org for browser preload lists".to_string(),
        });
    }

    issues
}

fn extract_max_age(hsts: &str) -> Option<i64> {
    // Find max-age directive
    for part in hsts.split(';') {
        let trimmed = part.trim();
        if trimmed.to_lowercase().starts_with("max-age") {
            // Extract the value after '='
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
    fn test_extract_max_age() {
        assert_eq!(
            extract_max_age("max-age=31536000; includeSubDomains"),
            Some(31536000)
        );
        
        assert_eq!(
            extract_max_age("max-age=3600"),
            Some(3600)
        );
        
        assert_eq!(
            extract_max_age("includeSubDomains; max-age=86400; preload"),
            Some(86400)
        );
        
        assert_eq!(
            extract_max_age("includeSubDomains"),
            None
        );
    }

    #[test]
    fn test_short_max_age() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "strict-transport-security",
            reqwest::header::HeaderValue::from_static("max-age=3600")
        );
        
        let issues = check(&headers);
        assert!(issues.iter().any(|i| i.message.contains("too short")));
    }
}
