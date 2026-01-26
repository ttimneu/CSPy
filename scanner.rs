use reqwest::{Client, redirect::Policy};
use std::time::Duration;
use url::Url;

use crate::checks::{ScanResult, SecurityIssue, Severity};

pub struct Scanner {
    client: Client,
}

impl Scanner {
    pub fn new(
        timeout: u64,
        follow_redirects: bool,
        max_redirects: usize,
        user_agent: Option<String>,
    ) -> Self {
        let redirect_policy = if follow_redirects {
            Policy::limited(max_redirects)
        } else {
            Policy::none()
        };

        let ua = user_agent.unwrap_or_else(|| {
            "CSPy/0.1.0 (Security Scanner)".to_string()
        });

        let client = Client::builder()
            .redirect(redirect_policy)
            .timeout(Duration::from_secs(timeout))
            .user_agent(ua)
            .danger_accept_invalid_certs(true) // For testing purposes
            .build()
            .expect("Failed to create HTTP client");

        Scanner { client }
    }

    pub async fn scan(&self, target: &str) -> Result<ScanResult, Box<dyn std::error::Error>> {
        // Normalize URL
        let url = self.normalize_url(target)?;
        
        // Send request
        let response = self.client.get(url.as_str()).send().await?;
        
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let final_url = response.url().to_string();

        // Analyze headers
        let mut issues = Vec::new();
        
        // Check CSP
        issues.extend(crate::checks::csp::check(&headers));
        
        // Check CORS
        issues.extend(crate::checks::cors::check(&headers));
        
        // Check HSTS
        issues.extend(crate::checks::hsts::check(&headers));
        
        // Check X-Frame-Options
        issues.extend(crate::checks::xframe::check(&headers));
        
        // Check Cookies
        issues.extend(crate::checks::cookies::check(&headers));
        
        // Additional security headers
        issues.extend(self.check_additional_headers(&headers));

        Ok(ScanResult {
            url: final_url,
            status,
            issues,
        })
    }

    fn normalize_url(&self, target: &str) -> Result<Url, Box<dyn std::error::Error>> {
        let normalized = if target.starts_with("http://") || target.starts_with("https://") {
            target.to_string()
        } else {
            format!("https://{}", target)
        };

        Ok(Url::parse(&normalized)?)
    }

    fn check_additional_headers(&self, headers: &reqwest::header::HeaderMap) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        // X-Content-Type-Options
        if !headers.contains_key("x-content-type-options") {
            issues.push(SecurityIssue {
                category: "X-Content-Type-Options".to_string(),
                severity: Severity::Low,
                message: "Missing X-Content-Type-Options header".to_string(),
                recommendation: "Add 'X-Content-Type-Options: nosniff' to prevent MIME sniffing".to_string(),
            });
        }

        // X-XSS-Protection (deprecated but still checked)
        if let Some(xss) = headers.get("x-xss-protection") {
            if let Ok(value) = xss.to_str() {
                if value.contains("0") {
                    issues.push(SecurityIssue {
                        category: "X-XSS-Protection".to_string(),
                        severity: Severity::Low,
                        message: "X-XSS-Protection is disabled".to_string(),
                        recommendation: "Consider removing this header (deprecated) and using CSP instead".to_string(),
                    });
                }
            }
        }

        // Referrer-Policy
        if !headers.contains_key("referrer-policy") {
            issues.push(SecurityIssue {
                category: "Referrer-Policy".to_string(),
                severity: Severity::Low,
                message: "Missing Referrer-Policy header".to_string(),
                recommendation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter".to_string(),
            });
        }

        // Permissions-Policy
        if !headers.contains_key("permissions-policy") {
            issues.push(SecurityIssue {
                category: "Permissions-Policy".to_string(),
                severity: Severity::Info,
                message: "Missing Permissions-Policy header".to_string(),
                recommendation: "Consider adding Permissions-Policy to control browser features".to_string(),
            });
        }

        issues
    }
}
