# CSPy

**Content Security Policy & HTTP Security Headers Analyzer**

A blazing-fast Rust tool for analyzing security headers and detecting misconfigurations in web applications. Perfect for security audits, CI/CD integration, and compliance checks.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

---

## 🎯 Features

### 🔍 Comprehensive Security Checks

- **Content Security Policy (CSP)**: Detects unsafe-inline, unsafe-eval, wildcards, and missing directives
- **CORS**: Identifies dangerous wildcard origins, credential misconfigurations, and overly permissive policies
- **HSTS**: Validates max-age, checks for includeSubDomains and preload directives
- **X-Frame-Options**: Prevents clickjacking with proper frame control analysis
- **Cookie Security**: Validates Secure, HttpOnly, and SameSite flags
- **Additional Headers**: Checks X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and more

### ⚡ Performance & Usability

- **Fast**: Async I/O powered by Tokio
- **Beautiful Output**: Color-coded severity levels with clear recommendations
- **Multiple Formats**: Pretty CLI output, JSON for automation, or minimal mode
- **Bulk Scanning**: Scan multiple URLs from a file
- **Export Results**: Save findings to file for reporting

---

## 📦 Installation

### From Source

```bash
git clone https://github.com/alhamrizvi-cloud/cspy.git
cd CSPy
cargo build --release
```

The binary will be at `target/release/cspy`

### Using Cargo

```bash
cargo install --path .
```

---

## 🚀 Usage

### Basic Scan

```bash
cspy https://example.com
```

### Scan Multiple URLs

```bash
cspy -i urls.txt
```

### JSON Output

```bash
cspy https://example.com --output json
```

### Save Results to File

```bash
cspy https://example.com -f report.json --output json
```

### Silent Mode

```bash
cspy https://example.com --silent
```

### Custom User-Agent

```bash
cspy https://example.com -A "MyScanner/1.0"
```

---

## 📋 Command-Line Options

```
Usage: cspy [OPTIONS] [URL]

Arguments:
  [URL]  Target URL to scan

Options:
  -i, --input <FILE>           Input file containing URLs (one per line)
  -o, --output <FORMAT>        Output format [default: pretty] [possible values: pretty, json, minimal]
  -f, --output-file <FILE>     Save results to file
  -s, --silent                 Silent mode (minimal output)
  -r, --redirect               Follow redirects [default: true]
      --max-redirects <NUM>    Maximum redirects to follow [default: 10]
  -t, --timeout <SECONDS>      Request timeout in seconds [default: 10]
  -A, --user-agent <STRING>    Custom User-Agent
  -h, --help                   Print help
  -V, --version                Print version
```

---

## 🎨 Example Output

```
 ______     ______     ______   __  __    
/\  ___\   /\  ___\   /\  == \ /\ \_\ \   
\ \ \____  \ \___  \  \ \  _-/ \ \____ \  
 \ \_____\  \/\_____\  \ \_\    \/\_____\ 
  \/_____/   \/_____/   \/_/     \/_____/ 
                                          
Content Security Policy & HTTP Security Headers Analyzer
By Security Researcher | v0.1.0

→ https://example.com
  Status: 200
  ⚠ Issues found:
    2 High
    3 Medium
    1 Low

  [HIGH] CSP: CSP allows 'unsafe-inline'
    → Remove 'unsafe-inline' and use nonces or hashes for inline scripts/styles

  [MEDIUM] HSTS: Missing Strict-Transport-Security header
    → Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS

  [MEDIUM] X-Frame-Options: Missing X-Frame-Options header
    → Add 'X-Frame-Options: DENY' or use CSP 'frame-ancestors 'none'' to prevent clickjacking
```

---

## 🔒 Security Checks Explained

### Content Security Policy (CSP)

Checks for:
- ❌ Missing CSP header
- ❌ `unsafe-inline` or `unsafe-eval`
- ❌ Wildcard sources in `script-src`
- ❌ Missing `default-src` or `object-src`
- ❌ Unsafe `base-uri` or `form-action`

**Best Practice:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self' cdn.example.com; object-src 'none'; base-uri 'self'
```

### CORS

Checks for:
- ❌ Wildcard origin with credentials (CRITICAL)
- ❌ Null origin allowed
- ❌ HTTP origins
- ❌ Wildcard methods or headers

**Best Practice:**
```http
Access-Control-Allow-Origin: https://trusted.example.com
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Credentials: true
```

### HSTS

Checks for:
- ❌ Missing HSTS header
- ❌ `max-age` less than 6 months
- ❌ Missing `includeSubDomains`
- ❌ Missing `preload` directive

**Best Practice:**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### Cookies

Checks for:
- ❌ Missing `Secure` flag
- ❌ Missing `HttpOnly` flag
- ❌ Missing `SameSite` attribute
- ❌ Invalid `__Host-` or `__Secure-` prefix usage

**Best Practice:**
```http
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
```

---

## 🎓 Learning Resources

### Security Standards
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [Content Security Policy Reference](https://content-security-policy.com/)

### Rust HTTP
- [Reqwest Documentation](https://docs.rs/reqwest/)
- [Tokio Async Book](https://tokio.rs/tokio/tutorial)

---

## 💼 Use Cases

✅ **Security Audits**: Quickly scan applications for header misconfigurations  
✅ **CI/CD Integration**: Automate security checks in your pipeline  
✅ **Compliance**: Validate PCI-DSS, SOC2, and other security requirements  
✅ **Bug Bounty**: Find low-hanging fruit in header configurations  
✅ **DevSecOps**: Shift-left security testing  

---

## 🛠️ Development

### Project Structure

```
cspy/
├── src/
│   ├── main.rs           # CLI and entry point
│   ├── scanner.rs        # HTTP client and orchestration
│   ├── output.rs         # Output formatting
│   └── checks/
│       ├── mod.rs        # Shared types
│       ├── csp.rs        # CSP analyzer
│       ├── cors.rs       # CORS analyzer
│       ├── hsts.rs       # HSTS analyzer
│       ├── xframe.rs     # X-Frame-Options analyzer
│       └── cookies.rs    # Cookie security analyzer
├── Cargo.toml
└── README.md
```

### Running Tests

```bash
cargo test
```

### Building for Release

```bash
cargo build --release
```

---

## 📝 Example Input File

Create a `urls.txt` file:

```
https://example.com
https://api.example.com
https://admin.example.com
https://checkout.example.com
```

Then scan:

```bash
cspy -i urls.txt -f results.json --output json
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- OWASP for security best practices
- Mozilla for web security guidelines
- The Rust community for amazing tools

---

## 🔮 Roadmap

- [ ] WAF detection
- [ ] Technology fingerprinting
- [ ] HTTP/2 support
- [ ] Comparative analysis (HTTP vs HTTPS)
- [ ] Custom rule engine
- [ ] PDF report generation
- [ ] Web UI dashboard

---

**Made with ❤️ and Rust**

*For security researchers, by security researchers*
