# 🚀 CSPy Quick Start Guide

## 📦 Prerequisites

Before you begin, ensure you have:
- **Rust** (1.70 or later): [Install Rust](https://rustup.rs/)
- **Git**: For cloning the repository

## 🔧 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/alhamrivi-cloud/cspy.git
cd CSPy
```

### Step 2: Build the Project

```bash
# Debug build (faster compilation, slower runtime)
cargo build

# Release build (slower compilation, faster runtime - RECOMMENDED)
cargo build --release
```

### Step 3: Run CSPy

```bash
# Using debug build
./target/debug/cspy https://example.com

# Using release build (recommended)
./target/release/cspy https://example.com
```

### Step 4: (Optional) Install Globally

```bash
cargo install --path .
```

Now you can use `cspy` from anywhere:

```bash
cspy https://example.com
```

---

## 🎯 Common Usage Scenarios

### 1️⃣ Scan a Single Website

```bash
cspy https://example.com
```

**Example Output:**
```
→ https://example.com
  Status: 200
  ⚠ Issues found:
    1 High
    2 Medium

  [HIGH] CSP: Missing Content-Security-Policy header
    → Implement CSP to prevent XSS and other injection attacks
```

---

### 2️⃣ Scan Multiple Websites

Create a file `targets.txt`:
```
https://example.com
https://api.example.com
https://admin.example.com
```

Run the scan:
```bash
cspy -i targets.txt
```

---

### 3️⃣ Export Results to JSON

```bash
# Scan and save as JSON
cspy https://example.com --output json -f results.json

# View the JSON file
cat results.json
```

**JSON Structure:**
```json
{
  "scan_time": "2026-01-27T10:30:00Z",
  "total_scanned": 1,
  "results": [
    {
      "url": "https://example.com",
      "status": 200,
      "issues": [...]
    }
  ]
}
```

---

### 4️⃣ Minimal Output (For Scripts)

```bash
cspy https://example.com --output minimal
```

**Output:**
```
  ✓ C:0 H:0 M:1 L:2
```

Symbols:
- ✓ = Safe
- ● = Medium issues
- ⚠ = High issues
- ✖ = Critical issues

---

### 5️⃣ Silent Mode (Exit Codes Only)

```bash
cspy https://example.com --silent
echo $?  # Check exit code
```

Perfect for CI/CD pipelines!

---

### 6️⃣ Custom Timeout and User-Agent

```bash
# 30-second timeout with custom UA
cspy https://slow-site.com -t 30 -A "CSPy Security Scanner"
```

---

### 7️⃣ Bulk Scan with Report

```bash
# Scan multiple sites and save detailed report
cspy -i urls.txt -f report.json --output json

# Or save as text
cspy -i urls.txt -f report.txt --output pretty
```

---

## 🔍 Understanding the Output

### Severity Levels

| Level | Symbol | Meaning | Action |
|-------|--------|---------|--------|
| **CRITICAL** | ✖ | Immediate security risk | Fix NOW |
| **HIGH** | ⚠ | Significant vulnerability | Fix soon |
| **MEDIUM** | ● | Important misconfiguration | Schedule fix |
| **LOW** | • | Minor issue | Consider fixing |
| **INFO** | ℹ | Informational | Review |

### Common Issues You'll See

#### 🔴 CRITICAL

```
[CRITICAL] CORS: CORS allows all origins (*) with credentials
→ NEVER use wildcard (*) with Access-Control-Allow-Credentials: true
```

**What it means**: Any website can steal user data  
**Fix**: Specify exact allowed origins

---

#### 🟠 HIGH

```
[HIGH] CSP: CSP allows 'unsafe-inline'
→ Remove 'unsafe-inline' and use nonces or hashes
```

**What it means**: Vulnerable to XSS attacks  
**Fix**: Use CSP nonces or hashes for inline scripts

---

#### 🟡 MEDIUM

```
[MEDIUM] HSTS: Missing Strict-Transport-Security header
→ Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'
```

**What it means**: Connection can be downgraded to HTTP  
**Fix**: Add HSTS header

---

## 🎓 Real-World Examples

### Example 1: E-commerce Site

```bash
cspy https://shop.example.com
```

**Focus on:**
- Cookie security (payment session)
- CSP (prevent card skimming)
- CORS (protect API endpoints)

---

### Example 2: API Security Audit

```bash
cspy https://api.example.com/v1
```

**Focus on:**
- CORS configuration
- Authentication cookie flags
- Security headers

---

### Example 3: CI/CD Integration

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Headers Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        
      - name: Build CSPy
        run: cargo build --release
        
      - name: Run Security Scan
        run: |
          ./target/release/cspy https://staging.example.com --output json -f results.json
          
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-scan
          path: results.json
```

---

## 🐛 Troubleshooting

### Issue: "Failed to create HTTP client"

**Solution**: Check network connectivity and firewall settings

---

### Issue: "SSL/TLS error"

**Solution**: Use `--no-verify` flag (coming soon) or fix the certificate

---

### Issue: Timeout errors

**Solution**: Increase timeout
```bash
cspy https://slow-site.com -t 60
```

---

### Issue: Permission denied (when installing globally)

**Solution**: Use cargo install path or add sudo
```bash
sudo cargo install --path .
```

---

## 📊 Interpreting Results

### ✅ Good Security Posture

```
→ https://secure-site.com
  Status: 200
  ✓ No security issues found!
```

### ⚠️ Needs Improvement

```
→ https://insecure-site.com
  Status: 200
  ⚠ Issues found:
    1 Critical
    3 High
    5 Medium
```

**Action**: Review and fix critical/high issues immediately

---

## 🎯 Next Steps

1. **Learn More**: Read the [full README](README.md)
2. **Security Headers**: Check [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/)
3. **Contribute**: Submit issues or PRs on GitHub
4. **Share**: Star the repo if you find it useful!

---

## 💡 Pro Tips

1. **Save your scans**: Always use `-f` to keep audit trails
2. **Compare over time**: Scan regularly to track improvements
3. **Automate**: Integrate into CI/CD for continuous monitoring
4. **Prioritize**: Fix Critical → High → Medium → Low
5. **Test after fixes**: Re-scan to verify remediation

---

## 📞 Getting Help

- **Issues**: Open a GitHub issue
- **Questions**: Check existing issues or discussions
- **Security**: Report security issues privately

---

**Happy Scanning! 🔒**
