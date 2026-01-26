# 🔐 Security Headers Guide

This guide explains each security header that CSPy checks, why it matters, and how to fix common issues.

---

## 📋 Table of Contents

1. [Content Security Policy (CSP)](#content-security-policy-csp)
2. [CORS (Cross-Origin Resource Sharing)](#cors)
3. [HSTS (HTTP Strict Transport Security)](#hsts)
4. [X-Frame-Options](#x-frame-options)
5. [Cookie Security](#cookie-security)
6. [Additional Headers](#additional-headers)

---

## Content Security Policy (CSP)

### What is CSP?

CSP is a security header that prevents Cross-Site Scripting (XSS), clickjacking, and other code injection attacks by controlling which resources can be loaded.

### Common Issues

#### ❌ Missing CSP Header

**Risk**: HIGH  
**Impact**: Vulnerable to XSS attacks

**Fix:**
```nginx
# Nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';";

# Apache
Header set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"

# Node.js (Helmet)
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    objectSrc: ["'none'"]
  }
}));
```

---

#### ❌ unsafe-inline in CSP

**Risk**: HIGH  
**Why it's bad**: Allows inline `<script>` tags, making XSS attacks possible

**Bad:**
```http
Content-Security-Policy: script-src 'self' 'unsafe-inline'
```

**Fix Option 1: Use Nonces**
```html
<!-- Server generates unique nonce for each request -->
<script nonce="random-nonce-123">
  console.log('Safe inline script');
</script>
```

```http
Content-Security-Policy: script-src 'self' 'nonce-random-nonce-123'
```

**Fix Option 2: Use Hashes**
```http
Content-Security-Policy: script-src 'self' 'sha256-abc123...'
```

**Fix Option 3: Move to External Files (Best)**
```html
<!-- Instead of inline -->
<script src="/js/app.js"></script>
```

---

#### ❌ Wildcard in script-src

**Risk**: CRITICAL  
**Example:**
```http
Content-Security-Policy: script-src *
```

**Fix:**
```http
Content-Security-Policy: script-src 'self' cdn.example.com
```

---

#### ❌ Missing default-src

**Risk**: MEDIUM  
**Why**: No fallback for undefined directives

**Fix:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self' cdn.example.com
```

---

### CSP Best Practices

#### ✅ Secure CSP Template

```http
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' cdn.example.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' fonts.gstatic.com;
  connect-src 'self' api.example.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  object-src 'none';
  upgrade-insecure-requests;
```

#### CSP for Single Page Apps (React/Vue/Angular)

```http
Content-Security-Policy: 
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: blob:;
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  base-uri 'self';
  object-src 'none';
```

---

## CORS

### What is CORS?

CORS controls which websites can access your resources via JavaScript.

### Common Issues

#### ❌ Wildcard Origin with Credentials (CRITICAL)

**Risk**: CRITICAL  
**Example:**
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

**Impact**: Any website can steal user data and session cookies

**Fix:**
```http
Access-Control-Allow-Origin: https://trusted-app.example.com
Access-Control-Allow-Credentials: true
```

**Code Examples:**

**Express.js:**
```javascript
app.use((req, res, next) => {
  const allowedOrigins = ['https://app.example.com'];
  const origin = req.headers.origin;
  
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});
```

**Django:**
```python
CORS_ALLOWED_ORIGINS = [
    "https://app.example.com",
]
CORS_ALLOW_CREDENTIALS = True
```

---

#### ❌ Null Origin Allowed

**Risk**: HIGH  
**Example:**
```http
Access-Control-Allow-Origin: null
```

**Impact**: Can be exploited via sandboxed iframes

**Fix:** Never allow `null` origin

---

#### ❌ HTTP Origins

**Risk**: MEDIUM  
**Example:**
```http
Access-Control-Allow-Origin: http://example.com
```

**Impact**: Vulnerable to Man-in-the-Middle attacks

**Fix:**
```http
Access-Control-Allow-Origin: https://example.com
```

---

### CORS Best Practices

#### ✅ For Public APIs (No Authentication)

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST
Access-Control-Max-Age: 3600
```

#### ✅ For Private APIs (With Authentication)

```http
Access-Control-Allow-Origin: https://trusted-app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 3600
```

---

## HSTS

### What is HSTS?

HSTS forces browsers to always use HTTPS, preventing protocol downgrade attacks.

### Common Issues

#### ❌ Missing HSTS

**Risk**: MEDIUM  
**Impact**: Users can be redirected to HTTP version

**Fix:**
```nginx
# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

---

#### ❌ Short max-age

**Risk**: MEDIUM  
**Example:**
```http
Strict-Transport-Security: max-age=3600
```

**Fix:**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Recommended max-age values:**
- Minimum: 15768000 (6 months)
- Recommended: 31536000 (1 year)
- Preload eligible: 31536000 (1 year)

---

### HSTS Best Practices

#### ✅ Full HSTS Configuration

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Breakdown:**
- `max-age=31536000`: 1 year
- `includeSubDomains`: Apply to all subdomains
- `preload`: Eligible for browser preload lists

#### Preload List Submission

After setting HSTS for 1 year, submit to: https://hstspreload.org/

---

## X-Frame-Options

### What is X-Frame-Options?

Prevents clickjacking by controlling if your site can be embedded in frames/iframes.

### Common Issues

#### ❌ Missing X-Frame-Options

**Risk**: MEDIUM  
**Impact**: Vulnerable to clickjacking attacks

**Fix:**
```http
X-Frame-Options: DENY
```

**Options:**
- `DENY`: Never allow framing
- `SAMEORIGIN`: Allow only same-origin framing

---

#### ❌ ALLOWALL

**Risk**: HIGH  
**Example:**
```http
X-Frame-Options: ALLOWALL
```

**Fix:**
```http
X-Frame-Options: DENY
```

---

### Modern Alternative: CSP frame-ancestors

```http
Content-Security-Policy: frame-ancestors 'none'
```

**Or allow specific origins:**
```http
Content-Security-Policy: frame-ancestors 'self' https://trusted.example.com
```

---

## Cookie Security

### Common Issues

#### ❌ Missing Secure Flag

**Risk**: MEDIUM  
**Impact**: Cookie can be sent over unencrypted HTTP

**Bad:**
```http
Set-Cookie: sessionid=abc123; HttpOnly
```

**Fix:**
```http
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict
```

---

#### ❌ Missing HttpOnly Flag

**Risk**: MEDIUM  
**Impact**: JavaScript can access cookie (XSS risk)

**Fix:**
```http
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict
```

---

#### ❌ Missing SameSite

**Risk**: LOW-MEDIUM  
**Impact**: Vulnerable to CSRF attacks

**Options:**
- `Strict`: Never sent cross-site (most secure)
- `Lax`: Sent on top-level navigation (recommended)
- `None`: Sent everywhere (requires Secure)

**Fix:**
```http
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Lax
```

---

### Cookie Best Practices

#### ✅ Session Cookie

```http
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```

#### ✅ Authentication Cookie

```http
Set-Cookie: __Host-auth=xyz789; Secure; HttpOnly; SameSite=Strict; Path=/
```

**Note**: `__Host-` prefix ensures:
- Must have Secure flag
- Cannot have Domain attribute
- Must have Path=/

#### ✅ Preference Cookie (Non-sensitive)

```http
Set-Cookie: theme=dark; Secure; SameSite=Lax; Max-Age=31536000
```

---

## Additional Headers

### X-Content-Type-Options

**Purpose**: Prevent MIME sniffing

**Fix:**
```http
X-Content-Type-Options: nosniff
```

---

### Referrer-Policy

**Purpose**: Control referrer information sent

**Fix:**
```http
Referrer-Policy: strict-origin-when-cross-origin
```

**Options:**
- `no-referrer`: Never send
- `strict-origin`: Send origin only
- `strict-origin-when-cross-origin`: Recommended

---

### Permissions-Policy

**Purpose**: Control browser features

**Fix:**
```http
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

---

## Complete Security Headers Example

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    # SSL Configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';" always;
}
```

### Apache

```apache
<VirtualHost *:443>
    ServerName example.com

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'"
</VirtualHost>
```

### Express.js (Node.js)

```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: {
    action: 'deny'
  },
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  }
}));
```

---

## Testing Your Fixes

After implementing security headers:

1. **Use CSPy:**
   ```bash
   cspy https://yoursite.com
   ```

2. **Browser DevTools:**
   - Open DevTools → Network tab
   - Check Response Headers

3. **Online Tools:**
   - https://securityheaders.com
   - https://observatory.mozilla.org

---

## Priority Guide

### Fix in This Order:

1. **CRITICAL** (Fix NOW)
   - CORS wildcard with credentials
   - CSP wildcards in script-src

2. **HIGH** (Fix This Week)
   - Missing CSP
   - unsafe-inline in CSP
   - Missing Secure on auth cookies

3. **MEDIUM** (Fix This Month)
   - Missing HSTS
   - Missing X-Frame-Options
   - Weak CORS policies

4. **LOW** (Schedule)
   - Missing SameSite on cookies
   - Additional headers

---

**For more information, consult:**
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [CSP Reference](https://content-security-policy.com/)
