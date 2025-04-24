# Before and After WAF Implementation

This document demonstrates the effectiveness of the ModSecurity WAF by showing attack attempts before and after implementation.

## SQL Injection Attack

### Before WAF
When submitting a SQL injection payload to an unprotected application:

```
http://example.com/vulnerable-app.php?id=1 OR 1=1
```

**Result:** The application executes the SQL injection, potentially revealing all user records instead of just the requested ID.

![SQL Injection Successful](screenshots/sql-injection-before.png)

### After WAF
The same attack with ModSecurity enabled:

```
http://example.com/vulnerable-app.php?id=1 OR 1=1
```

**Result:** ModSecurity blocks the request with a 403 Forbidden error, preventing the SQL injection attack.

![SQL Injection Blocked](screenshots/sql-injection-after.png)

## Cross-Site Scripting (XSS) Attack

### Before WAF
When submitting an XSS payload to an unprotected application:

```
http://example.com/vulnerable-app.php?input=<script>alert('XSS')</script>
```

**Result:** The JavaScript executes in the victim's browser, allowing attackers to steal cookies or perform actions on behalf of the user.

![XSS Successful](screenshots/xss-before.png)

### After WAF
The same attack with ModSecurity enabled:

```
http://example.com/vulnerable-app.php?input=<script>alert('XSS')</script>
```

**Result:** ModSecurity blocks the request, preventing the XSS attack from executing.

![XSS Blocked](screenshots/xss-after.png)

## Path Traversal Attack

### Before WAF
When attempting a path traversal attack on an unprotected application:

```
http://example.com/vulnerable-app.php?page=../../../etc/passwd
```

**Result:** The application may expose sensitive system files.

![Path Traversal Successful](screenshots/path-traversal-before.png)

### After WAF
The same attack with ModSecurity enabled:

```
http://example.com/vulnerable-app.php?page=../../../etc/passwd
```

**Result:** ModSecurity blocks the request, preventing access to system files.

![Path Traversal Blocked](screenshots/path-traversal-after.png)

## Command Injection Attack

### Before WAF
When attempting a command injection attack on an unprotected application:

```
http://example.com/vulnerable-app.php?cmd=ls;cat /etc/passwd
```

**Result:** The application executes the commands on the server.

![Command Injection Successful](screenshots/command-injection-before.png)

### After WAF
The same attack with ModSecurity enabled:

```
http://example.com/vulnerable-app.php?cmd=ls;cat /etc/passwd
```

**Result:** ModSecurity blocks the request, preventing command execution.

![Command Injection Blocked](screenshots/command-injection-after.png)

## WAF Monitoring and Logging

### Security Events Dashboard
The ModSecurity WAF logs all security events, providing visibility into attack attempts.

![Security Dashboard](screenshots/security-dashboard.png)

### Attack Analysis
ModSecurity provides detailed information about each blocked attack, including:
- Attack type
- Source IP address
- Request details
- Matched rule ID
- Severity level

![Attack Analysis](screenshots/attack-analysis.png)

## Conclusion

The implementation of ModSecurity WAF significantly improves the security posture of the web application by:

1. Blocking common attack vectors
2. Providing visibility into attack attempts
3. Adding a security layer independent of application code
4. Reducing the risk of successful exploitation

While a WAF is not a silver bullet for all security issues, it serves as an effective defense-in-depth measure that complements secure coding practices and regular security testing.