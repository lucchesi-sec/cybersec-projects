# Before and After WAF Implementation 🤖

> **Note:** This document contains conceptual examples of how attacks would be handled with and without a WAF. The screenshots referenced are placeholders - in a real implementation, you would need to generate your own evidence of WAF effectiveness.

## SQL Injection Attack

### Before WAF
When submitting a SQL injection payload to an unprotected application:

```
http://yourserver.com/app.php?id=1 OR 1=1
```

**Result:** The application executes the SQL injection, potentially revealing all user records instead of just the requested ID.

[SQL Injection Successful - In an unprotected application, this would return all records]

### After WAF
The same attack with ModSecurity enabled:

```
http://yourserver.com/app.php?id=1 OR 1=1
```

**Result:** ModSecurity blocks the request with a 403 Forbidden error, preventing the SQL injection attack.

[SQL Injection Blocked - With ModSecurity, you would see a 403 Forbidden error page]

## Cross-Site Scripting (XSS) Attack

### Before WAF
When submitting an XSS payload to an unprotected application:

```
http://yourserver.com/app.php?input=<script>alert('XSS')</script>
```

**Result:** The JavaScript executes in the victim's browser, allowing attackers to steal cookies or perform actions on behalf of the user.

[XSS Successful - In an unprotected application, you would see a JavaScript alert box]

### After WAF
The same attack with ModSecurity enabled:

```
http://yourserver.com/app.php?input=<script>alert('XSS')</script>
```

**Result:** ModSecurity blocks the request, preventing the XSS attack from executing.

[XSS Blocked - With ModSecurity, you would see a 403 Forbidden error page]

## Path Traversal Attack

### Before WAF
When attempting a path traversal attack on an unprotected application:

```
http://yourserver.com/app.php?page=../../../etc/passwd
```

**Result:** The application may expose sensitive system files.

[Path Traversal Successful - In an unprotected application, you might see the contents of /etc/passwd]

### After WAF
The same attack with ModSecurity enabled:

```
http://yourserver.com/app.php?page=../../../etc/passwd
```

**Result:** ModSecurity blocks the request, preventing access to system files.

[Path Traversal Blocked - With ModSecurity, you would see a 403 Forbidden error page]

## Command Injection Attack

### Before WAF
When attempting a command injection attack on an unprotected application:

```
http://yourserver.com/app.php?cmd=ls;cat /etc/passwd
```

**Result:** The application executes the commands on the server.

[Command Injection Successful - In an unprotected application, you would see directory listings and file contents]

### After WAF
The same attack with ModSecurity enabled:

```
http://yourserver.com/app.php?cmd=ls;cat /etc/passwd
```

**Result:** ModSecurity blocks the request, preventing command execution.

[Command Injection Blocked - With ModSecurity, you would see a 403 Forbidden error page]

## WAF Monitoring and Logging

### Security Events Dashboard
The ModSecurity WAF logs all security events, providing visibility into attack attempts.

Example log entry for a blocked SQL injection:
```
[2023-09-15 12:34:56] [client 192.168.1.100] ModSecurity: Access denied with code 403 (phase 2).
Matched "Operator `Rx' with parameter `(?i:(?:\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:(?:addextendedpro|sqlexe)c|(?:oacreat|prepexe)e|execute)|ql_(?:query|step)|SaveToFile|sqlite_))\b|exec\b.{1,100}?\bopen))'
against argument `id'. [file "/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "504"] [id "942440"] [rev ""] [msg "SQL Comment Sequence Detected"] [data "OR 1=1"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/152/248/66"] [tag "PCI/6.5.2"] [hostname "yourserver.com"] [uri "/app.php"] [unique_id "YYoq@8CoAwsAAFT5btcAAAAA"]
```

## Conclusion

The implementation of ModSecurity WAF significantly improves the security posture of web applications by:

1. Blocking common attack vectors before they reach the application
2. Providing visibility into attack attempts through detailed logging
3. Adding a security layer independent of application code
4. Reducing the risk of successful exploitation

While a WAF is not a complete solution for all security issues, it serves as an effective defense-in-depth measure that complements secure coding practices and regular security testing.

## Implementation Steps

For detailed implementation instructions, refer to the `install-guide.md` document in this repository.
