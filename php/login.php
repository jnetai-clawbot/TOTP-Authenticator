<?php
/**
 * TOTP Test Login - Example PHP Login Using Authenticator App
 * 
 * This demonstrates how to integrate TOTP authentication
 * into a PHP login system using our authenticator app.
 * 
 * Usage:
 *   php -S localhost:8000 login.php
 *   Then visit http://localhost:8000
 */

require_once __DIR__ . '/totp_auth.php';

// Start session
session_start();

// Configuration
$dbPath = __DIR__ . '/test_auth.db';
$sessionTimeout = 300; // 5 minutes for demo purposes

// Initialize app
$app = new AuthenticatorApp($dbPath);
$error = '';
$success = '';

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Check if already logged in
if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
    $timeLeft = $sessionTimeout - (time() - $_SESSION['login_time']);
    if ($timeLeft <= 0) {
        // Session expired
        session_destroy();
        $error = 'Session expired. Please login again.';
    } else {
        // Show protected page
        showProtectedPage($timeLeft);
        exit;
    }
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'setup':
            handleSetup();
            break;
        case 'login':
            handleLogin();
            break;
        case 'verify_totp':
            handleTOTPVerification();
            break;
        case 'register':
            handleRegister();
            break;
    }
}

/**
 * Handle initial password setup
 */
function handleSetup() {
    global $app, $error, $success;
    
    $password = $_POST['password'] ?? '';
    $confirm = $_POST['confirm'] ?? '';
    
    if (strlen($password) < 8) {
        $error = 'Password must be at least 8 characters.';
        return;
    }
    
    if ($password !== $confirm) {
        $error = 'Passwords do not match.';
        return;
    }
    
    try {
        $app->setupPassword($password);
        $success = 'Password set up successfully! You can now add sites and login.';
    } catch (Exception $e) {
        $error = 'Setup failed: ' . $e->getMessage();
    }
}

/**
 * Handle user registration (for demo purposes)
 */
function handleRegister() {
    global $app, $error, $success;
    
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $totpSecret = $_POST['totp_secret'] ?? '';
    
    if (empty($username) || empty($password) || empty($totpSecret)) {
        $error = 'All fields are required.';
        return;
    }
    
    // In a real app, you would hash the password and store in a user database
    // For demo, we just check if username exists in a simple text file
    
    $userFile = __DIR__ . '/users.json';
    $users = file_exists($userFile) ? json_decode(file_get_contents($userFile), true) : [];
    
    if (isset($users[$username])) {
        $error = 'Username already exists.';
        return;
    }
    
    // Validate TOTP secret format
    $totpSecret = strtoupper(preg_replace(['/\s+/', '/-+/'], '', $totpSecret));
    if (!preg_match('/^[A-Z2-7]+=*$/', $totpSecret)) {
        $error = 'Invalid TOTP secret format.';
        return;
    }
    
    // Store user with hashed password and TOTP secret
    // In production, use proper password hashing and secure storage
    $users[$username] = [
        'password_hash' => password_hash($password, PASSWORD_ARGON2ID),
        'totp_secret' => $totpSecret,
        'created_at' => date('c')
    ];
    
    file_put_contents($userFile, json_encode($users, JSON_PRETTY_PRINT));
    $success = "User '$username' registered successfully! You can now login.";
}

/**
 * Handle login
 */
function handleLogin() {
    global $app, $error;
    
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        $error = 'Username and password are required.';
        return;
    }
    
    // Load users
    $userFile = __DIR__ . '/users.json';
    $users = file_exists($userFile) ? json_decode(file_get_contents($userFile), true) : [];
    
    if (!isset($users[$username])) {
        $error = 'Invalid username or password.';
        return;
    }
    
    $user = $users[$username];
    
    // Verify password
    if (!password_verify($password, $user['password_hash'])) {
        $error = 'Invalid username or password.';
        return;
    }
    
    // Password OK - now verify TOTP
    // Store partial session data and require TOTP
    $_SESSION['pending_user'] = $username;
    $_SESSION['totp_secret'] = $user['totp_secret'];
    $_SESSION['login_step'] = 'totp';
    
    // Show TOTP verification form
    showTOTPForm();
    exit;
}

/**
 * Handle TOTP verification
 */
function handleTOTPVerification() {
    global $app, $error;
    
    $code = $_POST['totp_code'] ?? '';
    $pendingUser = $_SESSION['pending_user'] ?? '';
    $totpSecret = $_SESSION['totp_secret'] ?? '';
    
    if (empty($pendingUser) || empty($totpSecret)) {
        $error = 'Session expired. Please login again.';
        return;
    }
    
    if (empty($code) || !ctype_digit($code)) {
        $error = 'Please enter a valid TOTP code.';
        showTOTPForm();
        exit;
    }
    
    // Verify the TOTP code
    $totp = new TOTP();
    if ($totp->verify($totpSecret, $code)) {
        // TOTP verified - complete login
        $_SESSION['authenticated'] = true;
        $_SESSION['username'] = $pendingUser;
        $_SESSION['login_time'] = time();
        
        // Clear pending data
        unset($_SESSION['pending_user']);
        unset($_SESSION['totp_secret']);
        unset($_SESSION['login_step']);
        
        // Redirect to protected page
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $error = 'Invalid TOTP code. Please try again.';
        showTOTPForm();
        exit;
    }
}

/**
 * Show registration form
 */
function showRegisterForm() {
    ?>
<!DOCTYPE html>
<html>
<head>
    <title>TOTP Auth - Register</title>
    <style>
        * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #1a1a2e; color: #eee; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: #16213e; padding: 2rem; border-radius: 12px; width: 100%; max-width: 400px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); }
        h1 { text-align: center; color: #00d4ff; margin-bottom: 1.5rem; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: #aaa; }
        input { width: 100%; padding: 0.75rem; border: 1px solid #333; border-radius: 6px; background: #0f3460; color: #fff; font-size: 1rem; }
        input:focus { outline: none; border-color: #00d4ff; }
        button { width: 100%; padding: 0.875rem; background: #00d4ff; border: none; border-radius: 6px; color: #1a1a2e; font-weight: 600; font-size: 1rem; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #00a8cc; }
        .link { text-align: center; margin-top: 1rem; }
        .link a { color: #00d4ff; text-decoration: none; }
        .link a:hover { text-decoration: underline; }
        .help { font-size: 0.8rem; color: #888; margin-top: 0.25rem; }
        .error { background: #ff4757; color: white; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; }
        .success { background: #2ed573; color: #1a1a2e; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Register</h1>
        <?php global $error, $success; if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>
        
        <form method="POST">
            <input type="hidden" name="action" value="register">
            
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required placeholder="Enter username">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required placeholder="Enter password (min 8 chars)">
            </div>
            
            <div class="form-group">
                <label for="totp_secret">TOTP Secret Key</label>
                <input type="text" id="totp_secret" name="totp_secret" required placeholder="Base32 encoded secret">
                <div class="help">Enter the secret key from your authenticator app (e.g., JBSWY3DPEHPK3PXP)</div>
            </div>
            
            <button type="submit">Register</button>
        </form>
        
        <div class="link">
            Already have an account? <a href="?">Login</a>
        </div>
    </div>
</body>
</html>
    <?php
}

/**
 * Show login form
 */
function showLoginForm() {
    ?>
<!DOCTYPE html>
<html>
<head>
    <title>TOTP Auth - Login</title>
    <style>
        * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #1a1a2e; color: #eee; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: #16213e; padding: 2rem; border-radius: 12px; width: 100%; max-width: 400px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); }
        h1 { text-align: center; color: #00d4ff; margin-bottom: 1.5rem; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: #aaa; }
        input { width: 100%; padding: 0.75rem; border: 1px solid #333; border-radius: 6px; background: #0f3460; color: #fff; font-size: 1rem; }
        input:focus { outline: none; border-color: #00d4ff; }
        button { width: 100%; padding: 0.875rem; background: #00d4ff; border: none; border-radius: 6px; color: #1a1a2e; font-weight: 600; font-size: 1rem; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #00a8cc; }
        .link { text-align: center; margin-top: 1rem; }
        .link a { color: #00d4ff; text-decoration: none; }
        .link a:hover { text-decoration: underline; }
        .error { background: #ff4757; color: white; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; }
        .success { background: #2ed573; color: #1a1a2e; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 TOTP Login</h1>
        <?php global $error, $success; if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>
        
        <form method="POST">
            <input type="hidden" name="action" value="login">
            
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required placeholder="Enter username">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required placeholder="Enter password">
            </div>
            
            <button type="submit">Login with Password</button>
        </form>
        
        <div class="link">
            Don't have an account? <a href="?register">Register</a>
        </div>
    </div>
</body>
</html>
    <?php
}

/**
 * Show TOTP verification form
 */
function showTOTPForm() {
    global $error;
    ?>
<!DOCTYPE html>
<html>
<head>
    <title>TOTP Auth - Verify</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #1a1a2e; color: #eee; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: #16213e; padding: 2rem; border-radius: 12px; width: 100%; max-width: 400px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); }
        h1 { text-align: center; color: #00d4ff; margin-bottom: 1.5rem; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: #aaa; }
        input { width: 100%; padding: 0.75rem; border: 1px solid #333; border-radius: 6px; background: #0f3460; color: #fff; font-size: 1rem; text-align: center; letter-spacing: 0.5em; }
        input:focus { outline: none; border-color: #00d4ff; }
        button { width: 100%; padding: 0.875rem; background: #00d4ff; border: none; border-radius: 6px; color: #1a1a2e; font-weight: 600; font-size: 1rem; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #00a8cc; }
        .link { text-align: center; margin-top: 1rem; }
        .link a { color: #00d4ff; text-decoration: none; }
        .error { background: #ff4757; color: white; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; }
        .info { background: #0f3460; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Verify Code</h1>
        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        
        <div class="info">
            <p>Enter the 6-digit code from your authenticator app</p>
            <p><strong>User:</strong> <?= htmlspecialchars($_SESSION['pending_user'] ?? '') ?></p>
        </div>
        
        <form method="POST">
            <input type="hidden" name="action" value="verify_totp">
            
            <div class="form-group">
                <label for="totp_code">Authentication Code</label>
                <input type="text" id="totp_code" name="totp_code" required 
                       placeholder="000000" maxlength="6" autocomplete="off" autofocus>
            </div>
            
            <button type="submit">Verify</button>
        </form>
        
        <div class="link">
            <a href="?">Cancel and start over</a>
        </div>
    </div>
</body>
</html>
    <?php
}

/**
 * Show protected page after login
 */
function showProtectedPage($timeLeft) {
    ?>
<!DOCTYPE html>
<html>
<head>
    <title>TOTP Auth - Success</title>
    <style>
        * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #1a1a2e; color: #eee; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: #16213e; padding: 2rem; border-radius: 12px; width: 100%; max-width: 500px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); text-align: center; }
        h1 { color: #2ed573; margin-bottom: 1rem; }
        .success-icon { font-size: 4rem; margin-bottom: 1rem; }
        .user { background: #0f3460; padding: 1rem; border-radius: 8px; margin: 1.5rem 0; }
        .user strong { color: #00d4ff; }
        .timer { color: #ff6b6b; font-weight: bold; }
        .logout { display: inline-block; padding: 0.75rem 2rem; background: #ff4757; color: white; text-decoration: none; border-radius: 6px; margin-top: 1rem; transition: background 0.2s; }
        .logout:hover { background: #ff6b6b; }
        .info { background: #0f3460; padding: 1rem; border-radius: 8px; margin: 1rem 0; text-align: left; }
        .info h3 { color: #00d4ff; margin-top: 0; }
        .info p { margin: 0.5rem 0; color: #aaa; }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">🎉</div>
        <h1>Login Successful!</h1>
        
        <div class="user">
            Welcome, <strong><?= htmlspecialchars($_SESSION['username']) ?></strong>!
        </div>
        
        <div class="info">
            <h3>🔒 Two-Factor Authenticated</h3>
            <p>Your identity has been verified using:</p>
            <p>✓ Password verification</p>
            <p>✓ TOTP code verification (6-digit token)</p>
        </div>
        
        <p>Session expires in <span class="timer"><?= $timeLeft ?></span> seconds</p>
        
        <a href="?logout" class="logout">Logout</a>
    </div>
</body>
</html>
    <?php
}

// If no action and no session, show login form
if (!isset($_SESSION['authenticated'])) {
    if (isset($_GET['register'])) {
        showRegisterForm();
    } else {
        showLoginForm();
    }
}
