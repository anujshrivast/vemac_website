<?php
session_start();
require_once 'db_connect.php'; // Ensure this contains your database connection

// Security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");

// Rate limiting to prevent brute force
if (!isset($_SESSION['reset_attempts'])) {
    $_SESSION['reset_attempts'] = 0;
    $_SESSION['last_reset_time'] = time();
}

if ($_SESSION['reset_attempts'] >= 5 && (time() - $_SESSION['last_reset_time']) < 3600) {
    die("<script>showMessage('Too many attempts. Please try again later.', 'error');</script>");
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        try {
            // Prepare and bind
            $stmt = $conn->prepare("SELECT id, name, role FROM users WHERE email = ? AND status = 'active'");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();
                
                // Generate secure reset token
                $token = bin2hex(random_bytes(32));
                $expiry = date("Y-m-d H:i:s", strtotime('+30 minutes')); // Shorter expiry for security
                
                // Store token with hash
                $token_hash = password_hash($token, PASSWORD_DEFAULT);
                
                $updateStmt = $conn->prepare("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?");
                $updateStmt->bind_param("ssi", $token_hash, $expiry, $user['id']);
                
                if ($updateStmt->execute()) {
                    // In a real implementation, you would send an email here
                    // For now, we'll show a message to contact the office incharge
                    $_SESSION['reset_email'] = $email; // Store for confirmation page
                    $_SESSION['reset_attempts'] = 0; // Reset attempts on success
                    
                    // Log this reset attempt
                    $logStmt = $conn->prepare("INSERT INTO password_reset_logs (user_id, email, ip_address, user_agent) VALUES (?, ?, ?, ?)");
                    $ip = $_SERVER['REMOTE_ADDR'];
                    $agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
                    $logStmt->bind_param("isss", $user['id'], $email, $ip, $agent);
                    $logStmt->execute();
                    
                    header("Location: reset_instructions.php");
                    exit();
                } else {
                    throw new Exception("Failed to update reset token");
                }
                
                $updateStmt->close();
            } else {
                $_SESSION['reset_attempts']++;
                $_SESSION['last_reset_time'] = time();
                echo "<script>showMessage('If this email exists in our system, you will receive reset instructions.', 'info');</script>";
            }
            
            $stmt->close();
        } catch (Exception $e) {
            error_log("Password reset error: " . $e->getMessage());
            echo "<script>showMessage('An error occurred. Please try again later.', 'error');</script>";
        }
    } else {
        echo "<script>showMessage('Please enter a valid email address.', 'error');</script>";
    }
    
    $conn->close();
    header("Location: login.html");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password | Vemac </title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #3498db;
            --secondary-color: #2980b9;
            --success-color: #2ecc71;
            --danger-color: #e74c3c;
            --light-color: #f8f9fa;
            --dark-color: #343a40;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            padding: 20px;
        }
        
        .auth-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 450px;
            overflow: hidden;
            animation: fadeIn 0.5s ease-in-out;
        }
        
        .auth-header {
            background: var(--primary-color);
            color: white;
            padding: 25px;
            text-align: center;
        }
        
        .auth-body {
            padding: 30px;
        }
        
        .form-control {
            padding: 12px 15px;
            border-radius: 8px;
            border: 1px solid #ddd;
            transition: all 0.3s;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.25rem rgba(52, 152, 219, 0.25);
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border: none;
            padding: 12px;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .btn-primary:hover {
            background-color: var(--secondary-color);
            transform: translateY(-2px);
        }
        
        .btn-block {
            width: 100%;
        }
        
        .message {
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        
        .message.error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .message.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .message.info {
            background-color: #e2e3e5;
            color: #383d41;
            border: 1px solid #d6d8db;
        }
        
        .auth-footer {
            text-align: center;
            padding: 15px;
            background-color: var(--light-color);
            font-size: 14px;
        }
        
        .auth-footer a {
            color: var(--primary-color);
            text-decoration: none;
        }
        
        .logo {
            max-height: 60px;
            margin-bottom: 15px;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @media (max-width: 576px) {
            .auth-container {
                border-radius: 0;
            }
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="auth-header">
            <img src="images/logo.png" alt="School Logo" class="logo">
            <h2>Reset Your Password</h2>
            <p class="mb-0">Enter your email to receive reset instructions</p>
        </div>
        
        <div class="auth-body">
            <div id="message" class="message"></div>
            
            <form id="resetForm"  method="POST" novalidate>
                <div class="mb-3">
                    <label for="email" class="form-label">Email Address</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-envelope"></i></span>
                        <input type="email" class="form-control" id="email" name="email" 
                               placeholder="Enter your registered email" required>
                    </div>
                    <div class="invalid-feedback">Please provide a valid email address.</div>
                </div>
                
                <button type="submit" class="btn btn-primary btn-block mb-3">
                    <i class="fas fa-key me-2"></i> Request Reset Link
                </button>
                
                <div class="text-center mt-3">
                    <a href="login.php" class="text-decoration-none">
                        <i class="fas fa-arrow-left me-2"></i>Back to Login
                    </a>
                </div>
            </form>
        </div>
        
        <div class="auth-footer">
            Need help? Contact your <a href="mailto:incharge@school.edu">Office Incharge</a>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Form validation and message display
        function showMessage(text, type) {
            const messageEl = document.getElementById('message');
            messageEl.textContent = text;
            messageEl.className = `message ${type}`;
            messageEl.style.display = 'block';
            
            // Scroll to message
            messageEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
        
        // Form validation
        (function() {
            'use strict';
            
            const form = document.getElementById('resetForm');
            
            form.addEventListener('submit', function(event) {
                if (!form.checkValidity()) {
                    event.preventDefault();
                    event.stopPropagation();
                    
                    const emailInput = document.getElementById('email');
                    if (!emailInput.checkValidity()) {
                        showMessage('Please enter a valid email address.', 'error');
                    }
                }
                
                form.classList.add('was-validated');
            }, false);
        })();
        
        // Auto-focus email field
        document.getElementById('email').focus();
    </script>
</body>
</html>