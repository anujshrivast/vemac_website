<?php
require 'db_connect.php';
session_start();

// Redirect logged-in users
if (isset($_SESSION['user_id'])) {
    header("Location: " . getDashboardUrl($_SESSION['role']));
    exit();
}

// Function to sanitize input
function sanitizeInput($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}

// Function to get dashboard URL based on role
function getDashboardUrl($role) {
    switch ($role) {
        case 'admin': return 'admin.php';
        case 'student': return 'student.php';
        case 'office': return 'office.php';
        case 'teacher': return 'teacher.php';
        default: return 'login.php';
    }
}

// Login logic
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $role_input = sanitizeInput($_POST['role']);
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];

    // Validate inputs
    if (empty($role_input) || empty($email) || empty($password)) {
        $error = "All fields are required";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format";
    } else {
        // Fetch user data
        $stmt = $conn->prepare("SELECT id, username, name, email, phone, password, role, institute_name, status 
                              FROM users WHERE email = ?");
        if (!$stmt) {
            error_log("Database error: " . $conn->error);
            $error = "System error. Please try again later.";
        } else {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows === 0) {
                $error = "Invalid email or password";
            } else {
                $stmt->bind_result($user_id, $username, $name, $db_email, $phone, $hashed_password, $role, $institute_name, $status);
                $stmt->fetch();

                // Verify password
                if (password_verify($password, $hashed_password)) {
                    // Check account status
                    if ($status !== 'active') {
                        $error = "Account is inactive. Please contact administrator.";
                    } 
                    // Check role matches
                    elseif ($role_input !== $role) {
                        $error = "Invalid role for this account";
                    } 
                    // Successful login
                    else {
                        // Regenerate session ID to prevent fixation
                        session_regenerate_id(true);

                        // Store user data in session
                        $_SESSION['user_id'] = $user_id;
                        $_SESSION['username'] = $username;
                        $_SESSION['name'] = $name;
                        $_SESSION['email'] = $db_email;
                        $_SESSION['phone'] = $phone;
                        $_SESSION['role'] = $role;
                        $_SESSION['institute_name'] = $institute_name;
                        $_SESSION['last_login'] = time();

                        // Redirect to dashboard
                        header("Location: " . getDashboardUrl($role));
                        exit();
                    }
                } else {
                    $error = "Invalid email or password";
                }
            }
            $stmt->close();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login | Vemac </title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --primary: #6a1b9a;
      --primary-light: #9c4dcc;
      --primary-dark: #38006b;
      --secondary: #26a69a;
      --light: #f5f5f5;
      --dark: #212121;
      --gray: #757575;
      --white: #ffffff;
      --error: #f44336;
    }
    
    body {
      font-family: 'Segoe UI', 'Roboto', sans-serif;
      background: linear-gradient(rgba(0, 0, 0, 0.5), rgba(0, 0, 0, 0.5)), url('./images/s-bg.png') no-repeat center center fixed;
      background-size: cover;
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 20px;
    }
    
    .auth-card {
      background: rgba(255, 255, 255, 0.95);
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.15);
      width: 100%;
      max-width: 450px;
      padding: 2.5rem;
      animation: fadeIn 0.5s ease-out;
    }
    
    .auth-header {
      text-align: center;
      margin-bottom: 2rem;
    }
    
    .auth-header h2 {
      color: var(--primary);
      font-weight: 700;
      margin-bottom: 0.5rem;
    }
    
    .auth-header p {
      color: var(--gray);
    }
    
    .form-group {
      margin-bottom: 1.5rem;
      position: relative;
    }
    
    .form-label {
      font-weight: 500;
      color: var(--dark);
      margin-bottom: 0.5rem;
    }
    
    .form-control, .form-select {
      border-radius: 8px;
      height: 45px;
      border: 1px solid #e0e0e0;
      padding: 0.5rem 1rem;
      transition: all 0.3s ease;
    }
    
    .form-control:focus, .form-select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 0.25rem rgba(106, 27, 154, 0.25);
    }
    
    .btn-primary {
      background-color: var(--primary);
      border: none;
      border-radius: 8px;
      height: 45px;
      font-weight: 600;
      transition: all 0.3s ease;
    }
    
    .btn-primary:hover {
      background-color: var(--primary-dark);
      transform: translateY(-2px);
    }
    
    .password-toggle {
      position: absolute;
      right: 15px;
      top: 50%;
      transform: translateY(-50%);
      cursor: pointer;
      color: var(--gray);
    }
    
    .alert {
      border-radius: 8px;
      margin-bottom: 1.5rem;
    }
    
    .alert-danger {
      background-color: #f8d7da;
      border-color: #f5c6cb;
      color: #721c24;
    }
    
    .auth-footer {
      text-align: center;
      margin-top: 1.5rem;
      color: var(--gray);
    }
    
    .auth-footer a {
      color: var(--primary);
      text-decoration: none;
      font-weight: 500;
    }
    
    .auth-footer a:hover {
      text-decoration: underline;
    }
    
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    
    /* Responsive adjustments */
    @media (max-width: 576px) {
      .auth-card {
        padding: 1.5rem;
      }
    }
  </style>
</head>
<body>
  <div class="auth-card">
    <div class="auth-header">
      <h2><i class="fas fa-sign-in-alt me-2"></i>Login</h2>
      <p>Welcome to Vemac </p>
    </div>
    
    <?php if (isset($error)): ?>
      <div class="alert alert-danger">
        <?php echo htmlspecialchars($error); ?>
      </div>
    <?php endif; ?>
    
    <form method="POST" autocomplete="off">
      <div class="form-group">
        <label for="role" class="form-label">Select Role</label>
        <select class="form-select" id="role" name="role" required>
          <option value="" disabled selected>Select your role</option>
          <option value="office" <?php echo (isset($_POST['role']) && $_POST['role'] === 'office') ? 'selected' : ''; ?>>Office Incharge</option>
          <option value="student" <?php echo (isset($_POST['role']) && $_POST['role'] === 'student') ? 'selected' : ''; ?>>Student</option>
          <option value="teacher" <?php echo (isset($_POST['role']) && $_POST['role'] === 'teacher') ? 'selected' : ''; ?>>Teacher</option>
          <option value="admin" <?php echo (isset($_POST['role']) && $_POST['role'] === 'admin') ? 'selected' : ''; ?>>Admin</option>
        </select>
      </div>
      
      <div class="form-group">
        <label for="email" class="form-label">Email Address</label>
        <input type="email" class="form-control" id="email" name="email" 
               value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" 
               required placeholder="Enter your email">
      </div>
      
      <div class="form-group">
        <label for="password" class="form-label">Password</label>
        <input type="password" class="form-control" id="password" name="password" 
               required placeholder="Enter your password">
        <i class="fas fa-eye-slash password-toggle" id="togglePassword"></i>
      </div>
      
      <div class="form-group d-flex justify-content-between align-items-center">
        <div class="form-check">
          <input type="checkbox" class="form-check-input" id="remember" name="remember">
          <label class="form-check-label" for="remember">Remember me</label>
        </div>
        <a href="forgot-password.php" class="text-danger">Forgot password?</a>
      </div>
      
      <button type="submit" class="btn btn-primary w-100">
        <i class="fas fa-sign-in-alt me-2"></i>Login
      </button>
    </form>
    
    <div class="auth-footer">
      <p>Don't have an account? <a href="register.php">Contact administrator</a></p>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // Password toggle functionality
    const togglePassword = document.querySelector('#togglePassword');
    const password = document.querySelector('#password');
    
    togglePassword.addEventListener('click', function() {
      const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
      password.setAttribute('type', type);
      this.classList.toggle('fa-eye');
      this.classList.toggle('fa-eye-slash');
    });
    
    // Focus on role select on page load
    document.getElementById('role').focus();
  </script>
</body>
</html>