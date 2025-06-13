<?php
include 'db_connect.php';

// Fetch active institutes from database
$institutes = [];
$institute_query = "SELECT id, name FROM institutes WHERE status = 'active'";
$result = $conn->query($institute_query);
if ($result && $result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $institutes[] = $row;
    }
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize and validate input data
    $username = htmlspecialchars(trim($_POST['username'] ?? ''));
    $name = htmlspecialchars(trim($_POST['name'] ?? ''));
    $email = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $role = $_POST['role'] ?? '';
    $institute_id = isset($_POST['institute_id']) ? (int)$_POST['institute_id'] : 0;
    $phone = htmlspecialchars(trim($_POST['phone'] ?? ''));
    $status = 'active'; // Default status

    // Validate required fields
    $errors = [];
    if (empty($username)) $errors[] = "Username is required";
    if (empty($name)) $errors[] = "Full name is required";
    if (empty($email)) $errors[] = "Email is required";
    if (empty($password)) $errors[] = "Password is required";
    if (empty($confirmPassword)) $errors[] = "Confirm Password is required";
    if (empty($role)) $errors[] = "Role is required";
    if ($institute_id <= 0) $errors[] = "Institute is required";
    if (empty($phone)) $errors[] = "Phone number is required";

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format";
    }

    // Check if passwords match
    if ($password !== $confirmPassword) {
        $errors[] = "Passwords do not match";
    }

    // Strong password: min 8 chars, at least one uppercase, one lowercase, one digit, one special char
    if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/', $password)) {
        $errors[] = "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.";
    }

    // Check if username or email already exists
    if (empty($errors)) {
        $checkStmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $checkStmt->bind_param('ss', $username, $email);
        $checkStmt->execute();
        $checkStmt->store_result();
        if ($checkStmt->num_rows > 0) {
            $errors[] = "Username or Email already exists";
        }
        $checkStmt->close();
    }

    // If no errors, proceed with registration
    if (empty($errors)) {
        // Hash the password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Get institute name
        $institute_name = '';
        $institute_stmt = $conn->prepare("SELECT name FROM institutes WHERE id = ?");
        $institute_stmt->bind_param('i', $institute_id);
        $institute_stmt->execute();
        $institute_stmt->bind_result($institute_name);
        $institute_stmt->fetch();
        $institute_stmt->close();

        // Insert user into the users table
        $sql = "INSERT INTO users (username, name, email, phone, password, role, institute_name, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        $stmt = $conn->prepare($sql);

        if ($stmt) {
            $stmt->bind_param('ssssssss', $username, $name, $email, $phone, $hashedPassword, $role, $institute_name, $status);

            if ($stmt->execute()) {
                $success = "Registration successful for $role!";
                // Clear form fields
                $_POST = [];
            } else {
                $errors[] = "Error: " . $stmt->error;
            }
            $stmt->close();
        } else {
            $errors[] = "Database error: " . $conn->error;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register | Vemac </title>
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
            --success: #4caf50;
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
            max-width: 500px;
            padding: 2rem;
            transition: all 0.3s ease;
        }

        .auth-card:hover {
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
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
            margin-bottom: 1.25rem;
        }

        .form-label {
            font-weight: 500;
            color: var(--dark);
            margin-bottom: 0.5rem;
        }

        .form-control,
        .form-select {
            border-radius: 8px;
            height: 45px;
            border: 1px solid #e0e0e0;
            padding: 0.5rem 1rem;
            transition: all 0.3s ease;
        }

        .form-control:focus,
        .form-select:focus {
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

        .password-container {
            position: relative;
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

        .alert-success {
            background-color: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
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

        /* Responsive adjustments */
        @media (max-width: 576px) {
            .auth-card {
                padding: 1.5rem;
            }

            .auth-header h2 {
                font-size: 1.5rem;
            }
        }
    </style>
</head>

<body>
    <div class="auth-card">
        <div class="auth-header">
            <h2><i class="fas fa-user-plus me-2"></i>Create Account</h2>
            <p>Join Vemac today</p>
        </div>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">
                <ul class="mb-0">
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo htmlspecialchars($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <?php if (isset($success)): ?>
            <div class="alert alert-success">
                <?php echo htmlspecialchars($success); ?>
            </div>
        <?php endif; ?>

        <form action="register.php" method="POST" id="registrationForm">
            <div class="form-group">
                <label for="institute_id" class="form-label">Branch of Vemac</label>
                <select class="form-select" id="institute_id" name="institute_id" required>
                    <option value="" disabled selected>Select Institute</option>
                    <?php foreach ($institutes as $institute): ?>
                        <option value="<?php echo $institute['id']; ?>" <?php echo (isset($_POST['institute_id']) && $_POST['institute_id'] == $institute['id']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($institute['name']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="form-group">
                <label for="role" class="form-label">Role</label>
                <select class="form-select" id="role" name="role" required>
                    <option value="" disabled selected>Select your role</option>
                    <option value="student" <?php echo (isset($_POST['role']) && $_POST['role'] == 'student') ? 'selected' : ''; ?>>Student</option>
                    <option value="teacher" <?php echo (isset($_POST['role']) && $_POST['role'] == 'teacher') ? 'selected' : ''; ?>>Teacher</option>
                    <option value="office" <?php echo (isset($_POST['role']) && $_POST['role'] == 'office') ? 'selected' : ''; ?>>Office Incharge</option>
                </select>
            </div>

            <div class="form-group">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username"
                    value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>"
                    required placeholder="Choose a username">
            </div>

            <div class="form-group">
                <label for="name" class="form-label">Full Name</label>
                <input type="text" class="form-control" id="name" name="name"
                    value="<?php echo isset($_POST['name']) ? htmlspecialchars($_POST['name']) : ''; ?>"
                    required placeholder="Enter your full name">
            </div>

            <div class="form-group">
                <label for="email" class="form-label">Email Address</label>
                <input type="email" class="form-control" id="email" name="email"
                    value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>"
                    required placeholder="Enter your email">
            </div>

            <div class="form-group">
                <label for="phone" class="form-label">Contact Number</label>
                <input type="tel" class="form-control" id="phone" name="phone"
                    value="<?php echo isset($_POST['phone']) ? htmlspecialchars($_POST['phone']) : ''; ?>"
                    required placeholder="Enter your phone number">
            </div>

            <div class="form-group password-container">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required
                    placeholder="Create a password (min 8 chars with letters & numbers)">
                <i class="fas fa-eye-slash password-toggle" id="togglePassword"></i>
                <small class="form-text text-muted">
                    Must be at least 8 characters and include uppercase, lowercase, number, and special character
                </small>
            </div>

            <div class="form-group password-container">
                <label for="confirm_password" class="form-label">Confirm Password</label>
                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required
                    placeholder="Confirm your password">
                <i class="fas fa-eye-slash password-toggle" id="toggleConfirmPassword"></i>
            </div>

            <button type="submit" class="btn btn-primary w-100 mt-2">
                <i class="fas fa-user-plus me-2"></i>Register
            </button>
        </form>

        <div class="auth-footer">
            <p>Already have an account? <a href="login.php">Login here</a></p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Password toggle functionality
        function setupPasswordToggle(inputId, toggleId) {
            const toggle = document.getElementById(toggleId);
            const input = document.getElementById(inputId);

            toggle.addEventListener('click', function() {
                const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
                input.setAttribute('type', type);
                this.classList.toggle('fa-eye');
                this.classList.toggle('fa-eye-slash');
            });
        }

        // Initialize password toggles
        setupPasswordToggle('password', 'togglePassword');
        setupPasswordToggle('confirm_password', 'toggleConfirmPassword');

        // Form validation
        document.getElementById('registrationForm').addEventListener('submit', function(event) {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;

            // Check password match
            if (password !== confirmPassword) {
                event.preventDefault();
                alert('Passwords do not match!');
                document.getElementById('confirm_password').focus();
                return;
            }

            // Strong password: min 8 chars, at least one uppercase, one lowercase, one digit, one special char
            const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
            if (!passwordRegex.test(password)) {
                event.preventDefault();
                alert('Password must be at least 8 characters and include uppercase, lowercase, number, and special character.');
                document.getElementById('password').focus();
            }
        });

        // Phone number formatting
        document.getElementById('phone').addEventListener('input', function(e) {
            const x = e.target.value.replace(/\D/g, '').match(/(\d{0,3})(\d{0,3})(\d{0,4})/);
            e.target.value = !x[2] ? x[1] : '(' + x[1] + ') ' + x[2] + (x[3] ? '-' + x[3] : '');
        });
    </script>
</body>

</html>