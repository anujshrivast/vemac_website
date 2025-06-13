<?php
include 'db_connect.php';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize and validate input data
    $username = htmlspecialchars(trim($_POST['username'] ?? ''));
    $name = htmlspecialchars(trim($_POST['name'] ?? ''));
    $email = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $role = $_POST['role'] ?? '';
    $institute_name = htmlspecialchars(trim($_POST['institute_name'] ?? ''));
    $phone = htmlspecialchars(trim($_POST['phone'] ?? ''));
    $status = 'active'; // Default status

    // Validate required fields
    if (empty($username) || empty($name) || empty($email) || empty($password) || empty($confirmPassword) || empty($role) || empty($institute_name) || empty($phone)) {
        die("All fields are required.");
    }

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Invalid email format.");
    }

    // Check if passwords match
    if ($password !== $confirmPassword) {
        die("Passwords do not match.");
    }

    // Check if username or email already exists
    $checkStmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
    $checkStmt->bind_param('ss', $username, $email);
    $checkStmt->execute();
    $checkStmt->store_result();
    if ($checkStmt->num_rows > 0) {
        die("Username or Email already exists.");
    }
    $checkStmt->close();

    // Hash the password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Insert user into the users table
    $sql = "INSERT INTO users (username, name, email, phone, password, role, institute_name, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);

    if (!$stmt) {
        die("SQL prepare error: " . $conn->error);
    }

    // Bind parameters
    $stmt->bind_param('ssssssss', $username, $name, $email, $phone, $hashedPassword, $role, $institute_name, $status);

    // Execute the statement
    if (!$stmt->execute()) {
        die("SQL execute error: " . $stmt->error);
    }

    echo "Registration successful for $role!";

    // Optionally redirect to login page after success
    header("Location: login.html");
    exit();

    $stmt->close();
} else {
    die("Invalid request method.");
}
?>