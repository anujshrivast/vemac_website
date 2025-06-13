<?php
// Start the session at the very top
session_start();

// Database connection
$host = 'localhost';
$db = 'vemac_db';
$user = 'root';
$pass = '';

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Function to sanitize input
function sanitize_input($data)
{
    return htmlspecialchars(stripslashes(trim($data)));
}

// Login logic
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $role_input = sanitize_input($_POST['role']);
    $email = sanitize_input($_POST['email']);
    $password = sanitize_input($_POST['password']);

    // Fetch user data from the users table
    $stmt = $conn->prepare("SELECT id, username, name, email, phone, password, role, institute_name, status FROM users WHERE email = ?");
    if (!$stmt) {
        die("Prepare failed: " . $conn->error);
    }
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows === 0) {
        // User not found
        session_unset();
        session_destroy();
        die("User not Found ! <br> Check the Email id....");
        exit();
    }

    $stmt->bind_result($user_id, $username, $name, $db_email, $phone, $hashed_password, $role, $institute_name, $status);
    $stmt->fetch();

    // Check password
    if (!password_verify($password, $hashed_password)) {
        session_unset();
        session_destroy();
        die("Password is Invalid ! <br>Check the Password....");
        exit();
    }

    // Check status
    if ($status !== 'active') {
        session_unset();
        session_destroy();
        die("Account is inactive. Please contact the administrator.");
        exit();
    }

    // Successful login, store user session
    $_SESSION['user_id'] = $user_id;
    $_SESSION['username'] = $username;
    $_SESSION['name'] = $name;
    $_SESSION['email'] = $db_email;
    $_SESSION['phone'] = $phone;
    $_SESSION['role'] = $role;
    $_SESSION['institute_name'] = $institute_name;
    $_SESSION['status'] = $status;

    // Check role matches input
    if (!($role_input == $role)) {
        session_unset();
        session_destroy();
        die("User not Found ! <br> Check the Role of User....");
    }

    // Redirect based on role
    switch ($role) {
        case 'admin':
            header("Location: admin.php");
            exit();
        case 'student':
            header("Location: student.php");
            exit();
        case 'office':
            header("Location: office.php");
            exit();
        case 'teacher':
            header("Location: teacher.php");
            exit();
        default:
            session_unset();
            session_destroy();
            header("Location: login.php?error=unknown_role");
            exit();
    }

    $stmt->close();
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | VEMAC</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            align-items: center;
            text-align: center;
            margin-top: 100px;
        }

        .container {
            width: 350px;
            padding: 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            margin: auto;
        }

        .error {
            color: red;
            font-size: 14px;
            margin-bottom: 10px;
        }

        input,
        button {
            width: 100%;
            padding: 10px;
            margin-top: 10px;
        }
    </style>
</head>

<body>

    <div class="container">
        <h1>Invalid data Input Found....! <br> <a href="login.html">Login</a><br><br> Check Again ! OR <a href="register.html">Register</a></h2>

    </div>

</body>

</html>