<?php
// Include database connection securely
require_once 'db_connect.php';
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Improved session handling with security settings
session_start([
    'cookie_lifetime' => 1800, // 30 minutes
    'cookie_secure'   => true,  // Only send cookies over HTTPS
    'cookie_httponly' => true,  // Prevent JavaScript access to cookies
    'cookie_samesite' => 'Lax', // Changed from 'Strict' to 'Lax' for better compatibility
    'use_strict_mode' => true   // Prevent session fixation
]);

// Set security headers

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Error reporting configuration (disable display in production)
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);





// Session timeout (30 minutes)
$inactive = 1800;

// Check session timeout
if (isset($_SESSION['timeout'])) {
    $session_life = time() - $_SESSION['timeout'];
    if ($session_life > $inactive) {

        header("Location: logout.php");
        exit();
    }
}
$_SESSION['timeout'] = time();

// Authentication check
if (!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['office', 'admin'])) {
    header("Location: logout.php");
    exit();
}

// Add this to check authentication for all requests
function checkAuthentication()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: logout.php");
        exit();
    }
}

// Call at the start of all secure pages
checkAuthentication();

// Initialize variables
$attendance = [
    'attendance_id' => '',
    'user_type' => 'student',
    'user_id' => '',
    'batch_id' => '',
    'date' => date('Y-m-d'),
    'status' => 'present',
    'notes' => '',
    'recorded_time' => date('H:i:s')
];

$is_edit = false;
$title = "Add New Attendance";
$errors = [];

// Check if editing existing record
if (isset($_GET['id'])) {
    if (!is_numeric($_GET['id'])) {
        die("Invalid attendance ID");
    }
    
    $is_edit = true;
    $title = "Edit Attendance";
    
    $stmt = $pdo->prepare("SELECT * FROM attendance WHERE attendance_id = ?");
    $stmt->execute([$_GET['id']]);
    $attendance = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$attendance) {
        $_SESSION['error'] = "Attendance record not found";
        header("Location: attendance_view.php");
        exit();
    }
}

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate and sanitize inputs
    $attendance_id = $is_edit ? filter_input(INPUT_POST, 'attendance_id', FILTER_SANITIZE_NUMBER_INT) : null;
    $user_type = filter_input(INPUT_POST, 'user_type', FILTER_SANITIZE_STRING);
    $user_id = filter_input(INPUT_POST, 'user_id', FILTER_SANITIZE_NUMBER_INT);
    $batch_id = filter_input(INPUT_POST, 'batch_id', FILTER_SANITIZE_NUMBER_INT) ?: null;
    $date = filter_input(INPUT_POST, 'date', FILTER_SANITIZE_STRING);
    $status = filter_input(INPUT_POST, 'status', FILTER_SANITIZE_STRING);
    $notes = filter_input(INPUT_POST, 'notes', FILTER_SANITIZE_STRING) ?: null;
    $recorded_time = filter_input(INPUT_POST, 'recorded_time', FILTER_SANITIZE_STRING);

    // Validate required fields
    if (empty($user_id)) {
        $errors['user_id'] = "User ID is required";
    }
    if (empty($date)) {
        $errors['date'] = "Date is required";
    } elseif (!strtotime($date)) {
        $errors['date'] = "Invalid date format";
    }
    if (empty($recorded_time)) {
        $errors['recorded_time'] = "Recorded time is required";
    }

    // If no errors, proceed with database operation
    if (empty($errors)) {
        try {
            if ($is_edit) {
                $sql = "UPDATE attendance SET 
                        user_type = ?, 
                        user_id = ?, 
                        batch_id = ?, 
                        date = ?, 
                        status = ?, 
                        notes = ?, 
                        recorded_time = ?
                        WHERE attendance_id = ?";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([
                    $user_type, $user_id, $batch_id, $date, 
                    $status, $notes, $recorded_time, $attendance_id
                ]);
                
                $_SESSION['success'] = "Attendance updated successfully!";
            } else {
                $sql = "INSERT INTO attendance (
                        user_type, user_id, batch_id, date, 
                        status, notes, recorded_time
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([
                    $user_type, $user_id, $batch_id, $date, 
                    $status, $notes, $recorded_time
                ]);
                
                $_SESSION['success'] = "Attendance added successfully!";
            }
            
            header("Location: attendance_view.php");
            exit();
        } catch (PDOException $e) {
            $errors['database'] = "Database error: " . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title) ?> | Vemac Attendance System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        .card {
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            border-radius: 10px;
        }
        .card-header {
            background-color: #4e73df;
            color: white;
            border-radius: 10px 10px 0 0 !important;
        }
        .form-control:focus, .form-select:focus {
            border-color: #4e73df;
            box-shadow: 0 0 0 0.25rem rgba(78, 115, 223, 0.25);
        }
        .btn-primary {
            background-color: #4e73df;
            border-color: #4e73df;
        }
        .btn-primary:hover {
            background-color: #3a5bbf;
            border-color: #3a5bbf;
        }
        .is-invalid {
            border-color: #e74a3b;
        }
        .invalid-feedback {
            color: #e74a3b;
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <?php if (!empty($_SESSION['error'])): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <?= htmlspecialchars($_SESSION['error']) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>
        
        <?php if (!empty($errors['database'])): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <?= htmlspecialchars($errors['database']) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>

        <div class="row justify-content-center">
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h4 class="mb-0"><?= htmlspecialchars($title) ?></h4>
                        <a href="view_attendance.php" class="btn btn-sm btn-light">
                            <i class="bi bi-arrow-left"></i> Back to List
                        </a>
                    </div>
                    <div class="card-body">
                        <form method="post" id="attendanceForm">
                            <input type="hidden" name="attendance_id" value="<?= htmlspecialchars($attendance['attendance_id']) ?>">
                            
                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <label for="user_type" class="form-label">User Type <span class="text-danger">*</span></label>
                                    <select class="form-select <?= isset($errors['user_type']) ? 'is-invalid' : '' ?>" 
                                            id="user_type" name="user_type" required>
                                        <option value="student" <?= $attendance['user_type'] === 'student' ? 'selected' : '' ?>>Student</option>
                                        <option value="teacher" <?= $attendance['user_type'] === 'teacher' ? 'selected' : '' ?>>Teacher</option>
                                        <option value="staff" <?= $attendance['user_type'] === 'staff' ? 'selected' : '' ?>>Staff</option>
                                        <option value="office_incharge" <?= $attendance['user_type'] === 'office_incharge' ? 'selected' : '' ?>>Office Incharge</option>
                                    </select>
                                    <?php if (isset($errors['user_type'])): ?>
                                        <div class="invalid-feedback"><?= htmlspecialchars($errors['user_type']) ?></div>
                                    <?php endif; ?>
                                </div>
                                <div class="col-md-6">
                                    <label for="user_id" class="form-label">User ID <span class="text-danger">*</span></label>
                                    <input type="number" class="form-control <?= isset($errors['user_id']) ? 'is-invalid' : '' ?>" 
                                           id="user_id" name="user_id" value="<?= htmlspecialchars($attendance['user_id']) ?>" required>
                                    <?php if (isset($errors['user_id'])): ?>
                                        <div class="invalid-feedback"><?= htmlspecialchars($errors['user_id']) ?></div>
                                    <?php endif; ?>
                                </div>
                            </div>
                            
                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <label for="batch_id" class="form-label">Batch ID</label>
                                    <input type="number" class="form-control" id="batch_id" name="batch_id" 
                                           value="<?= htmlspecialchars($attendance['batch_id']) ?>">
                                </div>
                                <div class="col-md-6">
                                    <label for="date" class="form-label">Date <span class="text-danger">*</span></label>
                                    <input type="date" class="form-control <?= isset($errors['date']) ? 'is-invalid' : '' ?>" 
                                           id="date" name="date" value="<?= htmlspecialchars($attendance['date']) ?>" required>
                                    <?php if (isset($errors['date'])): ?>
                                        <div class="invalid-feedback"><?= htmlspecialchars($errors['date']) ?></div>
                                    <?php endif; ?>
                                </div>
                            </div>
                            
                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <label for="status" class="form-label">Status <span class="text-danger">*</span></label>
                                    <select class="form-select" id="status" name="status" required>
                                        <option value="present" <?= $attendance['status'] === 'present' ? 'selected' : '' ?>>Present</option>
                                        <option value="absent" <?= $attendance['status'] === 'absent' ? 'selected' : '' ?>>Absent</option>
                                        <option value="late" <?= $attendance['status'] === 'late' ? 'selected' : '' ?>>Late</option>
                                        <option value="half_day" <?= $attendance['status'] === 'half_day' ? 'selected' : '' ?>>Half Day</option>
                                    </select>
                                </div>
                                <div class="col-md-6">
                                    <label for="recorded_time" class="form-label">Recorded Time <span class="text-danger">*</span></label>
                                    <input type="time" class="form-control <?= isset($errors['recorded_time']) ? 'is-invalid' : '' ?>" 
                                           id="recorded_time" name="recorded_time" 
                                           value="<?= htmlspecialchars($attendance['recorded_time']) ?>" required>
                                    <?php if (isset($errors['recorded_time'])): ?>
                                        <div class="invalid-feedback"><?= htmlspecialchars($errors['recorded_time']) ?></div>
                                    <?php endif; ?>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="notes" class="form-label">Notes</label>
                                <textarea class="form-control" id="notes" name="notes" rows="3"><?= htmlspecialchars($attendance['notes']) ?></textarea>
                            </div>
                            
                            <div class="d-grid gap-2 d-md-flex justify-content-md-end mt-4">
                                <a href="view_attendance.php" class="btn btn-secondary me-md-2">
                                    <i class="bi bi-x-circle"></i> Cancel
                                </a>
                                <button type="submit" class="btn btn-primary">
                                    <i class="bi bi-save"></i> <?= $is_edit ? 'Update' : 'Save' ?>
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-fill current time if not editing
            <?php if (!$is_edit): ?>
                document.getElementById('recorded_time').value = new Date().toTimeString().substring(0, 5);
            <?php endif; ?>

            // Fetch user details when user_id changes
            document.getElementById('user_id').addEventListener('change', function() {
                const userId = this.value;
                const userType = document.getElementById('user_type').value;
                
                if (userId && userType === 'student') {
                    fetchUserDetails(userId);
                }
            });

            function fetchUserDetails(userId) {
                // Example AJAX call to fetch user details
                // You would implement this based on your application's API
                /*
                fetch(`/api/users/${userId}`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.batch_id) {
                            document.getElementById('batch_id').value = data.batch_id;
                        }
                    })
                    .catch(error => console.error('Error:', error));
                */
            }

            // Form validation
            document.getElementById('attendanceForm').addEventListener('submit', function(e) {
                let isValid = true;
                
                // Validate date
                const dateInput = document.getElementById('date');
                if (!dateInput.value) {
                    dateInput.classList.add('is-invalid');
                    isValid = false;
                } else {
                    dateInput.classList.remove('is-invalid');
                }
                
                if (!isValid) {
                    e.preventDefault();
                }
            });
        });
    </script>
</body>
</html>