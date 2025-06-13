<?php

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

if (!isset($_GET['id'])) {
    header("Location: batch_create.php");
    exit();
}

$batch_id = intval($_GET['id']);

// Get batch details
$batch = [];
$stmt = $conn->prepare("SELECT * FROM batches WHERE batch_id = ?");
$stmt->bind_param("i", $batch_id);
$stmt->execute();
$result = $stmt->get_result();
$batch = $result->fetch_assoc();
$stmt->close();

// Get assigned teachers
$teachers = [];
$stmt = $conn->prepare("
    SELECT t.teacher_id, t.name, t.subject 
    FROM teachers t
    JOIN batch_teachers bt ON t.teacher_id = bt.teacher_id
    WHERE bt.batch_id = ?
");
$stmt->bind_param("i", $batch_id);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $teachers[] = $row;
}
$stmt->close();

// Get assigned students
$students = [];
$stmt = $conn->prepare("
    SELECT s.student_id, s.first_name, s.last_name, s.course 
    FROM student_data s
    JOIN batch_students bs ON s.student_id = bs.student_id
    WHERE bs.batch_id = ? AND bs.status = 'active'
");
$stmt->bind_param("i", $batch_id);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $students[] = $row;
}
$stmt->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Batch Created Details </title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #27ae60;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .success-message {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .batch-info {
            margin-bottom: 30px;
        }
        
        .info-card {
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 4px;
        }
        
        .info-card h3 {
            margin-top: 0;
            color: #3498db;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .section {
            margin-bottom: 30px;
        }
        
        .section h2 {
            color: #3498db;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background-color: #f2f2f2;
            font-weight: 600;
        }
        
        tr:hover {
            background-color: #f5f5f5;
        }
        
        .btn {
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            text-decoration: none;
            margin-right: 10px;
        }
        
        .btn-primary {
            background-color: #3498db;
            color: white;
        }
        
        .btn-primary:hover {
            background-color: #2980b9;
        }
        
        .btn-secondary {
            background-color: #ecf0f1;
            color: #2c3e50;
        }
        
        .btn-secondary:hover {
            background-color: #bdc3c7;
        }
        
        .actions {
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-message">
            <i class="fas fa-check-circle fa-2x"></i>
            <span>Batch has been created successfully!</span>
        </div>
        
        <div class="batch-info">
            <h1>Batch Details: <?= htmlspecialchars($batch['batch_name']) ?></h1>
            
            <div class="info-grid">
                <div class="info-card">
                    <h3>Basic Information</h3>
                    <p><strong>Batch Code:</strong> <?= htmlspecialchars($batch['batch_code']) ?></p>
                    <p><strong>Course:</strong> <?= htmlspecialchars($batch['course']) ?></p>
                    <p><strong>Institute:</strong> <?= htmlspecialchars($batch['institute_name']) ?></p>
                </div>
                
                <div class="info-card">
                    <h3>Schedule</h3>
                    <p><strong>Start Date:</strong> <?= date('F j, Y', strtotime($batch['start_date'])) ?></p>
                    <p><strong>End Date:</strong> <?= $batch['end_date'] ? date('F j, Y', strtotime($batch['end_date'])) : 'Not set' ?></p>
                    <p><strong>Status:</strong> <?= htmlspecialchars($batch['status']) ?></p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2><i class="fas fa-chalkboard-teacher"></i> Assigned Teachers</h2>
            
            <?php if (!empty($teachers)): ?>
                <table>
                    <thead>
                        <tr>
                            <th>Teacher ID</th>
                            <th>Name</th>
                            <th>Subject</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach($teachers as $teacher): ?>
                            <tr>
                                <td><?= $teacher['teacher_id'] ?></td>
                                <td><?= htmlspecialchars($teacher['name']) ?></td>
                                <td><?= htmlspecialchars($teacher['subject']) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <p>No teachers assigned to this batch.</p>
            <?php endif; ?>
        </div>
        
        <div class="section">
            <h2><i class="fas fa-user-graduate"></i> Enrolled Students</h2>
            
            <?php if (!empty($students)): ?>
                <table>
                    <thead>
                        <tr>
                            <th>Student ID</th>
                            <th>Name</th>
                            <th>Course</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach($students as $student): ?>
                            <tr>
                                <td><?= $student['student_id'] ?></td>
                                <td><?= htmlspecialchars($student['first_name'] . ' ' . $student['last_name']) ?></td>
                                <td><?= htmlspecialchars($student['course']) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <p>No students enrolled in this batch yet.</p>
            <?php endif; ?>
        </div>
        
        <div class="actions">
            <a href="create_batch_page.php" class="btn btn-primary">
                <i class="fas fa-plus"></i> Create Another Batch
            </a>
            <a href="batch_list.php" class="btn btn-secondary">
                <i class="fas fa-list"></i> View All Batches
            </a>
        </div>
    </div>
</body>
</html>