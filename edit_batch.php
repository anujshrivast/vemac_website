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

// Check if batch ID is provided
if (!isset($_GET['batch_id']) || !is_numeric($_GET['batch_id'])) {
    $_SESSION['error_message'] = "Invalid batch ID";

    if ($_SESSION['role'] === 'admin') {
        header("Location: admin.php");
    } else {
        header("Location: office.php");
    }
    exit();
}

// Start session
session_start();
// Check if user is logged in and has the right role
if (!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['office', 'admin'])) {
    header("Location: logout.php");
    exit();
}


// Generate CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$batch_id = intval($_GET['batch_id']);
// Get batch details
$batch = [];
$query = "SELECT * FROM batches WHERE batch_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $batch_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    $_SESSION['error_message'] = "Batch not found";
    if ($_SESSION['role'] === 'admin') {
        header("Location: admin.php");
    } else {
        header("Location: office.php");
        exit();
    }
}

$batch = $result->fetch_assoc();

// Get all active institutes
$institutes = [];
$query = "SELECT institute_name FROM institute_branch";
$result = $conn->query($query);
if ($result) {
    $institutes = $result->fetch_all(MYSQLI_ASSOC);
}

// Get all active teachers (including those already in this batch)
$all_teachers = [];
$query = "SELECT teacher_id, name, subjects FROM teachers WHERE status = 'active'";
$result = $conn->query($query);
if ($result) {
    $all_teachers = $result->fetch_all(MYSQLI_ASSOC);
}

// Get teachers already assigned to this batch
$batch_teachers = [];
$query = "SELECT bt.teacher_id, t.name, bt.subject 
          FROM batch_teachers bt
          JOIN teachers t ON bt.teacher_id = t.teacher_id
          WHERE bt.batch_id = ? AND bt.status = 'active'";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $batch_id);
$stmt->execute();
$result = $stmt->get_result();
$batch_teachers = $result->fetch_all(MYSQLI_ASSOC);

// Get all active students not in any other active batch (or already in this batch)
$available_students = [];
$query = "SELECT sd.student_id, sd.first_name, sd.last_name 
          FROM student_data sd
          WHERE sd.is_active = 1 
          AND (sd.student_id NOT IN (
              SELECT student_id FROM batch_students 
              WHERE status = 'active' AND batch_id != ?
          ) OR sd.student_id IN (
              SELECT student_id FROM batch_students 
              WHERE batch_id = ? AND status = 'active'
          ))"; // <-- Add this closing parenthesis
$stmt = $conn->prepare($query);
$stmt->bind_param("ii", $batch_id, $batch_id);
$stmt->execute();
$result = $stmt->get_result();
$available_students = $result->fetch_all(MYSQLI_ASSOC);

// Get students already in this batch
$batch_students = [];
$query = "SELECT bs.student_id, sd.first_name, sd.last_name 
          FROM batch_students bs
          JOIN student_data sd ON bs.student_id = sd.student_id
          WHERE bs.batch_id = ? AND bs.status = 'active'";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $batch_id);
$stmt->execute();
$result = $stmt->get_result();
$batch_students = $result->fetch_all(MYSQLI_ASSOC);

// Process form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_batch'])) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $_SESSION['error_message'] = "Invalid CSRF token";
        header("Location: edit_batch.php?batch_id=" . $batch_id);
        exit();
    }

    // Validate and sanitize inputs
    $institute_name = $conn->real_escape_string(trim($_POST['institute_name']));
    $batch_name = $conn->real_escape_string(trim($_POST['batch_name']));
    $batch_code = $conn->real_escape_string(trim($_POST['batch_code']));
    $start_date = $conn->real_escape_string(trim($_POST['start_date']));
    $status = $conn->real_escape_string(trim($_POST['status']));

    // Basic validation
    $errors = [];
    if (empty($institute_name)) $errors[] = "Institute name is required";
    if (empty($batch_name)) $errors[] = "Batch name is required";
    if (empty($batch_code)) $errors[] = "Batch code is required";
    if (empty($start_date)) $errors[] = "Start date is required";
    if (empty($status)) $errors[] = "Status is required";

    // Check if batch code already exists (excluding current batch)
    $check_query = "SELECT batch_id FROM batches WHERE batch_code = ? AND batch_id != ?";
    $check_stmt = $conn->prepare($check_query);
    $check_stmt->bind_param("si", $batch_code, $batch_id);
    $check_stmt->execute();
    $check_result = $check_stmt->get_result();
    if ($check_result->num_rows > 0) {
        $errors[] = "Batch code already exists";
    }

    // Process if no errors
    if (empty($errors)) {
        $conn->begin_transaction();

        try {
            // Update batch record
            $update_batch = "UPDATE batches SET 
                            institute_name = ?,
                            batch_name = ?,
                            batch_code = ?,
                            start_date = ?,
                            status = ?
                            WHERE batch_id = ?";
            $stmt = $conn->prepare($update_batch);
            $stmt->bind_param("sssssi", $institute_name, $batch_name, $batch_code, $start_date, $status, $batch_id);
            $stmt->execute();

            // Process teachers
            $current_teacher_ids = array_column($batch_teachers, 'teacher_id');
            $new_teacher_ids = [];
            $teachers_to_add = [];
            $teachers_to_remove = [];

            if (!empty($_POST['teachers'])) {
                foreach ($_POST['teachers'] as $teacher) {
                    $teacher_id = intval($teacher['id']);
                    $subject = $conn->real_escape_string(trim($teacher['subject']));

                    if ($teacher_id > 0 && !empty($subject)) {
                        $new_teacher_ids[] = $teacher_id;
                        $teachers_to_add[$teacher_id] = $subject;
                    }
                }
            }

            // Find teachers to remove (in current but not in new)
            foreach ($current_teacher_ids as $teacher_id) {
                if (!in_array($teacher_id, $new_teacher_ids)) {
                    $teachers_to_remove[] = $teacher_id;
                }
            }


            // Remove teachers no longer in batch
            if (!empty($teachers_to_remove)) {
                $remove_teacher = "UPDATE batch_teachers SET status = 'Inactive'
                       WHERE batch_id = ? AND teacher_id = ?";
                $stmt_remove = $conn->prepare($remove_teacher);
                if (!$stmt_remove) {
                    die("Prepare failed: " . $conn->error . " | SQL: " . $remove_teacher);
                }
                foreach ($teachers_to_remove as $teacher_id) {
                    $stmt_remove->bind_param("ii", $batch_id, $teacher_id);
                    $stmt_remove->execute();
                }
            }

            // Add new teachers or update existing ones
            if (!empty($teachers_to_add)) {
                $insert_teacher = "INSERT INTO batch_teachers (batch_id, teacher_id, subject, join_date, status) 
                                 VALUES (?, ?, ?, CURDATE(), 'active')
                                 ON DUPLICATE KEY UPDATE subject = VALUES(subject), status = 'active'";
                $stmt_teacher = $conn->prepare($insert_teacher);

                foreach ($teachers_to_add as $teacher_id => $subject) {
                    $stmt_teacher->bind_param("iis", $batch_id, $teacher_id, $subject);
                    $stmt_teacher->execute();
                }
            }

            // Process students
            $current_student_ids = array_column($batch_students, 'student_id');
            $new_student_ids = [];
            $students_to_add = [];
            $students_to_remove = [];

            if (!empty($_POST['students'])) {
                foreach ($_POST['students'] as $student_id) {
                    $student_id = intval($student_id);
                    if ($student_id > 0) {
                        $new_student_ids[] = $student_id;
                        $students_to_add[] = $student_id;
                    }
                }
            }

            // Find students to remove (in current but not in new)
            foreach ($current_student_ids as $student_id) {
                if (!in_array($student_id, $new_student_ids)) {
                    $students_to_remove[] = $student_id;
                }
            }


            // Remove students no longer in batch
            if (!empty($students_to_remove)) {
                $remove_student = "UPDATE batch_students SET status = 'Removed'
                       WHERE batch_id = ? AND student_id = ?";
                $stmt_remove = $conn->prepare($remove_student);
                if (!$stmt_remove) {
                    die("Prepare failed: " . $conn->error . " | SQL: " . $remove_student);
                }
                foreach ($students_to_remove as $student_id) {
                    $stmt_remove->bind_param("ii", $batch_id, $student_id);
                    $stmt_remove->execute();
                }
            }

            // Add new students
            if (!empty($students_to_add)) {
                $insert_student = "INSERT INTO batch_students (batch_id, student_id, enrollment_date, status) 
                                  VALUES (?, ?, CURDATE(), 'active')
                                  ON DUPLICATE KEY UPDATE status = 'active'";
                $stmt_student = $conn->prepare($insert_student);

                foreach ($students_to_add as $student_id) {
                    // Only add if not already in batch
                    if (!in_array($student_id, $current_student_ids)) {
                        $stmt_student->bind_param("ii", $batch_id, $student_id);
                        $stmt_student->execute();
                    }
                }
            }

            $conn->commit();

            $_SESSION['success_message'] = "Batch updated successfully!";
            header("Location: office.php?batch_id=" . $batch_id . "&success=updated");
            exit();
        } catch (Exception $e) {
            $conn->rollback();
            $_SESSION['error_message'] = "Error updating batch: " . $e->getMessage();
            header("Location: edit_batch.php?batch_id=" . $batch_id);
            exit();
        }
    } else {
        $_SESSION['error_message'] = implode("<br>", $errors);
        header("Location: edit_batch.php?batch_id=" . $batch_id);
        exit();
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Batch - VEMAC</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <!-- Select2 for better multi-select -->
    <link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />
    <!-- Custom CSS -->
    <style>
        .teacher-card,
        .student-card {
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            background-color: #f8f9fa;
            position: relative;
            transition: all 0.3s ease;
        }

        .teacher-card:hover,
        .student-card:hover {
            background-color: #e9ecef;
            box-shadow: 0 0 5px rgba(0, 0, 0, 0.1);
        }

        .teacher-card .remove-btn,
        .student-card .remove-btn {
            position: absolute;
            top: 5px;
            right: 5px;
            opacity: 0.7;
            transition: opacity 0.2s;
        }

        .teacher-card .remove-btn:hover,
        .student-card .remove-btn:hover {
            opacity: 1;
        }

        #selectedTeachers,
        #selectedStudents {
            max-height: 400px;
            overflow-y: auto;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 5px;
            border: 1px solid #dee2e6;
        }

        .form-section {
            margin-bottom: 30px;
            padding: 25px;
            border-radius: 8px;
            background-color: #fff;
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.08);
        }

        .batch-header {
            background-color: #f1f8ff;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            border-left: 5px solid #0d6efd;
        }

        .batch-code-display {
            font-size: 1.1rem;
            font-weight: 500;
            color: #0d6efd;
            background-color: #e7f1ff;
            padding: 5px 10px;
            border-radius: 4px;
            display: inline-block;
        }

        .empty-state {
            text-align: center;
            padding: 30px;
            color: #6c757d;
        }

        .empty-state i {
            font-size: 2.5rem;
            margin-bottom: 15px;
            color: #adb5bd;
        }

        .tab-content {
            padding: 20px 0;
        }

        .nav-tabs .nav-link {
            font-weight: 500;
        }

        .stats-card {
            border-left: 4px solid #0d6efd;
            padding: 15px;
            margin-bottom: 15px;
            background-color: #fff;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }

        .stats-card .stat-value {
            font-size: 1.5rem;
            font-weight: 600;
            color: #0d6efd;
        }

        .stats-card .stat-label {
            color: #6c757d;
            font-size: 0.9rem;
        }
    </style>
</head>

<body>
    <div class="container py-4">
        <div class="row mb-4">
            <div class="col-12">
                <nav aria-label="breadcrumb">
                    <ol class="breadcrumb">
                        <li class="breadcrumb-item"><a href="dashboard.php">Dashboard</a></li>
                        <li class="breadcrumb-item"><a href="batch_management.php">Batch Management</a></li>
                        <li class="breadcrumb-item active" aria-current="page">Edit Batch</li>
                    </ol>
                </nav>
            </div>
        </div>

        <?php if (isset($_SESSION['error_message'])): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <?= $_SESSION['error_message'] ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
            <?php unset($_SESSION['error_message']); ?>
        <?php endif; ?>

        <?php if (isset($_GET['success']) && $_GET['success'] == 'updated'): ?>
            <div class="alert alert-success alert-dismissible fade show">
                Batch updated successfully!
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>

        <div class="batch-header">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h2><i class="bi bi-pencil-square"></i> Edit Batch: <?= htmlspecialchars($batch['batch_name']) ?></h2>
                    <div class="d-flex align-items-center mt-2">
                        <span class="batch-code-display me-3">
                            <i class="bi bi-tag"></i> <?= htmlspecialchars($batch['batch_code']) ?>
                        </span>
                        <span class="badge bg-<?= $batch['status'] == 'Active' ? 'success' : ($batch['status'] == 'Inactive' ? 'danger' : 'warning') ?>">
                            <?= htmlspecialchars($batch['status']) ?>
                        </span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="row">
                        <div class="col-6">
                            <div class="stats-card">
                                <div class="stat-value"><?= count($batch_teachers) ?></div>
                                <div class="stat-label">Teachers</div>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="stats-card">
                                <div class="stat-value"><?= count($batch_students) ?></div>
                                <div class="stat-label">Students</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <ul class="nav nav-tabs" id="batchTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="details-tab" data-bs-toggle="tab" data-bs-target="#details" type="button" role="tab">
                    <i class="bi bi-card-text"></i> Batch Details
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="teachers-tab" data-bs-toggle="tab" data-bs-target="#teachers" type="button" role="tab">
                    <i class="bi bi-person-badge"></i> Teachers
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="students-tab" data-bs-toggle="tab" data-bs-target="#students" type="button" role="tab">
                    <i class="bi bi-people"></i> Students
                </button>
            </li>
        </ul>

        <div class="tab-content" id="batchTabsContent">
            <div class="tab-pane fade show active" id="details" role="tabpanel">
                <form id="batchForm" method="post">
                    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                    <input type="hidden" name="update_batch" value="1">

                    <div class="form-section">
                        <h4 class="mb-4"><i class="bi bi-info-circle"></i> Basic Information</h4>

                        <div class="row g-3">
                            <div class="col-md-6">
                                <label for="institute_name" class="form-label">Institute Name *</label>
                                <select class="form-select" id="institute_name" name="institute_name" required>
                                    <option value="">Select Institute</option>
                                    <?php foreach ($institutes as $institute): ?>
                                        <option value="<?= htmlspecialchars($institute['institute_name']) ?>" <?= $institute['institute_name'] == $batch['institute_name'] ? 'selected' : '' ?>>
                                            <?= htmlspecialchars($institute['institute_name']) ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="col-md-6">
                                <label for="batch_name" class="form-label">Batch Name *</label>
                                <input type="text" class="form-control" id="batch_name" name="batch_name" value="<?= htmlspecialchars($batch['batch_name']) ?>" required>
                            </div>

                            <div class="col-md-4">
                                <label for="batch_code" class="form-label">Batch Code *</label>
                                <input type="text" class="form-control" id="batch_code" name="batch_code" value="<?= htmlspecialchars($batch['batch_code']) ?>" required>
                            </div>

                            <div class="col-md-4">
                                <label for="start_date" class="form-label">Start Date *</label>
                                <input type="date" class="form-control" id="start_date" name="start_date" value="<?= htmlspecialchars($batch['start_date']) ?>" required>
                            </div>

                            <div class="col-md-4">
                                <label for="status" class="form-label">Status *</label>
                                <select class="form-select" id="status" name="status" required>
                                    <option value="Active" <?= $batch['status'] == 'Active' ? 'selected' : '' ?>>Active</option>
                                    <option value="Inactive" <?= $batch['status'] == 'Inactive' ? 'selected' : '' ?>>Inactive</option>
                                    <option value="Planning" <?= $batch['status'] == 'Planning' ? 'selected' : '' ?>>Planning</option>
                                </select>
                            </div>
                        </div>

                        <div class="d-flex justify-content-end mt-4">
                            <button type="submit" class="btn btn-primary">
                                <i class="bi bi-save"></i> Save Changes
                            </button>
                        </div>
                    </div>
                </form>
            </div>

            <div class="tab-pane fade" id="teachers" role="tabpanel">
                <div class="form-section">
                    <h4 class="mb-4"><i class="bi bi-person-badge"></i> Manage Teachers</h4>

                    <div class="row g-3 mb-4">
                        <div class="col-md-5">
                            <label for="teacherSelect" class="form-label">Select Teacher</label>
                            <select class="form-select" id="teacherSelect">
                                <option value="">Select Teacher</option>
                                <?php foreach ($all_teachers as $teacher):
                                    // Skip teachers already in this batch
                                    $is_in_batch = false;
                                    foreach ($batch_teachers as $bt) {
                                        if ($bt['teacher_id'] == $teacher['teacher_id']) {
                                            $is_in_batch = true;
                                            break;
                                        }
                                    }
                                    if (!$is_in_batch): ?>
                                        <option value="<?= $teacher['teacher_id'] ?>" data-subjects="<?= htmlspecialchars($teacher['subjects']) ?>">
                                            <?= htmlspecialchars($teacher['name']) ?>
                                        </option>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div class="col-md-5">
                            <label for="teacherSubject" class="form-label">Subject</label>
                            <input type="text" class="form-control" id="teacherSubject" placeholder="Enter subject">
                        </div>

                        <div class="col-md-2 d-flex align-items-end">
                            <button type="button" class="btn btn-primary w-100" id="addTeacherBtn">
                                <i class="bi bi-plus"></i> Add Teacher
                            </button>
                        </div>
                    </div>

                    <div class="selected-teachers">
                        <h5 class="mb-3">Assigned Teachers</h5>
                        <div id="selectedTeachers">
                            <?php if (empty($batch_teachers)): ?>
                                <div class="empty-state">
                                    <i class="bi bi-person-x"></i>
                                    <p>No teachers assigned to this batch</p>
                                </div>
                            <?php else: ?>
                                <?php foreach ($batch_teachers as $teacher): ?>
                                    <div class="teacher-card position-relative" id="teacherCard-<?= $teacher['teacher_id'] ?>">
                                        <button type="button" class="btn btn-sm btn-danger remove-btn remove-teacher">
                                            <i class="bi bi-x"></i>
                                        </button>
                                        <h6><?= htmlspecialchars($teacher['name']) ?></h6>
                                        <p class="mb-1"><strong>Subject:</strong> <?= htmlspecialchars($teacher['subject']) ?></p>
                                        <input type="hidden" name="teachers[<?= $teacher['teacher_id'] ?>][id]" value="<?= $teacher['teacher_id'] ?>">
                                        <input type="hidden" name="teachers[<?= $teacher['teacher_id'] ?>][subject]" value="<?= htmlspecialchars($teacher['subject']) ?>">
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>

            <div class="tab-pane fade" id="students" role="tabpanel">
                <div class="form-section">
                    <h4 class="mb-4"><i class="bi bi-people"></i> Manage Students</h4>

                    <div class="row g-3 mb-4">
                        <div class="col-md-10">
                            <label for="studentSelect" class="form-label">Select Students</label>
                            <select class="form-select" id="studentSelect" multiple="multiple">
                                <?php foreach ($available_students as $student):
                                    // Skip students already in this batch
                                    $is_in_batch = false;
                                    foreach ($batch_students as $bs) {
                                        if ($bs['student_id'] == $student['student_id']) {
                                            $is_in_batch = true;
                                            break;
                                        }
                                    }
                                    if (!$is_in_batch): ?>
                                        <option value="<?= $student['student_id'] ?>">
                                            <?= htmlspecialchars($student['first_name'] . ' ' . $student['last_name']) ?>
                                            (ID: <?= $student['student_id'] ?>)
                                        </option>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div class="col-md-2 d-flex align-items-end">
                            <button type="button" class="btn btn-primary w-100" id="addStudentsBtn">
                                <i class="bi bi-plus"></i> Add Selected
                            </button>
                        </div>
                    </div>

                    <div class="selected-students">
                        <h5 class="mb-3">Enrolled Students</h5>
                        <div id="selectedStudents">
                            <?php if (empty($batch_students)): ?>
                                <div class="empty-state">
                                    <i class="bi bi-person-plus"></i>
                                    <p>No students enrolled in this batch</p>
                                </div>
                            <?php else: ?>
                                <?php foreach ($batch_students as $student): ?>
                                    <div class="student-card position-relative mb-2" id="studentCard-<?= $student['student_id'] ?>">
                                        <button type="button" class="btn btn-sm btn-danger remove-btn remove-student">
                                            <i class="bi bi-x"></i>
                                        </button>
                                        <p class="mb-0"><?= htmlspecialchars($student['first_name'] . ' ' . $student['last_name']) ?></p>
                                        <p class="mb-0 small text-muted">ID: <?= $student['student_id'] ?></p>
                                        <input type="hidden" name="students[]" value="<?= $student['student_id'] ?>">
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="d-flex justify-content-between mt-4">
            <a href="batch_management.php" class="btn btn-outline-secondary">
                <i class="bi bi-arrow-left"></i> Back to Batches
            </a>
            <button type="submit" form="batchForm" class="btn btn-success">
                <i class="bi bi-check-circle"></i> Save All Changes
            </button>
        </div>
    </div>

    <!-- JavaScript Libraries -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>
    <script>
        $(document).ready(function() {
            // Initialize Select2 for student multi-select
            $('#studentSelect').select2({
                placeholder: "Search and select students",
                allowClear: true,
                width: '100%'
            });

            // Auto-fill subject when teacher is selected
            $('#teacherSelect').change(function() {
                const selectedOption = $(this).find('option:selected');
                const subjects = selectedOption.data('subjects');
                if (subjects) {
                    // Take the first subject if multiple subjects are comma-separated
                    const firstSubject = subjects.split(',')[0].trim();
                    $('#teacherSubject').val(firstSubject);
                }
            });

            // Add teacher to the list
            $('#addTeacherBtn').click(function() {
                const teacherId = $('#teacherSelect').val();
                const teacherName = $('#teacherSelect option:selected').text();
                const subject = $('#teacherSubject').val().trim();

                if (!teacherId || !teacherName) {
                    alert('Please select a teacher');
                    return;
                }

                if (!subject) {
                    alert('Please enter a subject');
                    return;
                }

                // Create teacher card
                const teacherCard = `
                    <div class="teacher-card position-relative" id="teacherCard-${teacherId}">
                        <button type="button" class="btn btn-sm btn-danger remove-btn remove-teacher">
                            <i class="bi bi-x"></i>
                        </button>
                        <h6>${teacherName}</h6>
                        <p class="mb-1"><strong>Subject:</strong> ${subject}</p>
                        <input type="hidden" name="teachers[${teacherId}][id]" value="${teacherId}">
                        <input type="hidden" name="teachers[${teacherId}][subject]" value="${subject}">
                    </div>
                `;

                // Add to selected teachers container
                if ($('#selectedTeachers .empty-state').length) {
                    $('#selectedTeachers').html(teacherCard);
                } else {
                    $('#selectedTeachers').append(teacherCard);
                }

                // Remove from dropdown
                $('#teacherSelect option[value="' + teacherId + '"]').remove();
                $('#teacherSelect').val('').trigger('change');
                $('#teacherSubject').val('');
            });

            // Add students to the list
            $('#addStudentsBtn').click(function() {
                const selectedStudents = $('#studentSelect').val();

                if (!selectedStudents || selectedStudents.length === 0) {
                    alert('Please select at least one student');
                    return;
                }

                // Get student names for display
                const studentOptions = $('#studentSelect option:selected');
                let hasAdded = false;

                studentOptions.each(function() {
                    const studentId = $(this).val();
                    const studentName = $(this).text();

                    // Create student card
                    const studentCard = `
                        <div class="student-card position-relative mb-2" id="studentCard-${studentId}">
                            <button type="button" class="btn btn-sm btn-danger remove-btn remove-student">
                                <i class="bi bi-x"></i>
                            </button>
                            <p class="mb-0">${studentName.split(' (ID:')[0]}</p>
                            <p class="mb-0 small text-muted">ID: ${studentId}</p>
                            <input type="hidden" name="students[]" value="${studentId}">
                        </div>
                    `;

                    // Add to selected students container
                    if ($('#selectedStudents .empty-state').length && !hasAdded) {
                        $('#selectedStudents').html(studentCard);
                        hasAdded = true;
                    } else {
                        $('#selectedStudents').append(studentCard);
                    }

                    // Remove from dropdown
                    $(this).remove();
                });

                // Clear selection
                $('#studentSelect').val(null).trigger('change');
            });

            // Remove teacher (event delegation for dynamically added elements)
            $(document).on('click', '.remove-teacher', function() {
                const card = $(this).closest('.teacher-card');
                const teacherId = card.attr('id').replace('teacherCard-', '');
                const teacherName = card.find('h6').text();
                const subject = card.find('input[name*="[subject]"]').val();

                // Add back to dropdown
                $('#teacherSelect').append(new Option(teacherName, teacherId, false, false))
                    .find('option[value="' + teacherId + '"]')
                    .data('subjects', subject);

                card.remove();

                if ($('#selectedTeachers').children().length === 0) {
                    $('#selectedTeachers').html(`
                        <div class="empty-state">
                            <i class="bi bi-person-x"></i>
                            <p>No teachers assigned to this batch</p>
                        </div>
                    `);
                }
            });

            // Remove student (event delegation for dynamically added elements)
            $(document).on('click', '.remove-student', function() {
                const card = $(this).closest('.student-card');
                const studentId = card.attr('id').replace('studentCard-', '');
                const studentName = card.find('p:first').text() + ' (ID: ' + studentId + ')';

                // Add back to dropdown
                $('#studentSelect').append(new Option(studentName, studentId, false, false));

                card.remove();

                if ($('#selectedStudents').children().length === 0) {
                    $('#selectedStudents').html(`
                        <div class="empty-state">
                            <i class="bi bi-person-plus"></i>
                            <p>No students enrolled in this batch</p>
                        </div>
                    `);
                }
            });

            // Form validation before submission
            $('#batchForm').submit(function() {
                // Check if at least one teacher is assigned
                if ($('#selectedTeachers .teacher-card').length === 0) {
                    if (!confirm('No teachers have been assigned to this batch. Continue anyway?')) {
                        return false;
                    }
                }

                // Check if at least one student is enrolled
                if ($('#selectedStudents .student-card').length === 0) {
                    if (!confirm('No students have been enrolled in this batch. Continue anyway?')) {
                        return false;
                    }
                }

                return true;
            });
        });
    </script>
</body>

</html>