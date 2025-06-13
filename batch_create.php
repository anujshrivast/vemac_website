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



// Initialize variables for form data persistence
$formData = [
    'institute_name' => '',
    'batch_name' => '',
    'batch_code' => '',
    'course' => '',
    'start_date' => '',
    'end_date' => '',
    'status' => 'Active',
    'teacher_ids' => [],
    'teacher_subjects' => [],
    'students' => []
];

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate and sanitize input data
    $formData['institute_name'] = trim($_POST['institute_name'] ?? '');
    $formData['batch_name'] = trim($_POST['batch_name'] ?? '');
    $formData['batch_code'] = trim($_POST['batch_code'] ?? '');
    $formData['course'] = trim($_POST['course'] ?? '');
    $formData['start_date'] = trim($_POST['start_date'] ?? '');
    $formData['end_date'] = trim($_POST['end_date'] ?? '');
    $formData['status'] = trim($_POST['status'] ?? 'Active');
    
    // Basic validation
    if (empty($formData['institute_name'])) $errors['institute_name'] = 'Institute name is required';
    if (empty($formData['batch_name'])) $errors['batch_name'] = 'Batch name is required';
    if (empty($formData['batch_code'])) $errors['batch_code'] = 'Batch code is required';
    if (empty($formData['course'])) $errors['course'] = 'Course is required';
    if (empty($formData['start_date'])) $errors['start_date'] = 'Start date is required';
    
    // Validate dates
    if (!empty($formData['start_date']) && !empty($formData['end_date'])) {
        if (strtotime($formData['end_date']) < strtotime($formData['start_date'])) {
            $errors['end_date'] = 'End date must be after start date';
        }
    }
    
    // Validate teachers
    if (empty($_POST['teacher_ids']) || !is_array($_POST['teacher_ids'])) {
        $errors['teachers'] = 'At least one teacher is required';
    } else {
        $formData['teacher_ids'] = array_map('intval', $_POST['teacher_ids']);
        $formData['teacher_subjects'] = array_map('trim', $_POST['teacher_subjects'] ?? []);
        
        // Validate each teacher assignment
        foreach ($formData['teacher_ids'] as $index => $teacher_id) {
            if (empty($teacher_id)) {
                $errors['teachers'] = 'All teachers must be selected';
                break;
            }
            if (empty($formData['teacher_subjects'][$index])) {
                $errors['teachers'] = 'All subjects must be specified';
                break;
            }
        }
    }
    
    // Validate students
    if (empty($_POST['students']) || !is_array($_POST['students'])) {
        $errors['students'] = 'At least one student is required';
    } else {
        $formData['students'] = array_map('intval', $_POST['students']);
        
        // Check for duplicate students
        if (count($formData['students']) !== count(array_unique($formData['students']))) {
            $errors['students'] = 'Duplicate students are not allowed';
        }
    }
    
    // If no errors, proceed with database operations
    if (empty($errors)) {
        $conn->begin_transaction();
        
        try {
            // 1. Insert batch information
            $stmt = $conn->prepare("INSERT INTO batches (
                institute_name, batch_name, batch_code, course, 
                start_date, end_date, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())");
            
            $stmt->bind_param(
                "sssssss",
                $formData['institute_name'],
                $formData['batch_name'],
                $formData['batch_code'],
                $formData['course'],
                $formData['start_date'],
                $formData['end_date'] ?: null,
                $formData['status']
            );
            
            $stmt->execute();
            $batch_id = $conn->insert_id;
            $stmt->close();
            
            // 2. Insert teacher assignments with subjects
            $teacherStmt = $conn->prepare("INSERT INTO batch_teachers (batch_id, teacher_id, subject) VALUES (?, ?, ?)");
            
            foreach ($formData['teacher_ids'] as $index => $teacher_id) {
                $subject = $formData['teacher_subjects'][$index];
                $teacherStmt->bind_param("iis", $batch_id, $teacher_id, $subject);
                $teacherStmt->execute();
            }
            
            $teacherStmt->close();
            
            // 3. Insert student assignments
            $studentStmt = $conn->prepare("INSERT INTO batch_students (batch_id, student_id, status, enrolled_at) VALUES (?, ?, 'active', NOW())");
            
            foreach ($formData['students'] as $student_id) {
                $studentStmt->bind_param("ii", $batch_id, $student_id);
                $studentStmt->execute();
            }
            
            $studentStmt->close();
            
            $conn->commit();
            
            
            exit();
            
        } catch (Exception $e) {
            $conn->rollback();
            error_log("Batch creation error: " . $e->getMessage());
            $errors['database'] = "Failed to create batch. Please try again. Error: " . $e->getMessage();
        }
    }
}

// Fetch data for dropdowns
$institutes = $conn->query("SELECT DISTINCT institute_name FROM batches ORDER BY institute_name")->fetch_all(MYSQLI_ASSOC);
$courses = $conn->query("SELECT DISTINCT course FROM student_data WHERE course IS NOT NULL AND course != '' ORDER BY course")->fetch_all(MYSQLI_ASSOC);
$teachers = $conn->query("SELECT teacher_id, name, subject FROM teachers WHERE status = 'active' ORDER BY name")->fetch_all(MYSQLI_ASSOC);
$students = $conn->query("SELECT student_id, first_name, last_name, course FROM student_data WHERE is_active = 1 ORDER BY first_name, last_name")->fetch_all(MYSQLI_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create New Batch</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1000px;
            margin: 30px auto;
            padding: 20px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
        }
        
        h1, h2 {
            color: #2c3e50;
            margin-bottom: 20px;
        }
        
        h1 {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        
        .form-section {
            background: #f8fafc;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 25px;
            border-left: 4px solid #3498db;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
        }
        
        input[type="text"],
        input[type="date"],
        input[type="email"],
        input[type="tel"],
        select,
        textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        
        .form-row {
            display: flex;
            gap: 15px;
        }
        
        .form-row .form-group {
            flex: 1;
        }
        
        .btn-primary, .btn-secondary {
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background-color: #3498db;
            color: white;
        }
        
        .btn-primary:hover {
            background-color: #2980b9;
        }
        
        .btn-secondary {
            background-color: #6c757d;
            color: white;
        }
        
        .btn-secondary:hover {
            background-color: #5a6268;
        }
        
        .form-actions {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 20px;
        }
        
        .teacher-assignment, .student-assignment {
            display: flex;
            gap: 10px;
            align-items: center;
            margin-bottom: 10px;
            padding: 10px;
            background: #fff;
            border-radius: 4px;
            border: 1px solid #eee;
        }
        
        .teacher-assignment select, 
        .teacher-assignment input,
        .student-assignment select {
            flex: 1;
        }
        
        .btn-small {
            padding: 5px 10px;
            font-size: 14px;
        }
        
        .btn-danger {
            background-color: #e74c3c;
        }
        
        .btn-danger:hover {
            background-color: #c0392b;
        }
        
        .error-message {
            color: #e74c3c;
            font-size: 14px;
            margin-top: 5px;
        }
        
        .is-invalid {
            border-color: #e74c3c !important;
        }
        
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
    </style>
</head>

<body>
    <div class="container">
        <h1><i class="fas fa-users"></i> Create New Batch</h1>
        
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">
                <h4><i class="fas fa-exclamation-triangle"></i> Please fix the following errors:</h4>
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= htmlspecialchars($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form id="batchForm" method="post" action="">
            <!-- Batch Information Section -->
            <div class="form-section">
                <h2><i class="fas fa-info-circle"></i> Batch Information</h2>

                <div class="form-group">
                    <label for="institute_name">Institute Name:</label>
                    <select id="institute_name" name="institute_name" class="<?= isset($errors['institute_name']) ? 'is-invalid' : '' ?>" required>
                        <option value="">Select Institute</option>
                        <?php foreach($institutes as $inst): ?>
                        <option value="<?= htmlspecialchars($inst['institute_name']) ?>" <?= $formData['institute_name'] === $inst['institute_name'] ? 'selected' : '' ?>>
                            <?= htmlspecialchars($inst['institute_name']) ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                    <?php if (isset($errors['institute_name'])): ?>
                        <div class="error-message"><?= htmlspecialchars($errors['institute_name']) ?></div>
                    <?php endif; ?>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label for="batch_name">Batch Name:</label>
                        <input type="text" id="batch_name" name="batch_name" value="<?= htmlspecialchars($formData['batch_name']) ?>" class="<?= isset($errors['batch_name']) ? 'is-invalid' : '' ?>" required>
                        <?php if (isset($errors['batch_name'])): ?>
                            <div class="error-message"><?= htmlspecialchars($errors['batch_name']) ?></div>
                        <?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label for="batch_code">Batch Code:</label>
                        <input type="text" id="batch_code" name="batch_code" value="<?= htmlspecialchars($formData['batch_code']) ?>" class="<?= isset($errors['batch_code']) ? 'is-invalid' : '' ?>" required>
                        <?php if (isset($errors['batch_code'])): ?>
                            <div class="error-message"><?= htmlspecialchars($errors['batch_code']) ?></div>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="form-group">
                    <label for="course">Course:</label>
                    <select id="course" name="course" class="<?= isset($errors['course']) ? 'is-invalid' : '' ?>" required>
                        <option value="">Select Course</option>
                        <?php foreach($courses as $course): ?>
                        <option value="<?= htmlspecialchars($course['course']) ?>" <?= $formData['course'] === $course['course'] ? 'selected' : '' ?>>
                            <?= htmlspecialchars($course['course']) ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                    <?php if (isset($errors['course'])): ?>
                        <div class="error-message"><?= htmlspecialchars($errors['course']) ?></div>
                    <?php endif; ?>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label for="start_date">Start Date:</label>
                        <input type="date" id="start_date" name="start_date" value="<?= htmlspecialchars($formData['start_date']) ?>" class="<?= isset($errors['start_date']) ? 'is-invalid' : '' ?>" required>
                        <?php if (isset($errors['start_date'])): ?>
                            <div class="error-message"><?= htmlspecialchars($errors['start_date']) ?></div>
                        <?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label for="end_date">End Date:</label>
                        <input type="date" id="end_date" name="end_date" value="<?= htmlspecialchars($formData['end_date']) ?>" class="<?= isset($errors['end_date']) ? 'is-invalid' : '' ?>">
                        <?php if (isset($errors['end_date'])): ?>
                            <div class="error-message"><?= htmlspecialchars($errors['end_date']) ?></div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Teacher Assignment Section -->
            <div class="form-section">
                <h2><i class="fas fa-chalkboard-teacher"></i> Assign Teachers with Subjects</h2>
                <?php if (isset($errors['teachers'])): ?>
                    <div class="error-message mb-2"><?= htmlspecialchars($errors['teachers']) ?></div>
                <?php endif; ?>

                <div id="teacherAssignments">
                    <?php if (!empty($formData['teacher_ids'])): ?>
                        <?php foreach ($formData['teacher_ids'] as $index => $teacher_id): ?>
                            <div class="teacher-assignment">
                                <select name="teacher_ids[]" class="teacher-select" required>
                                    <option value="">Select Teacher</option>
                                    <?php foreach($teachers as $teacher): ?>
                                    <option value="<?= $teacher['teacher_id'] ?>" 
                                        data-subject="<?= htmlspecialchars($teacher['subject']) ?>"
                                        <?= $teacher_id == $teacher['teacher_id'] ? 'selected' : '' ?>>
                                        <?= htmlspecialchars($teacher['name']) ?> (
                                        <?= htmlspecialchars($teacher['subject']) ?>)
                                    </option>
                                    <?php endforeach; ?>
                                </select>

                                <input type="text" name="teacher_subjects[]" class="teacher-subject" 
                                    value="<?= htmlspecialchars($formData['teacher_subjects'][$index] ?? '') ?>" 
                                    placeholder="Subject" required>

                                <button type="button" class="removeTeacherBtn btn-small btn-danger">
                                    <i class="fas fa-times"></i>
                                </button>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>

                <button type="button" id="addTeacherBtn" class="btn-secondary">
                    <i class="fas fa-plus"></i> Add Teacher
                </button>
            </div>

            <!-- Student Assignment Section -->
            <div class="form-section">
                <h2><i class="fas fa-user-graduate"></i> Assign Students</h2>
                <?php if (isset($errors['students'])): ?>
                    <div class="error-message mb-2"><?= htmlspecialchars($errors['students']) ?></div>
                <?php endif; ?>

                <div id="studentAssignments">
                    <?php if (!empty($formData['students'])): ?>
                        <?php foreach ($formData['students'] as $student_id): ?>
                            <div class="student-assignment mb-2 d-flex align-items-center">
                                <select name="students[]" class="student-select form-control me-2" required>
                                    <option value="">Select Student</option>
                                    <?php foreach($students as $student): ?>
                                    <option value="<?= $student['student_id'] ?>"
                                        <?= $student_id == $student['student_id'] ? 'selected' : '' ?>>
                                        <?= htmlspecialchars($student['first_name'] . ' ' . $student['last_name']) ?> (
                                        <?= htmlspecialchars($student['course']) ?>)
                                    </option>
                                    <?php endforeach; ?>
                                </select>
                                <button type="button" class="removeStudentBtn btn-small btn-danger ms-2">
                                    <i class="fas fa-times"></i>
                                </button>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
                <button type="button" id="addStudentBtn" class="btn-secondary">
                    <i class="fas fa-plus"></i> Add Student
                </button>
            </div>

            <div class="form-actions">
                <button type="reset" class="btn-secondary">
                    <i class="fas fa-undo"></i> Reset
                </button>
                <button type="submit" class="btn-primary">
                    <i class="fas fa-save"></i> Create Batch
                </button>
            </div>
        </form>
    </div>

    <!-- Teacher Assignment Template -->
    <div id="teacherAssignmentTemplate" style="display:none;">
        <div class="teacher-assignment">
            <select name="teacher_ids[]" class="teacher-select" required>
                <option value="">Select Teacher</option>
                <?php foreach($teachers as $teacher): ?>
                <option value="<?= $teacher['teacher_id'] ?>" 
                    data-subject="<?= htmlspecialchars($teacher['subject']) ?>">
                    <?= htmlspecialchars($teacher['name']) ?> (
                    <?= htmlspecialchars($teacher['subject']) ?>)
                </option>
                <?php endforeach; ?>
            </select>

            <input type="text" name="teacher_subjects[]" class="teacher-subject" placeholder="Subject" required>

            <button type="button" class="removeTeacherBtn btn-small btn-danger">
                <i class="fas fa-times"></i>
            </button>
        </div>
    </div>

    <!-- Student Assignment Template -->
    <div id="studentAssignmentTemplate" style="display:none;">
        <div class="student-assignment mb-2 d-flex align-items-center">
            <select name="students[]" class="student-select form-control me-2" required>
                <option value="">Select Student</option>
                <?php foreach($students as $student): ?>
                <option value="<?= $student['student_id'] ?>">
                    <?= htmlspecialchars($student['first_name'] . ' ' . $student['last_name']) ?> (
                    <?= htmlspecialchars($student['course']) ?>)
                </option>
                <?php endforeach; ?>
            </select>
            <button type="button" class="removeStudentBtn btn-small btn-danger ms-2">
                <i class="fas fa-times"></i>
            </button>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function () {
            // Add teacher assignment row
            $('#addTeacherBtn').click(function () {
                const template = $('#teacherAssignmentTemplate').html();
                $('#teacherAssignments').append(template);
                updateTeacherSelects();
            });

            // Remove teacher assignment row
            $(document).on('click', '.removeTeacherBtn', function () {
                $(this).closest('.teacher-assignment').remove();
                updateTeacherSelects();
            });

            // Update subject field when teacher is selected
            $(document).on('change', '.teacher-select', function () {
                const selectedOption = $(this).find('option:selected');
                const subject = selectedOption.data('subject');
                $(this).closest('.teacher-assignment').find('.teacher-subject').val(subject || '');
            });

            // Add student assignment row
            $('#addStudentBtn').click(function () {
                const template = $('#studentAssignmentTemplate').html();
                $('#studentAssignments').append(template);
                updateStudentSelects();
            });

            // Remove student assignment row
            $(document).on('click', '.removeStudentBtn', function () {
                $(this).closest('.student-assignment').remove();
                updateStudentSelects();
            });

            // Ensure unique student selections
            function updateStudentSelects() {
                const selectedStudents = [];
                $('.student-select').each(function () {
                    const val = $(this).val();
                    if (val) selectedStudents.push(val);
                });

                $('.student-select').each(function () {
                    const currentVal = $(this).val();
                    $(this).find('option').each(function () {
                        const optionVal = $(this).val();
                        if (optionVal && selectedStudents.includes(optionVal) && optionVal !== currentVal) {
                            $(this).hide();
                        } else {
                            $(this).show();
                        }
                    });
                });
                
                // Show error if no students
                const studentError = $('#studentAssignments .student-assignment').length === 0;
                $('#studentAssignments').toggleClass('is-invalid', studentError);
            }

            // Update student dropdowns when changes occur
            $(document).on('change', '.student-select', updateStudentSelects);

            // Ensure unique teacher selections
            function updateTeacherSelects() {
                const selectedTeachers = [];
                $('.teacher-select').each(function () {
                    const val = $(this).val();
                    if (val) selectedTeachers.push(val);
                });

                $('.teacher-select').each(function () {
                    const currentVal = $(this).val();
                    $(this).find('option').each(function () {
                        const optionVal = $(this).val();
                        if (optionVal && selectedTeachers.includes(optionVal) && optionVal !== currentVal) {
                            $(this).hide();
                        } else {
                            $(this).show();
                        }
                    });
                });
                
                // Show error if no teachers
                const teacherError = $('#teacherAssignments .teacher-assignment').length === 0;
                $('#teacherAssignments').toggleClass('is-invalid', teacherError);
            }

            // Update teacher dropdowns when changes occur
            $(document).on('change', '.teacher-select', updateTeacherSelects);

            // Initialize with one student if none exists
            if ($('#studentAssignments .student-assignment').length === 0) {
                $('#addStudentBtn').click();
            }

            // Initialize with one teacher if none exists
            if ($('#teacherAssignments .teacher-assignment').length === 0) {
                $('#addTeacherBtn').click();
            }

            // Set default start date if not set
            if (!$('#start_date').val()) {
                $('#start_date').val(new Date().toISOString().split('T')[0]);
            }

            // Form validation
            $('#batchForm').submit(function (e) {
                // Validate at least one teacher
                if ($('#teacherAssignments .teacher-assignment').length === 0) {
                    e.preventDefault();
                    $('#teacherAssignments').addClass('is-invalid');
                    alert('Please assign at least one teacher to the batch.');
                    return false;
                }

                // Validate all teacher assignments are complete
                let teacherValid = true;
                $('.teacher-assignment').each(function () {
                    if ($(this).find('.teacher-select').val() === '' ||
                        $(this).find('.teacher-subject').val() === '') {
                        teacherValid = false;
                        return false; // break loop
                    }
                });

                if (!teacherValid) {
                    e.preventDefault();
                    alert('Please complete all teacher assignments (select teacher and subject).');
                    return false;
                }

                // Validate at least one student
                if ($('#studentAssignments .student-assignment').length === 0) {
                    e.preventDefault();
                    $('#studentAssignments').addClass('is-invalid');
                    alert('Please assign at least one student to the batch.');
                    return false;
                }

                return true;
            });
        });
    </script>
</body>
</html>