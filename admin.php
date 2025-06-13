<?php
// Include database connection securely
require_once 'db_connect.php';
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
    header("Location: logout.php?error=Database connection failed");
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

// Authentication check - only allow admin users
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
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

// Generate CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// Input validation functions
function validatePhone($phone)
{
    return preg_match('/^[0-9]{10}$/', $phone);
}

function validateEmail($email)
{
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function sanitizeInput($data)
{
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

// User Management Functions
function getAllUsers($conn)
{
    $users = [];
    $query = "SELECT u.id, u.username, u.name, u.email, u.phone, u.role, 
          u.institute_name, u.status, u.created_at, i.name as institute_name
          FROM users u
          LEFT JOIN institutes i ON u.institute_id = i.id";

    $stmt = $conn->prepare($query);

    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return $users;
    }

    $stmt->execute();
    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        $users[] = $row;
    }

    return $users;
}

function getUserById($conn, $user_id)
{
    $query = "SELECT * FROM users WHERE id = ?";
    $stmt = $conn->prepare($query);

    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return null;
    }

    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    return $result->fetch_assoc();
}

function addUser($conn, $data)
{
    $query = "INSERT INTO users (username, name, email, phone, password, role, 
          institute_name, institute_id, status) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($query);

    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return false;
    }

    // Hash the password
    $hashed_password = password_hash($data['password'], PASSWORD_DEFAULT);

    $stmt->bind_param(
        "sssssssss",
        $data['username'],
        $data['name'],
        $data['email'],
        $data['phone'],
        $hashed_password,
        $data['role'],
        $data['institute_name'],
        $data['institute_id'],
        $data['status']
    );

    return $stmt->execute();
}

function updateUser($conn, $user_id, $data)
{
    $query = "UPDATE users SET 
                username = ?,
                name = ?,
                email = ?,
                phone = ?,
                role = ?,
                institute_name = ?,
                status = ?
              WHERE id = ?";
    $stmt = $conn->prepare($query);

    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return false;
    }

    $stmt->bind_param(
        "sssssssi",
        $data['username'],
        $data['name'],
        $data['email'],
        $data['phone'],
        $data['role'],
        $data['institute_name'],
        $data['status'],
        $user_id
    );

    return $stmt->execute();
}

function deleteUser($conn, $user_id)
{
    $query = "DELETE FROM users WHERE id = ?";
    $stmt = $conn->prepare($query);

    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return false;
    }

    $stmt->bind_param("i", $user_id);
    return $stmt->execute();
}

function toggleUserStatus($conn, $user_id)
{
    try {
        // Get current status
        $query = "SELECT id, status FROM users WHERE id = ?";
        $stmt = $conn->prepare($query);
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }

        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            return ['status' => false, 'message' => 'User not found'];
        }

        $user = $result->fetch_assoc();
        $new_status = $user['status'] === 'active' ? 'inactive' : 'active';

        // Update status
        $query = "UPDATE users SET status = ? WHERE id = ?";
        $stmt = $conn->prepare($query);
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }

        $stmt->bind_param("si", $new_status, $user_id);
        $stmt->execute();

        return ['status' => true, 'new_status' => $new_status, 'message' => 'Status updated successfully'];
    } catch (Exception $e) {
        error_log("User status toggle error: " . $e->getMessage());
        return ['status' => false, 'message' => 'Database error'];
    }
}

// Institute Management Functions
function getAllInstitutes($conn)
{
    $institutes = [];
    $query = "SELECT * FROM institutes ORDER BY name";
    $stmt = $conn->prepare($query);

    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return $institutes;
    }

    $stmt->execute();
    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        $institutes[] = $row;
    }

    return $institutes;
}

function getInstituteById($conn, $institute_id)
{
    $query = "SELECT * FROM institutes WHERE id = ?";
    $stmt = $conn->prepare($query);

    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return null;
    }

    $stmt->bind_param("i", $institute_id);
    $stmt->execute();
    $result = $stmt->get_result();

    return $result->fetch_assoc();
}

function addInstitute($conn, $data)
{
    $query = "INSERT INTO institutes (name, address, phone, email, 
          office_incharge_name, office_incharge_contact, status) 
          VALUES (?, ?, ?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($query);

    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return false;
    }

    $stmt->bind_param(
        "sssssss",
        $data['name'],
        $data['address'],
        $data['phone'],
        $data['email'],
        $data['office_incharge_name'],
        $data['office_incharge_contact'],
        $data['status']
    );

    return $stmt->execute();
}

function updateInstitute($conn, $institute_id, $data)
{
    $query = "UPDATE institutes SET 
            name = ?,
            address = ?,
            phone = ?,
            email = ?,
            office_incharge_name = ?,
            office_incharge_contact = ?,
            status = ?
          WHERE id = ?";
    $stmt = $conn->prepare($query);

    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return false;
    }

    $stmt->bind_param(
        "ssssssi",
        $data['name'],
        $data['address'],
        $data['phone'],
        $data['email'],
        $data['office_incharge_name'],
        $data['office_incharge_contact'],
        $data['status'],
        $institute_id
    );

    return $stmt->execute();
}

function deleteInstitute($conn, $institute_id)
{
    $query = "DELETE FROM institutes WHERE id = ?";
    $stmt = $conn->prepare($query);

    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return false;
    }

    $stmt->bind_param("i", $institute_id);
    return $stmt->execute();
}

function toggleInstituteStatus($conn, $institute_id)
{
    try {
        // Get current status
        $query = "SELECT id, status FROM institutes WHERE id = ?";
        $stmt = $conn->prepare($query);
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }

        $stmt->bind_param("i", $institute_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            return ['status' => false, 'message' => 'Institute not found'];
        }

        $institute = $result->fetch_assoc();
        $new_status = $institute['status'] === 'active' ? 'inactive' : 'active';

        // Update status
        $query = "UPDATE institutes SET status = ? WHERE id = ?";
        $stmt = $conn->prepare($query);
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }

        $stmt->bind_param("si", $new_status, $institute_id);
        $stmt->execute();

        return ['status' => true, 'new_status' => $new_status, 'message' => 'Status updated successfully'];
    } catch (Exception $e) {
        error_log("Institute status toggle error: " . $e->getMessage());
        return ['status' => false, 'message' => 'Database error'];
    }
}

//  dashboard  Management Functions



function getFeesCollected($conn)
{
    $query = "SELECT SUM(total_amount) AS fees_collected FROM fees";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return 0;
    }
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    return $row['fees_collected'] ?? 0;
}

function getPendingDues($conn)
{
    $query = "SELECT SUM(total_amount) AS pending_fees FROM fees WHERE status = 'pending'";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return 0;
    }
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    return $row['pending_fees'] ?? 0;
}


function getRecentFees($conn, $limit = 5)
{
    $query = "SELECT * FROM fees ORDER BY payment_date DESC LIMIT ?";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return [];
    }
    $stmt->bind_param("i", $limit);
    $stmt->execute();
    $result = $stmt->get_result();
    $fees = [];
    while ($row = $result->fetch_assoc()) {
        $fees[] = $row;
    }
    return $fees;
}

function getRecentStudents($conn, $limit = 5)
{
    $query = "SELECT * FROM student_data ORDER BY created_at DESC LIMIT ?";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return [];
    }
    $stmt->bind_param("i", $limit);
    $stmt->execute();
    $result = $stmt->get_result();
    $students = [];
    while ($row = $result->fetch_assoc()) {
        $students[] = $row;
    }
    return $students;
}
function getAdmissions($conn)
{
    $currentYear = date("Y");
    $query = "SELECT COUNT(*) as current_year_admissions FROM student_data WHERE YEAR(admission_date) = ?";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return 0;
    }
    $stmt->bind_param("s", $currentYear);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    return $row['current_year_admissions'] ?? 0;
}


function get_all_students($conn)
{
    $students = [];
    $query = "SELECT * FROM student_data";
    $stmt = $conn->prepare($query);

    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return $students;
    }

    $stmt->execute();
    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        $row['is_active'] = $row['is_active'] ?? 1;
        $students[] = $row;
    }

    return $students;
}


function getAllFees($conn)
{
    $query = "SELECT * FROM fees ORDER BY payment_date";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return [];
    }
    $stmt->execute();
    $result = $stmt->get_result();
    $fees = [];
    while ($row = $result->fetch_assoc()) {
        $fees[] = $row;
    }
    return $fees;
}

function getPendingFees($conn)
{
    $query = "SELECT * FROM fees WHERE status = 'pending'";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return [];
    }
    $stmt->execute();
    $result = $stmt->get_result();
    $fees = [];
    while ($row = $result->fetch_assoc()) {
        $fees[] = $row;
    }
    return $fees;
}


function updateFeeStatus($conn, $fee_id, $status)
{
    $query = "UPDATE fees SET status = ? WHERE fee_id = ?";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return false;
    }
    $stmt->bind_param("si", $status, $fee_id);
    return $stmt->execute();
}

// Batch Management Functions
function getAllBatches($conn, $institute_name)
{
    $batches = [];

    if (empty($institute_name)) {
        die("Error: Institute name is empty");
        return $batches;
    }

    // Clean the institute name to ensure proper matching
    $institute_name = trim($conn->real_escape_string($institute_name));
    $query = "SELECT 
        b.batch_id, 
        b.institute_name, 
        b.batch_name, 
        b.batch_code, 
        b.course,
        b.start_date, 
        b.end_date,
        b.status,
        t.name as teacher_name,
        COUNT(bs.student_id) as student_count
      FROM batches b
      LEFT JOIN batch_teachers bt ON b.batch_id = bt.batch_id
      LEFT JOIN teachers t ON bt.teacher_id = t.teacher_id
      LEFT JOIN batch_students bs ON b.batch_id = bs.batch_id
      WHERE b.institute_name = ?
      GROUP BY b.batch_id";


    $stmt = $conn->prepare($query);
    if (!$stmt) {
        die("Prepare failed: " . $conn->error);
        return $batches;
    }

    $stmt->bind_param("s", $institute_name);
    if (!$stmt->execute()) {
        die("Execute failed: " . $stmt->error);
        return $batches;
    }

    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        // Ensure we have default values if NULL
        $row['teacher_name'] = $row['teacher_name'] ?? 'Not assigned';
        $row['student_count'] = $row['student_count'] ?? 0;
        $batches[] = $row;
    }

    return $batches;
}


function addStudentToBatch($conn, $batch_id, $student_id)
{
    try {
        // Check if student is already in batch
        $checkQuery = "SELECT * FROM batch_students WHERE batch_id = ? AND student_id = ?";
        $checkStmt = $conn->prepare($checkQuery);
        $checkStmt->bind_param("ii", $batch_id, $student_id);
        $checkStmt->execute();

        if ($checkStmt->get_result()->num_rows > 0) {
            return ['status' => false, 'message' => 'Student is already in this batch'];
        }

        // Add student to batch
        $query = "INSERT INTO batch_students (batch_id, student_id, status) VALUES (?, ?, 'active')";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("ii", $batch_id, $student_id);

        if ($stmt->execute()) {
            return ['status' => true, 'message' => 'Student added to batch successfully'];
        } else {
            return ['status' => false, 'message' => 'Failed to add student to batch'];
        }
    } catch (Exception $e) {
        error_log("Error adding student to batch: " . $e->getMessage());
        return ['status' => false, 'message' => 'Database error'];
    }
}

function removeStudentFromBatch($conn, $batch_id, $student_id)
{
    $query = "DELETE FROM batch_students WHERE batch_id = ? AND student_id = ?";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return false;
    }

    $stmt->bind_param("ii", $batch_id, $student_id);
    return $stmt->execute();
}



function deleteBatch($conn, $batch_id)
{
    try {
        $conn->begin_transaction();

        // Delete from batch_students
        $query1 = "DELETE FROM batch_students WHERE batch_id = ?";
        $stmt1 = $conn->prepare($query1);
        $stmt1->bind_param("i", $batch_id);
        $stmt1->execute();

        // Delete from batch_teachers
        $query2 = "DELETE FROM batch_teachers WHERE batch_id = ?";
        $stmt2 = $conn->prepare($query2);
        $stmt2->bind_param("i", $batch_id);
        $stmt2->execute();

        // Delete from batches
        $query3 = "DELETE FROM batches WHERE batch_id = ?";
        $stmt3 = $conn->prepare($query3);
        $stmt3->bind_param("i", $batch_id);
        $stmt3->execute();

        $conn->commit();
        return true;
    } catch (Exception $e) {
        $conn->rollback();
        error_log("Error deleting batch: " . $e->getMessage());
        return false;
    }
}


function getStatusBadgeColor($status)
{
    switch ($status) {
        case 'present':
            return 'success';
        case 'absent':
            return 'danger';
        case 'late':
            return 'warning';
        case 'half_day':
            return 'info';
        default:
            return 'secondary';
    }
}

function saveStudentData($conn, $data)
{
    $query = "INSERT INTO student_data (
        first_name, last_name, email, phone, dob, gender, photo_path,
        address, course, school_type, school,
        parent_name, parent_phone, Referred_by_About, Admission_Accpted_by, 
        institute_name, status, Admission_code
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return false;
    }

    $stmt->bind_param(
        "sssssssssssssssss",
        $data['first_name'],
        $data['last_name'],
        $data['email'],
        $data['phone'],
        $data['dob'],
        $data['gender'],
        $data['photo_path'],
        $data['address'],
        $data['course'],
        $data['school_type'],
        $data['school'],
        $data['parent_name'],
        $data['parent_phone'],
        $data['referred_by'],
        $data['admission_accepted_by'],
        $data['institute_name'],
        $data['status'],
        $data['admission_code']
    );

    return $stmt->execute();
}

function toggleStudentStatus($conn, $student_id)
{
    try {
        // Verify student exists and get current status
        $query = "SELECT student_id, COALESCE(is_active, 1) as is_active FROM student_data WHERE student_id = ?";
        $stmt = $conn->prepare($query);
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }

        $stmt->bind_param("i", $student_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            return ['status' => false, 'message' => 'Student not found'];
        }

        $student = $result->fetch_assoc();
        $new_status = $student['is_active'] ? 0 : 1;

        // Update status
        $query = "UPDATE student_data SET is_active = ? WHERE student_id = ?";
        $stmt = $conn->prepare($query);
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }

        $stmt->bind_param("ii", $new_status, $student_id);
        $stmt->execute();

        return ['status' => true, 'new_status' => $new_status, 'message' => 'Status updated successfully'];
    } catch (Exception $e) {
        error_log("Student status toggle error: " . $e->getMessage());
        return ['status' => false, 'message' => 'Database error'];
    }
}

// =============================================
// ATTENDANCE SYSTEM FUNCTIONS
// =============================================

/**
 * Get attendance records for a specific date and batch
 */
function getAttendanceRecords($conn, $batch_id, $date)
{
    $query = "SELECT a.*, s.first_name, s.last_name 
          FROM attendance a
          JOIN student_data s ON a.student_id = s.student_id
          WHERE a.student_id IN (
              SELECT student_id FROM batch_students 
              WHERE batch_id = ? AND status = 'active'
          ) AND a.date = ?";

    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return [];
    }

    $stmt->bind_param("is", $batch_id, $date);
    $stmt->execute();
    $result = $stmt->get_result();

    $records = [];
    while ($row = $result->fetch_assoc()) {
        $records[] = $row;
    }

    return $records;
}

/**
 * Get students in a batch who don't have attendance records for a specific date
 */
function getStudentsWithoutAttendance($conn, $batch_id, $date)
{
    $query = "SELECT s.student_id, s.first_name, s.last_name 
              FROM batch_students bs
              JOIN student_data s ON bs.student_id = s.student_id
              WHERE bs.batch_id = ? AND bs.status = 'active'
              AND NOT EXISTS (
                  SELECT 1 FROM attendance 
                  WHERE student_id = bs.student_id AND date = ?
              )";

    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return [];
    }

    $stmt->bind_param("is", $batch_id, $date);
    $stmt->execute();
    $result = $stmt->get_result();

    $students = [];
    while ($row = $result->fetch_assoc()) {
        $students[] = $row;
    }

    return $students;
}
/**
 * Save attendance records
 */
function saveAttendance($conn, $batch_id, $date, $attendance_data)
{
    try {
        $conn->begin_transaction();

        // First delete existing records for this batch and date
        $delete_query = "DELETE a FROM attendance a
                         JOIN batch_students bs ON a.student_id = bs.student_id
                         WHERE bs.batch_id = ? AND a.date = ?";

        $stmt = $conn->prepare($delete_query);
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }
        $stmt->bind_param("is", $batch_id, $date);
        $stmt->execute();

        // Insert new records
        $query = "INSERT INTO attendance (student_id, batch_id, date, status, notes) 
          VALUES (?, ?, ?, ?, ?)";
        $stmt = $conn->prepare($query);
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }

        foreach ($attendance_data as $student_id => $data) {
            $status = $data['status'];
            $notes = $data['notes'] ?? '';

            $stmt->bind_param("iisss", $student_id, $batch_id, $date, $status, $notes);
            if (!$stmt->execute()) {
                throw new Exception("Execute failed: " . $stmt->error);
            }
        }

        $conn->commit();
        return true;
    } catch (Exception $e) {
        $conn->rollback();
        error_log("Error saving attendance: " . $e->getMessage());
        return false;
    }
}

/**
 * Get batch details by ID
 */
function getBatchById($conn, $batch_id)
{
    $query = "SELECT * FROM batches WHERE batch_id = ?";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return null;
    }

    $stmt->bind_param("i", $batch_id);
    $stmt->execute();
    $result = $stmt->get_result();

    return $result->fetch_assoc();
}

/**
 * Get all active students in a batch
 */
function getBatchStudents($conn, $batch_id)
{
    $query = "SELECT s.student_id, s.first_name, s.last_name, s.photo_path 
              FROM batch_students bs
              JOIN student_data s ON bs.student_id = s.student_id
              WHERE bs.batch_id = ? AND bs.status = 'active'
              ORDER BY s.first_name, s.last_name";

    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return [];
    }

    $stmt->bind_param("i", $batch_id);
    $stmt->execute();
    $result = $stmt->get_result();

    $students = [];
    while ($row = $result->fetch_assoc()) {
        $students[] = $row;
    }

    return $students;
}

/**
 * Get attendance summary for a batch
 */
function getBatchAttendanceSummary($conn, $batch_id)
{
    $query = "SELECT 
                COUNT(DISTINCT student_id) AS total_students,
                SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) AS present_count,
                SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) AS absent_count,
                SUM(CASE WHEN status = 'late' THEN 1 ELSE 0 END) AS late_count,
                SUM(CASE WHEN status = 'half_day' THEN 1 ELSE 0 END) AS half_day_count
              FROM attendance
              WHERE student_id IN (
                  SELECT student_id FROM batch_students WHERE batch_id = ? AND status = 'active'
              )";

    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        return null;
    }

    $stmt->bind_param("i", $batch_id);
    $stmt->execute();
    $result = $stmt->get_result();

    return $result->fetch_assoc();
}

// Add these to your existing functions in admin.php

function getAttendanceSummary($conn, $batch_id)
{
    $query = "SELECT 
                COUNT(*) as total_students,
                SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) as present_count,
                SUM(CASE WHEN a.status = 'absent' THEN 1 ELSE 0 END) as absent_count,
                SUM(CASE WHEN a.status = 'late' THEN 1 ELSE 0 END) as late_count,
                SUM(CASE WHEN a.status = 'half_day' THEN 1 ELSE 0 END) as half_day_count
              FROM batch_students bs
              LEFT JOIN attendance a ON bs.student_id = a.student_id 
                AND a.date = CURDATE()
                AND a.batch_id = ?
              WHERE bs.batch_id = ? AND bs.status = 'active'";

    $stmt = $conn->prepare($query);
    $stmt->bind_param("ii", $batch_id, $batch_id);
    $stmt->execute();
    $result = $stmt->get_result();

    return $result->fetch_assoc();
}

function getMarkedDates($conn, $month, $year)
{
    $start_date = date("$year-$month-01");
    $end_date = date("$year-$month-t", strtotime($start_date));

    $query = "SELECT DISTINCT DATE_FORMAT(date, '%Y-%m-%d') as marked_date 
              FROM attendance 
              WHERE date BETWEEN ? AND ?";

    $stmt = $conn->prepare($query);
    $stmt->bind_param("ss", $start_date, $end_date);
    $stmt->execute();
    $result = $stmt->get_result();

    $dates = [];
    while ($row = $result->fetch_assoc()) {
        $dates[] = $row['marked_date'];
    }

    return $dates;
}

// Process form submissions
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');

    try {
        $response = ['success' => false, 'message' => 'Invalid request'];

        switch ($_GET['ajax']) {
            case 'get_attendance_report':
                // Validate inputs
                $batch_id = intval($_GET['batch_id'] ?? 0);
                $date = sanitizeInput($_GET['date'] ?? '');

                if (empty($batch_id) || empty($date)) {
                    throw new Exception("Batch ID and date are required");
                }

                // Get attendance records
                $attendance = getAttendanceRecords($conn, $batch_id, $date);
                $students_without_attendance = getStudentsWithoutAttendance($conn, $batch_id, $date);
                $batch = getBatchById($conn, $batch_id);

                $response = [
                    'success' => true,
                    'data' => [
                        'attendance' => $attendance,
                        'missing_attendance' => $students_without_attendance,
                        'batch' => $batch
                    ]
                ];
                break;

            case 'get_attendance_form':
                // Validate inputs
                $batch_id = intval($_GET['batch_id'] ?? 0);
                $date = sanitizeInput($_GET['date'] ?? '');

                if (empty($batch_id) || empty($date)) {
                    throw new Exception("Batch ID and date are required");
                }

                // Get students and existing attendance
                $students = getBatchStudents($conn, $batch_id);
                $existing_attendance = getAttendanceRecords($conn, $batch_id, $date);
                $batch = getBatchById($conn, $batch_id);

                // Prepare attendance data
                $attendance_data = [];
                foreach ($students as $student) {
                    $status = 'present'; // default
                    $notes = '';

                    // Check if attendance exists for this student
                    foreach ($existing_attendance as $record) {
                        if ($record['student_id'] == $student['student_id']) {
                            $status = $record['status'];
                            $notes = $record['notes'];
                            break;
                        }
                    }

                    $attendance_data[$student['student_id']] = [
                        'name' => $student['first_name'] . ' ' . $student['last_name'],
                        'photo' => $student['photo_path'] ?? 'default.jpg',
                        'status' => $status,
                        'notes' => $notes
                    ];
                }

                $response = [
                    'success' => true,
                    'data' => [
                        'attendance' => $attendance_data,
                        'batch' => $batch
                    ]
                ];
                break;
            case 'get_batch_options':
                $query = "SELECT batch_id, batch_name, batch_code FROM batches WHERE status = 'Active'";
                $stmt = $conn->prepare($query);
                $stmt->execute();
                $result = $stmt->get_result();

                $batches = [];
                while ($row = $result->fetch_assoc()) {
                    $batches[] = $row;
                }

                echo json_encode(['success' => true, 'batches' => $batches]);
                break;

            case 'get_batch_summaries':
                $query = "SELECT b.batch_id, b.batch_name, b.batch_code, b.course, b.status,
                     COUNT(bs.student_id) as total_students
              FROM batches b
              LEFT JOIN batch_students bs ON b.batch_id = bs.batch_id AND bs.status = 'active'
              WHERE b.status = 'Active'
              GROUP BY b.batch_id";

                $stmt = $conn->prepare($query);
                $stmt->execute();
                $result = $stmt->get_result();

                $batches = [];
                while ($row = $result->fetch_assoc()) {
                    $summary = getAttendanceSummary($conn, $row['batch_id']);
                    $batches[] = array_merge($row, $summary);
                }

                echo json_encode(['success' => true, 'batches' => $batches]);
                break;

            case 'get_marked_dates':
                $month = $_GET['month'] ?? date('m');
                $year = $_GET['year'] ?? date('Y');

                $dates = getMarkedDates($conn, $month, $year);
                echo json_encode(['success' => true, 'dates' => $dates]);
                break;
        }

        echo json_encode($response);
        exit();
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => $e->getMessage()
        ]);
        exit();
    }
}





// Process form submissions with CSRF validation
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $_SESSION['error_message'] = "CSRF token validation failed";
        header("Location: admin.php");
        exit();
    }

    $form_type = $_POST['form_type'] ?? '';
    $errors = [];
    $success = false;

    switch ($form_type) {
        case 'add_user':
            // Validate and sanitize inputs
            $data = [
                'username' => sanitizeInput($_POST['username'] ?? ''),
                'name' => sanitizeInput($_POST['name'] ?? ''),
                'email' => sanitizeInput($_POST['email'] ?? ''),
                'phone' => sanitizeInput($_POST['phone'] ?? ''),
                'password' => $_POST['password'] ?? '',
                'role' => sanitizeInput($_POST['role'] ?? ''),
                'institute_name' => sanitizeInput($_POST['institute_name'] ?? ''),
                'status' => sanitizeInput($_POST['status'] ?? 'active')
            ];

            // Validate required fields
            if (empty($data['username'])) $errors['username'] = 'Username is required';
            if (empty($data['name'])) $errors['name'] = 'Name is required';
            if (!validateEmail($data['email'])) $errors['email'] = 'Valid email is required';
            if (!validatePhone($data['phone'])) $errors['phone'] = 'Valid phone number is required';
            if (empty($data['password'])) $errors['password'] = 'Password is required';
            if (strlen($data['password']) < 8) $errors['password'] = 'Password must be at least 8 characters';
            if (empty($data['role'])) $errors['role'] = 'Role is required';

            if (empty($errors)) {
                if (addUser($conn, $data)) {
                    $_SESSION['success_message'] = "User added successfully!";
                    header("Location: admin.php?section=user-management");
                    exit();
                } else {
                    $errors['database'] = 'Failed to add user';
                }
            }
            break;

        case 'edit_user':
            $user_id = intval($_POST['user_id']);
            $data = [
                'username' => sanitizeInput($_POST['username'] ?? ''),
                'name' => sanitizeInput($_POST['name'] ?? ''),
                'email' => sanitizeInput($_POST['email'] ?? ''),
                'phone' => sanitizeInput($_POST['phone'] ?? ''),
                'role' => sanitizeInput($_POST['role'] ?? ''),
                'institute_name' => sanitizeInput($_POST['institute_name'] ?? ''),
                'status' => sanitizeInput($_POST['status'] ?? 'active')
            ];

            // Validate required fields
            if (empty($data['username'])) $errors['username'] = 'Username is required';
            if (empty($data['name'])) $errors['name'] = 'Name is required';
            if (!validateEmail($data['email'])) $errors['email'] = 'Valid email is required';
            if (!validatePhone($data['phone'])) $errors['phone'] = 'Valid phone number is required';
            if (empty($data['role'])) $errors['role'] = 'Role is required';

            if (empty($errors)) {
                if (updateUser($conn, $user_id, $data)) {
                    $_SESSION['success_message'] = "User updated successfully!";
                    header("Location: admin.php?section=user-management");
                    exit();
                } else {
                    $errors['database'] = 'Failed to update user';
                }
            }
            break;

        case 'delete_user':
            $user_id = intval($_POST['user_id']);
            if (deleteUser($conn, $user_id)) {
                $_SESSION['success_message'] = "User deleted successfully!";
            } else {
                $_SESSION['error_message'] = "Failed to delete user";
            }
            header("Location: admin.php?section=user-management");
            exit();
            break;

        case 'toggle_user_status':
            if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
                header('Content-Type: application/json');
                echo json_encode(['status' => false, 'message' => 'CSRF token validation failed']);
                exit;
            }
            $user_id = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
            if ($user_id === false || $user_id === null) {
                header('Content-Type: application/json');
                echo json_encode(['status' => false, 'message' => 'Invalid user ID']);
                exit;
            }
            $result = toggleUserStatus($conn, $user_id);
            header('Content-Type: application/json');
            echo json_encode($result);
            exit;
            break;

        case 'add_institute':
            $data = [
                'name' => sanitizeInput($_POST['name'] ?? ''),
                'address' => sanitizeInput($_POST['address'] ?? ''),
                'phone' => sanitizeInput($_POST['phone'] ?? ''),
                'email' => sanitizeInput($_POST['email'] ?? ''),
                'office_incharge_name' => sanitizeInput($_POST['office_incharge_name'] ?? ''),
                'office_incharge_contact' => sanitizeInput($_POST['office_incharge_contact'] ?? ''),
                'status' => sanitizeInput($_POST['status'] ?? 'active')
            ];

            // Validate required fields
            if (empty($data['name'])) $errors['name'] = 'Institute name is required';
            if (empty($data['address'])) $errors['address'] = 'Address is required';
            if (!validatePhone($data['phone'])) $errors['phone'] = 'Valid phone number is required';
            if (!empty($data['email']) && !validateEmail($data['email'])) $errors['email'] = 'Valid email is required';

            if (empty($errors)) {
                if (addInstitute($conn, $data)) {
                    $_SESSION['success_message'] = "Institute added successfully!";
                    header("Location: admin.php?section=institute-management");
                    exit();
                } else {
                    $errors['database'] = 'Failed to add institute';
                }
            }
            break;

        case 'edit_institute':
            $institute_id = intval($_POST['institute_id']);
            $data = [
                'name' => sanitizeInput($_POST['name'] ?? ''),
                'address' => sanitizeInput($_POST['address'] ?? ''),
                'phone' => sanitizeInput($_POST['phone'] ?? ''),
                'email' => sanitizeInput($_POST['email'] ?? ''),
                'website' => sanitizeInput($_POST['website'] ?? ''),
                'status' => sanitizeInput($_POST['status'] ?? 'active')
            ];

            // Validate required fields
            if (empty($data['name'])) $errors['name'] = 'Institute name is required';
            if (empty($data['address'])) $errors['address'] = 'Address is required';
            if (!validatePhone($data['phone'])) $errors['phone'] = 'Valid phone number is required';
            if (!empty($data['email']) && !validateEmail($data['email'])) $errors['email'] = 'Valid email is required';

            if (empty($errors)) {
                if (updateInstitute($conn, $institute_id, $data)) {
                    $_SESSION['success_message'] = "Institute updated successfully!";
                    header("Location: admin.php?section=institute-management");
                    exit();
                } else {
                    $errors['database'] = 'Failed to update institute';
                }
            }
            break;

        case 'delete_institute':
            $institute_id = intval($_POST['institute_id']);
            if (deleteInstitute($conn, $institute_id)) {
                $_SESSION['success_message'] = "Institute deleted successfully!";
            } else {
                $_SESSION['error_message'] = "Failed to delete institute";
            }
            header("Location: admin.php?section=institute-management");
            exit();
            break;

        case 'toggle_institute_status':
            if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
                header('Content-Type: application/json');
                echo json_encode(['status' => false, 'message' => 'CSRF token validation failed']);
                exit;
            }
            $institute_id = filter_input(INPUT_POST, 'institute_id', FILTER_VALIDATE_INT);
            if ($institute_id === false || $institute_id === null) {
                header('Content-Type: application/json');
                echo json_encode(['status' => false, 'message' => 'Invalid institute ID']);
                exit;
            }
            $result = toggleInstituteStatus($conn, $institute_id);
            header('Content-Type: application/json');
            echo json_encode($result);
            exit;
            break;
        case 'admission_form':
            // Validate and sanitize inputs
            $data = [
                'first_name' => sanitizeInput($_POST['first_name'] ?? ''),
                'last_name' => sanitizeInput($_POST['last_name'] ?? ''),
                'email' => sanitizeInput($_POST['email'] ?? ''),
                'phone' => sanitizeInput($_POST['phone'] ?? ''),
                'dob' => sanitizeInput($_POST['dob'] ?? ''),
                'gender' => sanitizeInput($_POST['gender'] ?? ''),
                'address' => sanitizeInput($_POST['address'] ?? ''),
                'course' => sanitizeInput($_POST['Course'] ?? ''),
                'school_type' => sanitizeInput($_POST['school_type'] ?? ''),
                'school' => sanitizeInput($_POST['school'] ?? ''),
                'parent_name' => sanitizeInput($_POST['parent_name'] ?? ''),
                'parent_phone' => sanitizeInput($_POST['parent_phone'] ?? ''),
                'referred_by' => sanitizeInput($_POST['Referred_by_About'] ?? ''),
                'admission_accepted_by' => sanitizeInput($_POST['Admission_Accpted_by'] ?? ''),
                'institute_name' => sanitizeInput($_POST['institute_name'] ?? ''),
                'status' => sanitizeInput($_POST['status'] ?? ''),
                'admission_code' => sanitizeInput($_POST['Admission_code'] ?? ''),
                'photo_path' => ''
            ];

            // Validate required fields
            if (empty($data['first_name'])) $errors['first_name'] = 'First name is required';
            if (empty($data['last_name'])) $errors['last_name'] = 'Last name is required';
            if (!validateEmail($data['email'])) $errors['email'] = 'Valid email is required';
            if (!validatePhone($data['phone'])) $errors['phone'] = 'Valid phone number is required';
            if (empty($data['dob'])) $errors['dob'] = 'Date of birth is required';
            if (empty($data['gender'])) $errors['gender'] = 'Gender is required';
            if (empty($data['address'])) $errors['address'] = 'Address is required';
            if (empty($data['course'])) $errors['course'] = 'Course is required';
            if (empty($data['parent_name'])) $errors['parent_name'] = 'Parent name is required';
            if (!validatePhone($data['parent_phone'])) $errors['parent_phone'] = 'Valid parent phone is required';
            if (empty($data['institute_name'])) $errors['institute_name'] = 'Institute is required';
            if (empty($data['admission_code'])) $errors['admission_code'] = 'Admission code is required';
            if (empty($data['status'])) $errors['status'] = 'Status is required';
            if (empty($_POST['terms'])) $errors['terms'] = 'You must accept the terms';

            // Handle file upload securely
            if (isset($_FILES['photo']) && $_FILES['photo']['error'] === UPLOAD_ERR_OK) {
                $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
                $fileExt = strtolower(pathinfo($_FILES['photo']['name'], PATHINFO_EXTENSION));

                if (!in_array($fileExt, $allowedExtensions)) {
                    $errors['photo'] = 'Invalid file type. Only JPG, PNG, and GIF are allowed.';
                } else {
                    $uploadDir = 'uploads/student_photos/';
                    if (!is_dir($uploadDir)) {
                        mkdir($uploadDir, 0755, true);
                    }

                    // Generate random filename
                    $fileName = bin2hex(random_bytes(16)) . '.' . $fileExt;
                    $destPath = $uploadDir . $fileName;

                    // Verify the file is actually an image
                    $imageInfo = getimagesize($_FILES['photo']['tmp_name']);
                    if ($imageInfo === false) {
                        $errors['photo'] = 'Uploaded file is not a valid image';
                    } elseif (move_uploaded_file($_FILES['photo']['tmp_name'], $destPath)) {
                        $data['photo_path'] = $destPath;
                    } else {
                        $errors['photo'] = 'Failed to upload photo';
                    }
                }
            }

            if (empty($errors)) {
                if (saveStudentData($conn, $data)) {
                    $_SESSION['success_message'] = "Student admission added successfully!";
                    header("Location: admin.php");
                    exit();
                } else {
                    $errors['database'] = 'Failed to save student data';
                }
            }
            break;

        case 'toggle_student_status':
            if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
                header('Content-Type: application/json');
                echo json_encode(['status' => false, 'message' => 'CSRF token validation failed']);
                exit;
            }

            $student_id = filter_input(INPUT_POST, 'student_id', FILTER_VALIDATE_INT);
            if ($student_id === false || $student_id === null) {
                header('Content-Type: application/json');
                echo json_encode(['status' => false, 'message' => 'Invalid student ID']);
                exit;
            }

            $result = toggleStudentStatus($conn, $student_id);
            header('Content-Type: application/json');
            echo json_encode($result);
            exit;
            break;



        case 'delete_batch':
            $batch_id = intval($_POST['batch_id']);
            if (deleteBatch($conn, $batch_id)) {
                $_SESSION['success_message'] = "Batch deleted successfully!";
            } else {
                $_SESSION['error_message'] = "Failed to delete batch";
            }
            header("Location: admin.php?section=batch-management");
            exit();
            break;

        case 'add_student_to_batch':
            $batch_id = intval($_POST['batch_id']);
            $student_id = intval($_POST['student_id']);
            $result = addStudentToBatch($conn, $batch_id, $student_id);
            if ($result['status']) {
                $_SESSION['success_message'] = $result['message'];
            } else {
                $_SESSION['error_message'] = $result['message'];
            }
            header("Location: admin.php?section=batch-management&action=view&batch_id=" . $batch_id);
            exit();
            break;

        case 'remove_student_from_batch':
            $batch_id = intval($_POST['batch_id']);
            $student_id = intval($_POST['student_id']);
            if (removeStudentFromBatch($conn, $batch_id, $student_id)) {
                $_SESSION['success_message'] = "Student removed from batch successfully!";
            } else {
                $_SESSION['error_message'] = "Failed to remove student from batch";
            }
            header("Location: admin.php?section=batch-management&action=view&batch_id=" . $batch_id);
            exit();
            break;


        case 'toggle_student_status':
            if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
                header('Content-Type: application/json');
                echo json_encode(['status' => false, 'message' => 'CSRF token validation failed']);
                exit;
            }
            $student_id = filter_input(INPUT_POST, 'student_id', FILTER_VALIDATE_INT);
            if ($student_id === false || $student_id === null) {
                header('Content-Type: application/json');
                echo json_encode(['status' => false, 'message' => 'Invalid student ID']);
                exit;
            }
            $result = toggleStudentStatus($conn, $student_id);
            header('Content-Type: application/json');
            echo json_encode($result);
            exit;
        case 'save_attendance':
            // Validate inputs
            $batch_id = intval($_POST['batch_id']);
            $date = sanitizeInput($_POST['date']);

            if (empty($batch_id)) {
                $errors[] = "Batch ID is required";
            }

            if (empty($date)) {
                $errors[] = "Date is required";
            }

            // Process attendance data
            $attendance_data = [];
            foreach ($_POST['attendance'] as $student_id => $data) {
                $student_id = intval($student_id);
                $status = sanitizeInput($data['status']);
                $notes = sanitizeInput($data['notes'] ?? '');

                $attendance_data[$student_id] = [
                    'status' => $status,
                    'notes' => $notes
                ];
            }

            if (empty($errors)) {
                if (saveAttendance($conn, $batch_id, $date, $attendance_data)) {
                    $_SESSION['success_message'] = "Attendance saved successfully!";
                } else {
                    $_SESSION['error_message'] = "Failed to save attendance";
                }
            } else {
                $_SESSION['error_message'] = implode("<br>", $errors);
            }


            if ($_SESSION['role'] === 'admin') {
                header("Location: admin.php?section=attendance-tracking");
            } else {
                header("Location: office.php?section=attendance-tracking");
            }

            exit();
            exit();
            break;


        default:
            $_SESSION['error_message'] = "Unknown form submission";
            if ($_SESSION['role'] === 'admin') {
                header("Location: admin.php");
            } else {
                header("Location: office.php");
            }
            exit();
    }

    // If we got here, there were errors - store them in session
    if (!empty($errors)) {
        $_SESSION['form_errors'] = $errors;
        $_SESSION['form_data'] = $_POST;
    }
}

// Get all users and institutes for display
$users = getAllUsers($conn);
$institutes = getAllInstitutes($conn);
$feesCollected = getFeesCollected($conn);
$pendingDues = getPendingDues($conn);
$admissions = getAdmissions($conn);
$recentFees = getRecentFees($conn);
$recentStudents = getRecentStudents($conn);
$batches = getAllBatches($conn, $_SESSION['institute_name'] ?? 'Vemac');
$allFees = getAllFees($conn);
$pendingFees = getPendingFees($conn);




// Handle search
$students = get_all_students($conn);

// Check for messages in URL
$message = isset($_GET['message']) ? sanitizeInput($_GET['message']) : '';
$section = isset($_GET['section']) ? sanitizeInput($_GET['section']) : 'dashboard';

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - VEMAC</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <!-- Custom CSS -->
    <style>
        :root {
            --primary-color: #4e73df;
            --secondary-color: #858796;
            --success-color: #1cc88a;
            --info-color: #36b9cc;
            --warning-color: #f6c23e;
            --danger-color: #e74a3b;
            --light-color: #f8f9fc;
            --dark-color: #5a5c69;
            --body-bg: #f8f9fa;
            --card-bg: #ffffff;
            --text-color: #333333;
            --sidebar-bg: #000000;
            --sidebar-text: #ffffff;
            --sidebar-hover: rgba(255, 255, 255, 0.1);
            --table-header-bg: #f8f9fc;
            --table-row-hover: rgba(0, 0, 0, 0.02);
            --primary-color-rgb: 78, 115, 223;
            --success-color-rgb: 28, 200, 138;
            --warning-color-rgb: 246, 194, 62;
            --danger-color-rgb: 231, 74, 59;
        }

        [data-bs-theme="dark"] {
            --primary-color: #4e73df;
            --secondary-color: #858796;
            --success-color: #1cc88a;
            --info-color: #36b9cc;
            --warning-color: #f6c23e;
            --danger-color: #e74a3b;
            --light-color: #2a3042;
            --dark-color: #d1d3e2;
            --body-bg: #1a1a2e;
            --card-bg: #16213e;
            --text-color: #e6e6e6;
            --sidebar-bg: #000000;
            --sidebar-text: #ffffff;
            --sidebar-hover: rgba(255, 255, 255, 0.1);
            --table-header-bg: #2a3042;
            --table-row-hover: rgba(255, 255, 255, 0.05);
        }

        body {
            background-color: var(--body-bg);
            color: var(--text-color);
            transition: background-color 0.3s ease, color 0.3s ease;
        }

        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            bottom: 0;
            z-index: 1000;
            background-color: #343a40;
            color: white;
            overflow-y: auto;
        }

        .sidebar a {
            color: var(--sidebar-text);
            text-decoration: none;
            padding: 12px 20px;
            display: block;
            border-radius: 5px;
            margin: 5px 10px;
            transition: all 0.3s;
        }

        .sidebar a:hover {
            background-color: var(--sidebar-hover);
            transform: translateX(5px);
        }

        .sidebar a.active {
            background-color: var(--primary-color);
            font-weight: 600;
        }

        .sidebar a i {
            margin-right: 10px;
            width: 20px;
            text-align: center;
        }

        .main-content {
            margin-left: 250px;
            padding: 20px;
            transition: margin 0.3s;
        }

        .card {
            margin-bottom: 20px;
            background-color: var(--card-bg);
            border: none;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }

        .card-title {
            color: var(--primary-color);
            font-weight: 600;
        }

        .card-text {
            font-size: 1.5rem;
            font-weight: 700;
        }

        .form-section {
            background-color: var(--card-bg);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        }

        .section-title {
            color: var(--primary-color);
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 10px;
            margin-bottom: 25px;
            font-weight: 600;
            display: flex;
            align-items: center;
        }

        .section-title i {
            margin-right: 10px;
        }

        .form-label {
            font-weight: 500;
            color: var(--text-color);
        }

        .form-control,
        .form-select {
            background-color: var(--card-bg);
            color: var(--text-color);
            border: 1px solid var(--secondary-color);
            padding: 10px 15px;
            border-radius: 5px;
        }

        .form-control:focus,
        .form-select:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(78, 115, 223, 0.25);
            background-color: var(--card-bg);
            color: var(--text-color);
        }

        /* Enhanced Table Styles */
        .table {
            width: 100%;
            margin-bottom: 1rem;
            color: var(--text-color);
            border-collapse: separate;
            border-spacing: 0;
        }

        .table thead th {
            background-color: var(--primary-color);
            color: white;
            font-weight: 600;
            padding: 12px 15px;
            position: sticky;
            top: 0;
            border: none;
        }

        .table thead th:first-child {
            border-top-left-radius: 10px;
            border-bottom-left-radius: 0;
        }

        .table thead th:last-child {
            border-top-right-radius: 10px;
            border-bottom-right-radius: 0;
        }

        .table tbody tr {
            transition: all 0.2s ease;
        }

        .table tbody tr:nth-child(even) {
            background-color: rgba(var(--primary-color-rgb), 0.05);
        }

        .table tbody tr:hover {
            background-color: rgba(var(--primary-color-rgb), 0.1);
            transform: translateX(2px);
        }

        .table td {
            padding: 12px 15px;
            vertical-align: middle;
            border-top: 1px solid rgba(0, 0, 0, 0.05);
        }

        .table td:first-child {
            border-left: 3px solid transparent;
        }

        .table tr:hover td:first-child {
            border-left: 3px solid var(--primary-color);
        }

        /* Status badges */
        .badge {
            padding: 6px 10px;
            font-weight: 500;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        /* Action buttons */
        .btn-table-action {
            padding: 5px 10px;
            font-size: 0.8rem;
            border-radius: 4px;
            margin: 2px;
            min-width: 80px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .btn-table-action i {
            margin-right: 5px;
        }

        /* Table responsive container */
        .table-responsive {
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        }

        /* Dark mode table adjustments */
        [data-bs-theme="dark"] .table thead th {
            background-color: var(--dark-color);
            color: var(--card-bg);
        }

        [data-bs-theme="dark"] .table tbody tr:nth-child(even) {
            background-color: rgba(255, 255, 255, 0.03);
        }

        [data-bs-theme="dark"] .table tbody tr:hover {
            background-color: rgba(255, 255, 255, 0.07);
        }

        [data-bs-theme="dark"] .table td {
            border-top: 1px solid rgba(255, 255, 255, 0.05);
        }

        .table {
            color: var(--text-color);
            background-color: var(--card-bg);
            border-radius: 10px;
            overflow: hidden;
        }

        .table thead th {
            background-color: var(--table-header-bg);
            border-bottom: 2px solid var(--secondary-color);
            font-weight: 600;
            position: sticky;
            top: 0;
        }

        .table tbody tr:hover {
            background-color: var(--table-row-hover);
        }

        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }

        .btn-success {
            background-color: var(--success-color);
            border-color: var(--success-color);
        }

        .btn-danger {
            background-color: var(--danger-color);
            border-color: var(--danger-color);
        }

        .btn-secondary {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
        }

        .nav-tabs .nav-link {
            color: var(--text-color);
        }

        .nav-tabs .nav-link.active {
            color: var(--primary-color);
            border-bottom: 2px solid var(--primary-color);
            font-weight: 600;
        }

        .required-field::after {
            content: " *";
            color: var(--danger-color);
        }

        .error-message {
            color: var(--danger-color);
            font-size: 0.875em;
        }

        .success-message {
            color: var(--success-color);
            font-size: 1.1em;
            font-weight: 500;
        }

        /* Toggle Switch Styles */
        .form-switch .form-check-input {
            width: 3em;
            height: 1.5em;
            margin-right: 0.5em;
        }

        .form-switch .form-check-input:checked {
            background-color: var(--success-color);
            border-color: var(--success-color);
        }

        .form-switch .form-check-input:focus {
            box-shadow: 0 0 0 0.25rem rgba(25, 135, 84, 0.25);
        }

        /* Toast Notifications */
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1100;
        }

        .toast {
            border: none;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        /* Dark mode toggle */
        .dark-mode-toggle {
            position: fixed;
            bottom: 20px;
            left: 20px;
            z-index: 1001;
            background: var(--sidebar-bg);
            color: var(--sidebar-text);
            border: none;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
        }

        /* Responsive adjustments */
        @media (max-width: 992px) {
            .sidebar {
                width: 70px;
                overflow: hidden;
            }

            .sidebar a span {
                display: none;
            }

            .sidebar a i {
                margin-right: 0;
                font-size: 1.2rem;
            }

            .main-content {
                margin-left: 70px;
            }

            .sidebar-brand {
                display: none;
            }
        }

        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                height: auto;
                position: relative;
            }

            .sidebar a {
                display: inline-block;
                padding: 10px;
                margin: 2px;
            }

            .main-content {
                margin-left: 0;
            }

            .sidebar-brand {
                display: block;
                text-align: center;
            }
        }

        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--card-bg);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--primary-color);
            border-radius: 10px;
        }

        /* Animation for cards */
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .card {
            animation: fadeIn 0.5s ease forwards;
        }

        /* Badge styles */
        .badge {
            padding: 5px 10px;
            font-weight: 600;
            border-radius: 20px;
        }

        /* Status badges */
        .badge-success {
            background-color: var(--success-color);
        }

        .badge-warning {
            background-color: var(--warning-color);
            color: #000;
        }

        .badge-danger {
            background-color: var(--danger-color);
        }

        /* Custom modal styles */
        .modal-content {
            background-color: var(--card-bg);
            color: var(--text-color);
            border: none;
            border-radius: 10px;
        }

        .modal-header {
            border-bottom: 1px solid var(--secondary-color);
        }

        .modal-footer {
            border-top: 1px solid var(--secondary-color);
        }

        /* Custom tab styles */
        .nav-tabs {
            border-bottom: 1px solid var(--secondary-color);
        }

        .nav-tabs .nav-link:hover {
            border-color: transparent;
            color: var(--primary-color);
        }

        /* Custom input group styles */
        .input-group-text {
            background-color: var(--table-header-bg);
            color: var(--text-color);
            border: 1px solid var(--secondary-color);
        }

        /* Custom pagination */
        .page-item.active .page-link {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }

        .page-link {
            color: var(--primary-color);
            background-color: var(--card-bg);
            border: 1px solid var(--secondary-color);
        }

        .page-link:hover {
            color: var(--primary-color);
            background-color: var(--table-header-bg);
            border-color: var(--secondary-color);
        }

        /* Custom dropdown styles */
        .dropdown-menu {
            background-color: var(--card-bg);
            border: 1px solid var(--secondary-color);
        }

        .dropdown-item {
            color: var(--text-color);
        }

        .dropdown-item:hover {
            background-color: var(--table-row-hover);
            color: var(--text-color);
        }

        /* Custom progress bar */
        .progress {
            background-color: var(--table-header-bg);
        }

        .progress-bar {
            background-color: var(--primary-color);
        }

        /* Custom alert styles */
        .alert {
            border: none;
            color: white;
        }

        .alert-success {
            background-color: var(--success-color);
        }

        .alert-danger {
            background-color: var(--danger-color);
        }

        .alert-info {
            background-color: var(--info-color);
        }

        .alert-warning {
            background-color: var(--warning-color);
            color: #000;
        }

        /* DataTables custom styling */
        .dataTables_wrapper .dataTables_filter input {
            background-color: var(--card-bg);
            color: var(--text-color);
            border: 1px solid var(--secondary-color);
            padding: 5px 10px;
            border-radius: 4px;
        }

        .dataTables_wrapper .dataTables_length select {
            background-color: var(--card-bg);
            color: var(--text-color);
            border: 1px solid var(--secondary-color);
        }

        .dataTables_wrapper .dataTables_info {
            color: var(--text-color);
        }

        .dataTables_wrapper .dataTables_paginate .paginate_button {
            color: var(--text-color) !important;
            border: 1px solid var(--secondary-color);
        }

        .dataTables_wrapper .dataTables_paginate .paginate_button.current {
            background: var(--primary-color) !important;
            color: white !important;
            border: 1px solid var(--primary-color);
        }

        /* Responsive table container */
        .table-responsive {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }

        /* Loading spinner */
        .spinner-container {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 200px;
        }

        /* Action buttons spacing */
        .action-buttons {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
        }

        /* Fixed header for tables */
        .table-fixed-header {
            position: relative;
        }

        .table-fixed-header thead th {
            position: sticky;
            top: 0;
            z-index: 10;
        }


        /* Attendance specific styles */
        .attendance-card {
            transition: all 0.3s ease;
            border-radius: 10px;
            overflow: hidden;
        }

        .attendance-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }

        .attendance-status {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 20px;
        }

        .status-badge {
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
        }

        .status-badge i {
            margin-right: 5px;
        }

        .present-badge {
            background-color: #d1fae5;
            color: #065f46;
        }

        .absent-badge {
            background-color: #fee2e2;
            color: #b91c1c;
        }

        .late-badge {
            background-color: #fef3c7;
            color: #92400e;
        }

        .halfday-badge {
            background-color: #dbeafe;
            color: #1e40af;
        }

        .student-attendance-item {
            display: flex;
            align-items: center;
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            background-color: var(--card-bg);
            border: 1px solid var(--secondary-color);
        }

        .student-photo {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            object-fit: cover;
            margin-right: 15px;
            border: 2px solid var(--primary-color);
        }

        .student-info {
            flex-grow: 1;
        }

        .student-name {
            font-weight: 600;
            margin-bottom: 3px;
        }

        .attendance-actions {
            display: flex;
            gap: 10px;
        }

        .attendance-select {
            min-width: 120px;
        }

        .attendance-notes {
            flex-grow: 1;
            max-width: 300px;
        }

        .attendance-calendar {
            background-color: var(--card-bg);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .calendar-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .calendar-title {
            font-size: 1.2rem;
            font-weight: 600;
        }

        .calendar-nav {
            display: flex;
            gap: 10px;
        }

        .calendar-grid {
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            gap: 5px;
        }

        .calendar-day-header {
            text-align: center;
            font-weight: 600;
            padding: 5px;
            color: var(--primary-color);
        }

        .calendar-day {
            aspect-ratio: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .calendar-day:hover {
            background-color: var(--table-row-hover);
        }

        .calendar-day.active {
            background-color: var(--primary-color);
            color: white;
        }

        .calendar-day.has-attendance {
            position: relative;
        }

        .calendar-day.has-attendance::after {
            content: '';
            position: absolute;
            bottom: 5px;
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background-color: var(--success-color);
        }

        .aFFFttendance-summary-chart {
            height: 300px;
            margin-top: 20px;
        }

        /* Responsive adjustments */
        @media (max-width: 768px) {
            .student-attendance-item {
                flex-direction: column;
                align-items: flex-start;
            }

            .attendance-actions {
                width: 100%;
                margin-top: 10px;
                flex-direction: column;
            }

            .attendance-select,
            .attendance-notes {
                width: 100%;
                max-width: 100%;
            }
        }
    </style>
</head>

<body>
    <!-- Dark Mode Toggle Button -->
    <button class="dark-mode-toggle" id="darkModeToggle">
        <i class="bi bi-moon-fill"></i>
    </button>

    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-2 sidebar p-0">
                <div class="sidebar-brand text-center py-3">
                    <h3 class="text-white">VEMAC</h3>
                </div>
                <ul class="nav flex-column mt-3">
                    <li>
                        <a href="#" onclick="showSection('dashboard')"
                            class="<?= $section === 'dashboard' ? 'active' : '' ?>">
                            <i class="bi bi-speedometer2"></i>
                            <span>Dashboard</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" onclick="showSection('user-management')"
                            class="<?= $section === 'user-management' ? 'active' : '' ?>">
                            <i class="bi bi-people"></i>
                            <span>User Management</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" onclick="showSection('student-management')"
                            class="<?= $section === 'student-management' ? 'active' : '' ?>">
                            <i class="bi bi-person-plus"></i>
                            <span>Student Admission</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" onclick="showSection('fees-management')"
                            class="<?= $section === 'fees-management' ? 'active' : '' ?>">
                            <i class="bi bi-cash register"></i>
                            <span>Fees Management</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" onclick="showSection('institute-management')"
                            class="<?= $section === 'institute-management' ? 'active' : '' ?>">
                            <i class="bi bi-building"></i>
                            <span>Institute Management</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" onclick="showSection('batch-management')"
                            class="<?= $section === 'batch-management' ? 'active' : '' ?>">
                            <i class="bi bi-calendar"></i>
                            <span>Batch Management</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" onclick="showSection('attendance-tracking')"
                            class="<?= $section === 'attendance-tracking' ? 'active' : '' ?>">
                            <i class="bi bi-check-square"></i>
                            <span>Attendance Tracking</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" onclick="showSection('system-settings')"
                            class="<?= $section === 'system-settings' ? 'active' : '' ?>">
                            <i class="bi bi-gear"></i>
                            <span>System Settings</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" onclick="showSection('reports')"
                            class="<?= $section === 'reports' ? 'active' : '' ?>">
                            <i class="bi bi-graph-up"></i>
                            <span>Reports</span>
                        </a>
                    </li>
                    <li class="mt-auto">
                        <a href="logout.php" class="logout-link">
                            <i class="bi bi-box-arrow-right"></i>
                            <span>Logout</span>
                        </a>
                    </li>
                </ul>
            </div>

            <!-- Main Content -->
            <div class="col-md-10 main-content">
                <!-- Toast Container -->
                <div class="toast-container position-fixed top-0 end-0 p-3">
                    <!-- Toasts will be added here dynamically -->
                </div>

                <?php if (isset($_SESSION['success_message'])): ?>
                    <div class="alert alert-success alert-dismissible fade show">
                        <?= $_SESSION['success_message'] ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                    <?php unset($_SESSION['success_message']); ?>
                <?php endif; ?>

                <?php if (isset($_SESSION['error_message'])): ?>
                    <div class="alert alert-danger alert-dismissible fade show">
                        <?= $_SESSION['error_message'] ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                    <?php unset($_SESSION['error_message']); ?>
                <?php endif; ?>

                <!-- Dashboard Panel -->
                <section id="dashboard" class="section" style="<?= $section === 'dashboard' ? '' : 'display: none;' ?>">
                    <div class="container-fluid px-0 mb-2">
                        <div class="row g-4">
                            <div class="col-12 col-md-8">
                                <div class="p-2 h-100">
                                    <h4 class="mb-1">
                                        Welcome, <span class="text-primary fw-bold">
                                            <?= htmlspecialchars($_SESSION['name'] ?? 'Admin'); ?>
                                        </span> 👋
                                    </h4>
                                    <p class="mb-0 text-muted">
                                        You are logged in as <span class="fw-semibold">Admin</span>
                                    </p>
                                </div>
                            </div>
                            <div class="col-12 col-md-4 d-flex justify-content-md-end align-items-start">
                                <div class="d-flex gap-2 mt-2 mt-md-0 flex-wrap">
                                    <button class="btn btn-sm btn-success d-flex align-items-center"
                                        data-bs-toggle="modal" data-bs-target="#addUserModal">
                                        <i class="bi bi-person-plus me-1"></i> Add User
                                    </button>
                                    <button class="btn btn-sm btn-success d-flex align-items-center"
                                        data-bs-toggle="modal" data-bs-target="#addInstituteModal">
                                        <i class="bi bi-building-add me-1"></i> Add Institute
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="row">
                        <div class="col-md-3">
                            <div class="card border-start border-primary border-4">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            <h5 class="card-title text-primary">Total Users</h5>
                                            <p class="card-text display-6 fw-bold">
                                                <?= count($users); ?>
                                            </p>
                                        </div>
                                        <div class="bg-primary bg-opacity-10 p-3 rounded-circle">
                                            <i class="bi bi-people text-primary fs-4"></i>
                                        </div>
                                    </div>
                                    <div class="mt-3">
                                        <a href="#" onclick="showSection('user-management')"
                                            class="text-primary text-decoration-none small">
                                            View users <i class="bi bi-arrow-right"></i>
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card border-start border-success border-4">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            <h5 class="card-title text-success">Active Users</h5>
                                            <p class="card-text display-6 fw-bold">
                                                <?= count(array_filter($users, function ($user) {
                                                    return $user['status'] === 'active';
                                                })); ?>
                                            </p>
                                        </div>
                                        <div class="bg-success bg-opacity-10 p-3 rounded-circle">
                                            <i class="bi bi-person-check text-success fs-4"></i>
                                        </div>
                                    </div>
                                    <div class="mt-3">
                                        <a href="#" onclick="showSection('user-management')"
                                            class="text-success text-decoration-none small">
                                            View active users <i class="bi bi-arrow-right"></i>
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card border-start border-info border-4">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            <h5 class="card-title text-info">Institutes</h5>
                                            <p class="card-text display-6 fw-bold">
                                                <?= count($institutes); ?>
                                            </p>
                                        </div>
                                        <div class="bg-info bg-opacity-10 p-3 rounded-circle">
                                            <i class="bi bi-building text-info fs-4"></i>
                                        </div>
                                    </div>
                                    <div class="mt-3">
                                        <a href="#" onclick="showSection('institute-management')"
                                            class="text-info text-decoration-none small">
                                            View institutes <i class="bi bi-arrow-right"></i>
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card border-start border-warning border-4">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            <h5 class="card-title text-warning">Active Institutes</h5>
                                            <p class="card-text display-6 fw-bold">
                                                <?= count(array_filter($institutes, function ($institute) {
                                                    return $institute['status'] === 'active';
                                                })); ?>
                                            </p>
                                        </div>
                                        <div class="bg-warning bg-opacity-10 p-3 rounded-circle">
                                            <i class="bi bi-building-check text-warning fs-4"></i>
                                        </div>
                                    </div>
                                    <div class="mt-3">
                                        <a href="#" onclick="showSection('institute-management')"
                                            class="text-warning text-decoration-none small">
                                            View active institutes <i class="bi bi-arrow-right"></i>
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Recent Activity Section -->
                    <div class="row mt-4">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header bg-primary text-white">
                                    <h5 class="mb-0">Recent Users</h5>
                                </div>
                                <div class="card-body">
                                    <div class="list-group">
                                        <?php
                                        $recentUsers = array_slice(array_reverse($users), 0, 5);
                                        if (empty($recentUsers)): ?>
                                            <div class="list-group-item">
                                                <p class="mb-1 text-muted">No recent users found</p>
                                            </div>
                                        <?php else: ?>
                                            <?php foreach ($recentUsers as $user): ?>
                                                <a href="#" class="list-group-item list-group-item-action">
                                                    <div class="d-flex w-100 justify-content-between">
                                                        <h6 class="mb-1">
                                                            <?= htmlspecialchars($user['name']) ?>
                                                        </h6>
                                                        <small>
                                                            <?= date('M d, Y', strtotime($user['created_at'] ?? 'now')) ?>
                                                        </small>
                                                    </div>
                                                    <p class="mb-1">
                                                        <?= htmlspecialchars($user['role']) ?>
                                                    </p>
                                                    <small>
                                                        <?= htmlspecialchars($user['institute_name'] ?? 'No institute') ?>
                                                    </small>
                                                </a>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header bg-primary text-white">
                                    <h5 class="mb-0">Recent Institutes</h5>
                                </div>
                                <div class="card-body">
                                    <div class="list-group">
                                        <?php
                                        $recentInstitutes = array_slice(array_reverse($institutes), 0, 5);
                                        if (empty($recentInstitutes)): ?>
                                            <div class="list-group-item">
                                                <p class="mb-1 text-muted">No recent institutes found</p>
                                            </div>
                                        <?php else: ?>
                                            <?php foreach ($recentInstitutes as $institute): ?>
                                                <a href="#" class="list-group-item list-group-item-action">
                                                    <div class="d-flex w-100 justify-content-between">
                                                        <h6 class="mb-1">
                                                            <?= htmlspecialchars($institute['name']) ?>
                                                        </h6>
                                                        <small>
                                                            <?= date('M d, Y', strtotime($institute['created_at'] ?? 'now')) ?>
                                                        </small>
                                                    </div>
                                                    <p class="mb-1">
                                                        <?= htmlspecialchars($institute['email']) ?>
                                                    </p>
                                                    <small>
                                                        <?= htmlspecialchars($institute['phone']) ?>
                                                    </small>
                                                </a>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- User Management Section -->
                <section id="user-management" class="section"
                    style="<?= $section === 'user-management' ? '' : 'display: none;' ?>">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2 class="mb-0">User Management</h2>
                        <button class="btn btn-success" data-bs-toggle="modal" data-bs-target="#addUserModal">
                            <i class="bi bi-person-plus"></i> Add User
                        </button>
                    </div>

                    <div class="card">
                        <div class="card-body">
                            <?php if ($message): ?>
                                <div class="alert alert-info">
                                    <?= htmlspecialchars($message) ?>
                                </div>
                            <?php endif; ?>

                            <!-- Users Table -->
                            <div class="table-responsive">
                                <table class="table table-hover" id="usersTable">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>User</th>
                                            <th>Role</th>
                                            <th>Institute</th>
                                            <th>Contact</th>
                                            <th>Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($users as $user): ?>
                                            <tr>
                                                <td>
                                                    <span class="text-muted">#</span>
                                                    <?= htmlspecialchars($user['id']) ?>
                                                </td>
                                                <td>
                                                    <div class="d-flex align-items-center">
                                                        <div class="avatar-placeholder rounded-circle me-2 bg-light text-dark d-flex align-items-center justify-content-center"
                                                            style="width: 32px; height: 32px;">
                                                            <?= substr(htmlspecialchars($user['name']), 0, 1) ?>
                                                        </div>
                                                        <div>
                                                            <strong>
                                                                <?= htmlspecialchars($user['name']) ?>
                                                            </strong>
                                                            <div class="text-muted small">@
                                                                <?= htmlspecialchars($user['username']) ?>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td>
                                                    <span class="badge bg-<?=
                                                                            $user['role'] === 'admin' ? 'primary' : ($user['role'] === 'office' ? 'info' : 'secondary')
                                                                            ?>">
                                                        <?= ucfirst($user['role']) ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <?= htmlspecialchars($user['institute_name'] ?? 'N/A') ?>
                                                </td>
                                                <td>
                                                    <div>
                                                        <?= htmlspecialchars($user['email']) ?>
                                                    </div>
                                                    <div class="text-muted small">
                                                        <?= htmlspecialchars($user['phone'] ?? 'N/A') ?>
                                                    </div>
                                                </td>
                                                <td>
                                                    <span
                                                        class="badge bg-<?= $user['status'] === 'active' ? 'success' : 'secondary' ?> bg-opacity-10 text-<?= $user['status'] === 'active' ? 'success' : 'secondary' ?> border border-<?= $user['status'] === 'active' ? 'success' : 'secondary' ?> border-opacity-25">
                                                        <?= ucfirst($user['status']) ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <div class="d-flex flex-wrap">
                                                        <button class="btn btn-table-action btn-outline-primary btn-sm"
                                                            onclick="editUser(<?= $user['id'] ?>)">
                                                            <i class="bi bi-pencil"></i> Edit
                                                        </button>
                                                        <button class="btn btn-table-action btn-outline-danger btn-sm ms-2"
                                                            onclick="confirmDeleteUser(<?= $user['id'] ?>)">
                                                            <i class="bi bi-trash"></i> Delete
                                                        </button>
                                                        <div class="form-check form-switch ms-2 d-flex align-items-center">
                                                            <input class="form-check-input user-status-toggle"
                                                                type="checkbox" role="switch"
                                                                id="userStatusToggle<?= $user['id'] ?>"
                                                                data-user-id="<?= $user['id'] ?>"
                                                                <?= $user['status'] === 'active' ? 'checked' : '' ?>>
                                                        </div>
                                                    </div>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Institute Management Section -->
                <section id="institute-management" class="section"
                    style="<?= $section === 'institute-management' ? '' : 'display: none;' ?>">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2 class="mb-0">Institute Management</h2>
                        <button class="btn btn-success" data-bs-toggle="modal" data-bs-target="#addInstituteModal">
                            <i class="bi bi-building-add"></i> Add Institute
                        </button>
                    </div>

                    <div class="card">
                        <div class="card-body">
                            <!-- Institutes Table -->
                            <div class="table-responsive">
                                <table class="table table-hover" id="institutesTable">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Institute</th>
                                            <th>Contact</th>
                                            <th>Website</th>
                                            <th>Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($institutes as $institute): ?>
                                            <tr>
                                                <td>
                                                    <span class="text-muted">#</span>
                                                    <?= htmlspecialchars($institute['id']) ?>
                                                </td>
                                                <td>
                                                    <strong>
                                                        <?= htmlspecialchars($institute['name']) ?>
                                                    </strong>
                                                    <div class="text-muted small">
                                                        <?= htmlspecialchars($institute['address']) ?>
                                                    </div>
                                                </td>
                                                <td>
                                                    <div>
                                                        <?= htmlspecialchars($institute['email']) ?>
                                                    </div>
                                                    <div class="text-muted small">
                                                        <?= htmlspecialchars($institute['phone']) ?>
                                                    </div>
                                                </td>
                                                <td>
                                                    <?php if (!empty($institute['website'])): ?>
                                                        <a href="<?= htmlspecialchars($institute['website']) ?>" target="_blank"
                                                            class="text-decoration-none">
                                                            <?= htmlspecialchars(parse_url($institute['website'], PHP_URL_HOST)) ?>
                                                        </a>
                                                    <?php else: ?>
                                                        <span class="text-muted">N/A</span>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <span
                                                        class="badge bg-<?= $institute['status'] === 'active' ? 'success' : 'secondary' ?> bg-opacity-10 text-<?= $institute['status'] === 'active' ? 'success' : 'secondary' ?> border border-<?= $institute['status'] === 'active' ? 'success' : 'secondary' ?> border-opacity-25">
                                                        <?= ucfirst($institute['status']) ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <div class="d-flex flex-wrap">
                                                        <button class="btn btn-table-action btn-outline-primary btn-sm"
                                                            onclick="editInstitute(<?= $institute['id'] ?>)">
                                                            <i class="bi bi-pencil"></i> Edit
                                                        </button>
                                                        <button class="btn btn-table-action btn-outline-danger btn-sm ms-2"
                                                            onclick="confirmDeleteInstitute(<?= $institute['id'] ?>)">
                                                            <i class="bi bi-trash"></i> Delete
                                                        </button>
                                                        <div class="form-check form-switch ms-2 d-flex align-items-center">
                                                            <input class="form-check-input institute-status-toggle"
                                                                type="checkbox" role="switch"
                                                                id="instituteStatusToggle<?= $institute['id'] ?>"
                                                                data-institute-id="<?= $institute['id'] ?>"
                                                                <?= $institute['status'] === 'active' ? 'checked' : '' ?>>
                                                        </div>
                                                    </div>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </section>


                <!-- Student Management Section -->
                <section id="student-management" class="section"
                    style="<?= $section === 'student-management' ? '' : 'display: none;' ?>">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2 class="mb-0">Student Management</h2>
                        <a href="Add_student.php" class="btn btn-success">
                            <i class="bi bi-person-plus"></i> Add Student
                        </a>
                    </div>

                    <div class="card">
                        <div class="card-body">
                            <?php if ($message): ?>
                                <div class="alert alert-info">
                                    <?= htmlspecialchars($message) ?>
                                </div>
                            <?php endif; ?>



                            <!-- Students Table -->
                            <div class="table-responsive">
                                <table class="table table-hover" id="studentsTable">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Name</th>
                                            <th>Institute</th>
                                            <th>Admission Code</th>
                                            <th>Contact</th>
                                            <th>Course</th>
                                            <th>Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($students as $student): ?>
                                            <tr>
                                                <td>
                                                    <span class="text-muted">#</span>
                                                    <?= htmlspecialchars($student['student_id']) ?>
                                                </td>
                                                <td>
                                                    <div class="d-flex align-items-center">
                                                        <?php if (!empty($student['photo_path'])): ?>
                                                            <img src="<?= htmlspecialchars($student['photo_path']) ?>"
                                                                class="rounded-circle me-2" width="32" height="32"
                                                                alt="<?= htmlspecialchars($student['first_name']) ?>">
                                                        <?php else: ?>
                                                            <div class="avatar-placeholder rounded-circle me-2 bg-light text-dark d-flex align-items-center justify-content-center"
                                                                style="width: 32px; height: 32px;">
                                                                <?= substr(htmlspecialchars($student['first_name']), 0, 1) ?>
                                                            </div>
                                                        <?php endif; ?>
                                                        <div>
                                                            <strong>
                                                                <?= htmlspecialchars($student['first_name']) ?>
                                                                <?= htmlspecialchars($student['last_name']) ?>
                                                            </strong>
                                                            <div class="text-muted small">
                                                                <?= htmlspecialchars($student['email']) ?>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td>
                                                    <?= htmlspecialchars($student['institute_name']) ?>
                                                </td>
                                                <td>
                                                    <span
                                                        class="badge bg-info bg-opacity-10 text-info border border-info border-opacity-25">
                                                        <?= htmlspecialchars($student['Admission_code']) ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <div>
                                                        <?= htmlspecialchars($student['phone']) ?>
                                                    </div>
                                                    <div class="text-muted small">
                                                        <?= htmlspecialchars($student['parent_phone']) ?>
                                                    </div>
                                                </td>
                                                <td>
                                                    <?= htmlspecialchars($student['course']) ?>
                                                </td>
                                                <td>
                                                    <span
                                                        class="badge bg-<?= ($student['is_active'] ?? 1) ? 'success' : 'secondary' ?> bg-opacity-10 text-<?= ($student['is_active'] ?? 1) ? 'success' : 'secondary' ?> border border-<?= ($student['is_active'] ?? 1) ? 'success' : 'secondary' ?> border-opacity-25">
                                                        <?= ($student['is_active'] ?? 1) ? 'Active' : 'Inactive' ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <div class="d-flex flex-wrap">
                                                        <a href="edit_student.php?id=<?= htmlspecialchars($student['student_id']) ?>"
                                                            class="btn btn-table-action btn-outline-primary btn-sm">
                                                            <i class="bi bi-pencil"></i> Edit
                                                        </a>

                                                        <form class="status-toggle-form d-inline" method="post"
                                                            autocomplete="off">
                                                            <input type="hidden" name="csrf_token"
                                                                value="<?= $csrf_token ?>">
                                                            <input type="hidden" name="form_type"
                                                                value="toggle_student_status">
                                                            <input type="hidden" name="student_id"
                                                                value="<?= $student['student_id'] ?>">
                                                            <div
                                                                class="form-check form-switch ms-2 d-flex align-items-center">
                                                                <input class="form-check-input status-toggle"
                                                                    type="checkbox" role="switch"
                                                                    id="statusToggle<?= $student['student_id'] ?>"
                                                                    data-student-id="<?= $student['student_id'] ?>"
                                                                    <?= ($student['is_active'] ?? 1) ? 'checked' : '' ?>>
                                                            </div>
                                                        </form>
                                                    </div>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Fees Management Section -->
                <section id="fees-management" class="section"
                    style="<?= $section === 'fees-management' ? '' : 'display: none;' ?>">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2 class="mb-0">Fees Management</h2>
                        <a href="add_fee.php" class="btn btn-primary">
                            <i class="bi bi-plus-circle"></i> Add Fee Payment
                        </a>
                    </div>

                    <div class="card">
                        <div class="card-body">
                            <!-- Navigation Tabs -->
                            <ul class="nav nav-tabs mb-4" id="feesTab" role="tablist">
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link active" id="all-fees-tab" data-bs-toggle="tab"
                                        data-bs-target="#all-fees" type="button" role="tab">All Fees</button>
                                </li>
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link" id="pending-fees-tab" data-bs-toggle="tab"
                                        data-bs-target="#pending-fees" type="button" role="tab">Pending Fees</button>
                                </li>
                            </ul>

                            <!-- Tab Content -->
                            <div class="tab-content" id="feesTabContent">
                                <!-- All Fees Tab -->
                                <div class="tab-pane fade show active" id="all-fees" role="tabpanel">
                                    <div class="table-responsive">
                                        <table class="table table-hover" id="allFeesTable">
                                            <thead>
                                                <tr>
                                                    <th>Payment ID</th>
                                                    <th>Student</th>
                                                    <th>Details</th>
                                                    <th>Amount</th>
                                                    <th>Date</th>
                                                    <th>Status</th>
                                                    <th>Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach (getAllFees($conn) as $fee): ?>
                                                    <tr>
                                                        <td>
                                                            <span class="text-muted">#</span>
                                                            <?= htmlspecialchars($fee['fee_id']) ?>
                                                        </td>
                                                        <td>
                                                            <strong>
                                                                <?= htmlspecialchars($fee['student_name']) ?>
                                                            </strong>

                                                        </td>
                                                        <td>
                                                            <div class="text-muted small">
                                                                <?= htmlspecialchars($fee['payment_method'] ?? 'N/A') ?>
                                                            </div>
                                                            <div class="text-muted small">
                                                                <?= htmlspecialchars($fee['transaction_id'] ?? '') ?>
                                                            </div>
                                                        </td>
                                                        <td>
                                                            <strong>₹
                                                                <?= number_format($fee['total_amount'], 2) ?>
                                                            </strong>
                                                        </td>
                                                        <td>
                                                            <?= date('d M Y', strtotime($fee['payment_date'])) ?>
                                                            <div class="text-muted small">
                                                                <?= date('h:i A', strtotime($fee['payment_date'])) ?>
                                                            </div>
                                                        </td>
                                                        <td>
                                                            <span
                                                                class="badge bg-<?= $fee['status'] === 'paid' ? 'success' : 'warning' ?> bg-opacity-10 text-<?= $fee['status'] === 'paid' ? 'success' : 'warning' ?> border border-<?= $fee['status'] === 'paid' ? 'success' : 'warning' ?> border-opacity-25">
                                                                <?= ucfirst($fee['status']) ?>
                                                            </span>
                                                        </td>
                                                        <td>
                                                            <div class="d-flex flex-wrap">
                                                                <a href="edit_fee.php?fee_id=<?= htmlspecialchars($fee['fee_id']) ?>"
                                                                    class="btn btn-table-action btn-outline-primary btn-sm">
                                                                    <i class="bi bi-pencil"></i> Edit
                                                                </a>
                                                                <?php if ($fee['status'] === 'pending'): ?>
                                                                    <button
                                                                        class="btn btn-table-action btn-outline-success btn-sm"
                                                                        onclick="markAsPaid(<?= $fee['fee_id'] ?>)">
                                                                        <i class="bi bi-check-circle"></i> Paid
                                                                    </button>
                                                                <?php endif; ?>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Batch Management Section -->
                <section id="batch-management" class="section"
                    style="<?= $section === 'batch-management' ? '' : 'display: none;' ?>">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2 class="mb-0">Batch Management</h2>
                        <a href="batch_create.php" class="btn btn-primary">
                            <i class="bi bi-plus-circle"></i> Create Batch
                        </a>
                    </div>

                    <div class="card">
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-hover" id="batchesTable">
                                    <thead>
                                        <tr>
                                            <th>Batch</th>
                                            <th>Details</th>
                                            <th>Schedule</th>
                                            <th>Teacher</th>
                                            <th>Students</th>
                                            <th>Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($batches as $batch): ?>
                                            <tr>
                                                <td>
                                                    <strong>
                                                        <?= htmlspecialchars($batch['batch_name']) ?>
                                                    </strong>
                                                    <div class="text-muted small">
                                                        <?= htmlspecialchars($batch['batch_code']) ?>
                                                    </div>
                                                </td>
                                                <td>
                                                    <div>
                                                        <?= htmlspecialchars($batch['institute_name']) ?>
                                                    </div>
                                                    <div class="text-muted small">
                                                        <?= htmlspecialchars($batch['course'] ?? 'N/A') ?>
                                                    </div>
                                                </td>
                                                <td>
                                                    <?php if (!empty($batch['start_date'])): ?>
                                                        <div>Starts:
                                                            <?= date('d M Y', strtotime($batch['start_date'])) ?>
                                                        </div>
                                                        <div class="text-muted small">
                                                            <?php if (!empty($batch['end_date'])): ?>
                                                                Ends:
                                                                <?= date('d M Y', strtotime($batch['end_date'])) ?>
                                                            <?php else: ?>
                                                                Ongoing
                                                            <?php endif; ?>
                                                        </div>
                                                    <?php else: ?>
                                                        <span class="text-muted">Not scheduled</span>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <?= htmlspecialchars($batch['teacher_name'] ?? 'Not assigned') ?>
                                                </td>
                                                <td>
                                                    <div class="d-flex align-items-center">
                                                        <div class="progress flex-grow-1 me-2" style="height: 6px;">
                                                            <div class="progress-bar bg-primary"
                                                                style="width: <?= min(100, ($batch['student_count'] / ($batch['max_students'] ?? 30)) * 100) ?>%">
                                                            </div>
                                                        </div>
                                                        <span>
                                                            <?= $batch['student_count'] ?? 0 ?>
                                                        </span>
                                                    </div>
                                                </td>
                                                <td>
                                                    <span
                                                        class="badge bg-<?= ($batch['status'] ?? '') === 'Active' ? 'success' : 'secondary' ?> bg-opacity-10 text-<?= ($batch['status'] ?? '') === 'Active' ? 'success' : 'secondary' ?> border border-<?= ($batch['status'] ?? '') === 'Active' ? 'success' : 'secondary' ?> border-opacity-25">
                                                        <?= htmlspecialchars($batch['status'] ?? 'N/A') ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <div class="dropdown">
                                                        <button
                                                            class="btn btn-table-action btn-outline-primary btn-sm dropdown-toggle"
                                                            type="button" data-bs-toggle="dropdown">
                                                            <i class="bi bi-gear"></i> Actions
                                                        </button>
                                                        <ul class="dropdown-menu">
                                                            <li>
                                                                <a class="dropdown-item"
                                                                    href="batch_view.php?batch_id=<?= $batch['batch_id'] ?>">
                                                                    <i class="bi bi-eye"></i> View
                                                                </a>
                                                            </li>
                                                            <li>
                                                                <a class="dropdown-item"
                                                                    href="batch_edit.php?batch_id=<?= $batch['batch_id'] ?>">
                                                                    <i class="bi bi-pencil"></i> Edit
                                                                </a>
                                                            </li>
                                                            <li>
                                                                <a class="dropdown-item"
                                                                    href="batch_students.php?batch_id=<?= $batch['batch_id'] ?>">
                                                                    <i class="bi bi-people"></i> Students
                                                                </a>
                                                            </li>
                                                            <li>
                                                                <hr class="dropdown-divider">
                                                            </li>
                                                            <li>
                                                                <button class="dropdown-item text-danger"
                                                                    onclick="confirmDeleteBatch(<?= $batch['batch_id'] ?>)">
                                                                    <i class="bi bi-trash"></i> Delete
                                                                </button>
                                                            </li>
                                                        </ul>
                                                    </div>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>

                        </div>
                    </div>
                </section>


                <!-- Attendance Tracking Section -->
                <section id="attendance-tracking" class="section" style="display: none;">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <div>
                            <h2 class="mb-0">Attendance Tracking</h2>
                            <p class="text-muted mb-0">Monitor and manage student attendance records</p>
                        </div>
                        <div class="d-flex gap-2">
                            <a href="attendance_add.php" class="btn btn-primary">
                                <i class="bi bi-plus-circle me-1"></i> Mark Attendance
                            </a>
                            <button class="btn btn-outline-secondary" id="refreshAttendance" title="Refresh Data">
                                <i class="bi bi-arrow-clockwise"></i>
                                <span class="d-none d-md-inline"> Refresh</span>
                            </button>
                        </div>
                    </div>

                    <!-- Batch Summary Cards -->
                    <div class="row mb-4 g-3" id="batchSummaryCards">
                        <!-- Loading Skeleton -->
                        <div class="col-12">
                            <div class="card">
                                <div class="card-body">
                                    <div class="d-flex justify-content-center py-4">
                                        <div class="spinner-border text-primary" role="status">
                                            <span class="visually-hidden">Loading...</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="row g-4">
                        <div class="col-lg-5">
                            <div class="card h-100">
                                <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                                    <h5 class="mb-0">Attendance Calendar</h5>
                                    <div class="d-flex gap-2">
                                        <button class="btn btn-sm btn-light" id="prevMonth" title="Previous Month">
                                            <i class="bi bi-chevron-left"></i>
                                        </button>
                                        <button class="btn btn-sm btn-light" id="todayMonth" title="Current Month">
                                            Today
                                        </button>
                                        <button class="btn btn-sm btn-light" id="nextMonth" title="Next Month">
                                            <i class="bi bi-chevron-right"></i>
                                        </button>
                                    </div>
                                </div>
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-center mb-3">
                                        <h4 id="calendarMonthYear" class="mb-0">Loading...</h4>
                                        <div class="btn-group" role="group">
                                            <button type="button" class="btn btn-outline-primary btn-sm active" id="viewMonth">
                                                Month
                                            </button>
                                            <button type="button" class="btn btn-outline-primary btn-sm" id="viewWeek">
                                                Week
                                            </button>
                                        </div>
                                    </div>
                                    <div id="calendarContainer">
                                        <div class="text-center py-4">
                                            <div class="spinner-border text-primary" role="status">
                                                <span class="visually-hidden">Loading...</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="col-lg-7">
                            <div class="card h-100">
                                <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                                    <h5 class="mb-0">Daily Attendance Report</h5>
                                    <div class="dropdown">
                                        <button class="btn btn-sm btn-light dropdown-toggle" type="button" id="reportActionsDropdown"
                                            data-bs-toggle="dropdown" aria-expanded="false">
                                            <i class="bi bi-gear"></i>
                                        </button>
                                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="reportActionsDropdown">
                                            <li><a class="dropdown-item" href="#" onclick="printAttendanceReport()">
                                                    <i class="bi bi-printer me-2"></i>Print Report
                                                </a></li>
                                            <li><a class="dropdown-item" href="#" onclick="exportAttendanceToExcel()">
                                                    <i class="bi bi-file-earmark-excel me-2"></i>Export to Excel
                                                </a></li>
                                            <li>
                                                <hr class="dropdown-divider">
                                            </li>
                                            <li><a class="dropdown-item" href="#" id="sendReportEmail">
                                                    <i class="bi bi-envelope me-2"></i>Email Report
                                                </a></li>
                                        </ul>
                                    </div>
                                </div>
                                <div class="card-body d-flex flex-column">
                                    <form id="attendanceReportForm" class="row g-3 mb-4">
                                        <div class="col-md-6">
                                            <label class="form-label">Batch</label>
                                            <select name="batch_id" class="form-select" id="reportBatchSelect" required>
                                                <option value="">Select Batch</option>
                                                <!-- Options will be loaded via AJAX -->
                                            </select>
                                        </div>
                                        <div class="col-md-4">
                                            <label class="form-label">Date</label>
                                            <div class="input-group">
                                                <input type="date" name="date" class="form-control" id="reportDate" required>
                                                <button class="btn btn-outline-secondary" type="button" id="todayDateBtn">
                                                    Today
                                                </button>
                                            </div>
                                        </div>
                                        <div class="col-md-2 d-flex align-items-end">
                                            <button type="submit" class="btn btn-success w-100">
                                                <i class="bi bi-search me-1"></i> View
                                            </button>
                                        </div>
                                    </form>

                                    <div id="attendanceReportContainer" class="flex-grow-1">
                                        <div class="d-flex flex-column justify-content-center align-items-center text-center text-muted py-5 h-100">
                                            <i class="bi bi-calendar-check fs-1 mb-3"></i>
                                            <h5>No Report Selected</h5>
                                            <p class="mb-0">Select a batch and date to view attendance records</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Attendance Report Template (hidden) -->
                    <template id="attendanceReportTemplate">
                        <div class="attendance-report">
                            <div class="d-flex justify-content-between align-items-center mb-4">
                                <div>
                                    <h4 class="mb-0" id="reportBatchName"></h4>
                                    <p class="text-muted mb-0" id="reportDateDisplay"></p>
                                </div>
                                <div class="d-flex gap-2">
                                    <span class="badge bg-primary rounded-pill" id="reportTotalStudents"></span>
                                </div>
                            </div>

                            <div class="row mb-4 g-3">
                                <div class="col-md-3">
                                    <div class="card border-start border-success border-4 h-100">
                                        <div class="card-body">
                                            <div class="d-flex justify-content-between align-items-center">
                                                <div>
                                                    <h6 class="card-title text-success">Present</h6>
                                                    <p class="card-text fw-bold fs-4 mb-0" id="presentCount">0</p>
                                                    <small class="text-muted" id="presentPercentage">0%</small>
                                                </div>
                                                <div class="bg-success bg-opacity-10 p-2 rounded-circle">
                                                    <i class="bi bi-check-circle text-success fs-4"></i>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="card border-start border-danger border-4 h-100">
                                        <div class="card-body">
                                            <div class="d-flex justify-content-between align-items-center">
                                                <div>
                                                    <h6 class="card-title text-danger">Absent</h6>
                                                    <p class="card-text fw-bold fs-4 mb-0" id="absentCount">0</p>
                                                    <small class="text-muted" id="absentPercentage">0%</small>
                                                </div>
                                                <div class="bg-danger bg-opacity-10 p-2 rounded-circle">
                                                    <i class="bi bi-x-circle text-danger fs-4"></i>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="card border-start border-warning border-4 h-100">
                                        <div class="card-body">
                                            <div class="d-flex justify-content-between align-items-center">
                                                <div>
                                                    <h6 class="card-title text-warning">Late</h6>
                                                    <p class="card-text fw-bold fs-4 mb-0" id="lateCount">0</p>
                                                    <small class="text-muted" id="latePercentage">0%</small>
                                                </div>
                                                <div class="bg-warning bg-opacity-10 p-2 rounded-circle">
                                                    <i class="bi bi-clock-history text-warning fs-4"></i>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="card border-start border-info border-4 h-100">
                                        <div class="card-body">
                                            <div class="d-flex justify-content-between align-items-center">
                                                <div>
                                                    <h6 class="card-title text-info">Half Day</h6>
                                                    <p class="card-text fw-bold fs-4 mb-0" id="halfDayCount">0</p>
                                                    <small class="text-muted" id="halfDayPercentage">0%</small>
                                                </div>
                                                <div class="bg-info bg-opacity-10 p-2 rounded-circle">
                                                    <i class="bi bi-hourglass-split text-info fs-4"></i>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="card mb-4">
                                <div class="card-header bg-light">
                                    <h5 class="mb-0">Attendance Details</h5>
                                </div>
                                <div class="card-body p-0">
                                    <div class="table-responsive">
                                        <table class="table table-hover mb-0">
                                            <thead class="table-light">
                                                <tr>
                                                    <th>Student</th>
                                                    <th width="120">Status</th>
                                                    <th>Notes</th>
                                                    <th width="120">Time</th>
                                                </tr>
                                            </thead>
                                            <tbody id="attendanceReportBody">
                                                <!-- Attendance rows will be inserted here -->
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>

                            <div class="card">
                                <div class="card-header bg-light">
                                    <h5 class="mb-0">Students Without Attendance</h5>
                                </div>
                                <div class="card-body">
                                    <div class="alert alert-warning mb-0" id="noMissingStudents" style="display: none;">
                                        <i class="bi bi-check-circle me-2"></i> All students have attendance records for this date.
                                    </div>
                                    <div id="missingAttendanceList" class="list-group">
                                        <!-- Students without attendance will be listed here -->
                                    </div>
                                </div>
                            </div>
                        </div>
                    </template>
                </section>

                
                <!-- System Settings Section -->
                <section id="system-settings" class="section"
                    style="<?= $section === 'system-settings' ? '' : 'display: none;' ?>">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2 class="mb-0">System Settings</h2>
                    </div>

                    <div class="card">
                        <div class="card-body">
                            <form id="systemSettingsForm">
                                <div class="row mb-4">
                                    <div class="col-md-6">
                                        <h5 class="mb-3">General Settings</h5>
                                        <div class="mb-3">
                                            <label for="systemName" class="form-label">System Name</label>
                                            <input type="text" class="form-control" id="systemName" value="VEMAC">
                                        </div>
                                        <div class="mb-3">
                                            <label for="timezone" class="form-label">Timezone</label>
                                            <select class="form-select" id="timezone">
                                                <option value="Asia/Kolkata" selected>Asia/Kolkata (IST)</option>
                                                <option value="UTC">UTC</option>
                                                <!-- Add more timezones as needed -->
                                            </select>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <h5 class="mb-3">Security Settings</h5>
                                        <div class="mb-3">
                                            <div class="form-check form-switch">
                                                <input class="form-check-input" type="checkbox" id="enable2FA" checked>
                                                <label class="form-check-label" for="enable2FA">Enable Two-Factor
                                                    Authentication</label>
                                            </div>
                                        </div>
                                        <div class="mb-3">
                                            <div class="form-check form-switch">
                                                <input class="form-check-input" type="checkbox" id="passwordComplexity"
                                                    checked>
                                                <label class="form-check-label" for="passwordComplexity">Require Complex
                                                    Passwords</label>
                                            </div>
                                        </div>
                                        <div class="mb-3">
                                            <div class="form-check form-switch">
                                                <input class="form-check-input" type="checkbox" id="sessionTimeout"
                                                    checked>
                                                <label class="form-check-label" for="sessionTimeout">Enable Session
                                                    Timeout (30 min)</label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-12">
                                        <button type="submit" class="btn btn-primary">
                                            <i class="bi bi-save"></i> Save Settings
                                        </button>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </div>
                </section>

                <!-- Reports Section -->
                <section id="reports" class="section" style="<?= $section === 'reports' ? '' : 'display: none;' ?>">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2 class="mb-0">Reports</h2>
                    </div>

                    <div class="card">
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h5 class="mb-3">User Activity Report</h5>
                                    <div class="mb-3">
                                        <label for="userActivityDateRange" class="form-label">Date Range</label>
                                        <select class="form-select" id="userActivityDateRange">
                                            <option value="today">Today</option>
                                            <option value="week">This Week</option>
                                            <option value="month" selected>This Month</option>
                                            <option value="year">This Year</option>
                                            <option value="custom">Custom Range</option>
                                        </select>
                                    </div>
                                    <button class="btn btn-primary" id="generateUserActivityReport">
                                        <i class="bi bi-file-earmark-bar-graph"></i> Generate Report
                                    </button>
                                </div>
                                <div class="col-md-6">
                                    <h5 class="mb-3">Institute Usage Report</h5>
                                    <div class="mb-3">
                                        <label for="instituteReportSelect" class="form-label">Institute</label>
                                        <select class="form-select" id="instituteReportSelect">
                                            <option value="all">All Institutes</option>
                                            <?php foreach ($institutes as $institute): ?>
                                                <option value="<?= $institute['id'] ?>">
                                                    <?= htmlspecialchars($institute['name']) ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <button class="btn btn-primary" id="generateInstituteReport">
                                        <i class="bi bi-building-gear"></i> Generate Report
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="card mt-4">
                        <div class="card-body">
                            <div id="reportResultsContainer">
                                <div class="text-center py-5 text-muted">
                                    <i class="bi bi-graph-up fs-1"></i>
                                    <p>Generate a report to view data</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Add User Modal -->
                <div class="modal fade" id="addUserModal" tabindex="-1" aria-labelledby="addUserModalLabel"
                    aria-hidden="true">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="addUserModalLabel">Add New User</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"
                                    aria-label="Close"></button>
                            </div>
                            <form id="addUserForm" method="POST">
                                <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                                <input type="hidden" name="form_type" value="add_user">
                                <div class="modal-body">
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="username" class="form-label required-field">Username</label>
                                            <input type="text" class="form-control" id="username" name="username"
                                                required>
                                            <div class="error-message" id="usernameError"></div>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="name" class="form-label required-field">Full Name</label>
                                            <input type="text" class="form-control" id="name" name="name" required>
                                            <div class="error-message" id="nameError"></div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="email" class="form-label required-field">Email</label>
                                            <input type="email" class="form-control" id="email" name="email" required>
                                            <div class="error-message" id="emailError"></div>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="phone" class="form-label required-field">Phone</label>
                                            <input type="tel" class="form-control" id="phone" name="phone" required>
                                            <div class="error-message" id="phoneError"></div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="password" class="form-label required-field">Password</label>
                                            <input type="password" class="form-control" id="password" name="password"
                                                required>
                                            <div class="error-message" id="passwordError"></div>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="confirmPassword" class="form-label required-field">Confirm
                                                Password</label>
                                            <input type="password" class="form-control" id="confirmPassword"
                                                name="confirmPassword" required>
                                            <div class="error-message" id="confirmPasswordError"></div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="role" class="form-label required-field">Role</label>
                                            <select class="form-select" id="role" name="role" required>
                                                <option value="">Select Role</option>
                                                <option value="admin">Administrator</option>
                                                <option value="office">Office Incharge</option>
                                                <option value="student">Student</option>
                                                <option value="teacher">Teacher</option>
                                            </select>
                                            <div class="error-message" id="roleError"></div>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="institute_name" class="form-label">Institute</label>
                                            <select class="form-select" id="institute_name" name="institute_name">
                                                <option value="">Select Institute</option>
                                                <?php foreach ($institutes as $institute): ?>
                                                    <option value="<?= htmlspecialchars($institute['name']) ?>">
                                                        <?= htmlspecialchars($institute['name']) ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="status" class="form-label">Status</label>
                                            <select class="form-select" id="status" name="status">
                                                <option value="active" selected>Active</option>
                                                <option value="inactive">Inactive</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary"
                                        data-bs-dismiss="modal">Close</button>
                                    <button type="submit" class="btn btn-primary">Save User</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- Edit User Modal -->
                <div class="modal fade" id="editUserModal" tabindex="-1" aria-labelledby="editUserModalLabel"
                    aria-hidden="true">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="editUserModalLabel">Edit User</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"
                                    aria-label="Close"></button>
                            </div>
                            <form id="editUserForm" method="POST">
                                <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                                <input type="hidden" name="form_type" value="edit_user">
                                <input type="hidden" id="edit_user_id" name="user_id">
                                <div class="modal-body">
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="edit_username"
                                                class="form-label required-field">Username</label>
                                            <input type="text" class="form-control" id="edit_username" name="username"
                                                required>
                                            <div class="error-message" id="editUsernameError"></div>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="edit_name" class="form-label required-field">Full Name</label>
                                            <input type="text" class="form-control" id="edit_name" name="name" required>
                                            <div class="error-message" id="editNameError"></div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="edit_email" class="form-label required-field">Email</label>
                                            <input type="email" class="form-control" id="edit_email" name="email"
                                                required>
                                            <div class="error-message" id="editEmailError"></div>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="edit_phone" class="form-label required-field">Phone</label>
                                            <input type="tel" class="form-control" id="edit_phone" name="phone"
                                                required>
                                            <div class="error-message" id="editPhoneError"></div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="edit_role" class="form-label required-field">Role</label>
                                            <select class="form-select" id="edit_role" name="role" required>
                                                <option value="">Select Role</option>
                                                <option value="admin">Administrator</option>
                                                <option value="office">Office Incharge</option>
                                                <option value="teacher">Teacher</option>
                                            </select>
                                            <div class="error-message" id="editRoleError"></div>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="edit_institute_name" class="form-label">Institute</label>
                                            <select class="form-select" id="edit_institute_name" name="institute_name">
                                                <option value="">Select Institute</option>
                                                <?php foreach ($institutes as $institute): ?>
                                                    <option value="<?= htmlspecialchars($institute['name']) ?>">
                                                        <?= htmlspecialchars($institute['name']) ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="edit_status" class="form-label">Status</label>
                                            <select class="form-select" id="edit_status" name="status">
                                                <option value="active">Active</option>
                                                <option value="inactive">Inactive</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary"
                                        data-bs-dismiss="modal">Close</button>
                                    <button type="submit" class="btn btn-primary">Update User</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- Add Institute Modal -->
                <div class="modal fade" id="addInstituteModal" tabindex="-1" aria-labelledby="addInstituteModalLabel"
                    aria-hidden="true">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="addInstituteModalLabel">Add New Institute</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"
                                    aria-label="Close"></button>
                            </div>
                            <form id="addInstituteForm" method="POST">
                                <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                                <input type="hidden" name="form_type" value="add_institute">
                                <div class="modal-body">
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="institute_name" class="form-label required-field">Institute
                                                Name</label>
                                            <input type="text" class="form-control" id="institute_name" name="name"
                                                required>
                                            <div class="error-message" id="instituteNameError"></div>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="institute_phone" class="form-label required-field">Phone</label>
                                            <input type="tel" class="form-control" id="institute_phone" name="phone"
                                                required>
                                            <div class="error-message" id="institutePhoneError"></div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="institute_email" class="form-label">Email</label>
                                            <input type="email" class="form-control" id="institute_email" name="email">
                                            <div class="error-message" id="instituteEmailError"></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="office_incharge_name" class="form-label">Office Incharge
                                            Name</label>
                                        <input type="text" class="form-control" id="office_incharge_name"
                                            name="office_incharge_name">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="office_incharge_contact" class="form-label">Office Incharge
                                            Contact</label>
                                        <input type="tel" class="form-control" id="office_incharge_contact"
                                            name="office_incharge_contact">
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-12 mb-3">
                                        <label for="institute_address" class="form-label required-field">Address</label>
                                        <textarea class="form-control" id="institute_address" name="address" rows="3"
                                            required></textarea>
                                        <div class="error-message" id="instituteAddressError"></div>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="institute_status" class="form-label">Status</label>
                                        <select class="form-select" id="institute_status" name="status">
                                            <option value="active" selected>Active</option>
                                            <option value="inactive">Inactive</option>
                                        </select>
                                    </div>
                                </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            <button type="submit" class="btn btn-primary">Save Institute</button>
                        </div>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Edit Institute Modal -->
            <div class="modal fade" id="editInstituteModal" tabindex="-1" aria-labelledby="editInstituteModalLabel"
                aria-hidden="true">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="editInstituteModalLabel">Edit Institute</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <form id="editInstituteForm" method="POST">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                            <input type="hidden" name="form_type" value="edit_institute">
                            <input type="hidden" id="edit_institute_id" name="institute_id">
                            <div class="modal-body">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="edit_institute_name" class="form-label required-field">Institute
                                            Name</label>
                                        <input type="text" class="form-control" id="edit_institute_name" name="name"
                                            required>
                                        <div class="error-message" id="editInstituteNameError"></div>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="edit_institute_phone"
                                            class="form-label required-field">Phone</label>
                                        <input type="tel" class="form-control" id="edit_institute_phone" name="phone"
                                            required>
                                        <div class="error-message" id="editInstitutePhoneError"></div>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="edit_institute_email" class="form-label">Email</label>
                                        <input type="email" class="form-control" id="edit_institute_email" name="email">
                                        <div class="error-message" id="editInstituteEmailError"></div>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="edit_office_incharge_name" class="form-label">Office Incharge
                                            Name</label>
                                        <input type="text" class="form-control" id="edit_office_incharge_name"
                                            name="office_incharge_name">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="edit_office_incharge_contact" class="form-label">Office Incharge
                                            Contact</label>
                                        <input type="tel" class="form-control" id="edit_office_incharge_contact"
                                            name="office_incharge_contact">
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-12 mb-3">
                                        <label for="edit_institute_address"
                                            class="form-label required-field">Address</label>
                                        <textarea class="form-control" id="edit_institute_address" name="address"
                                            rows="3" required></textarea>
                                        <div class="error-message" id="editInstituteAddressError"></div>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="edit_institute_status" class="form-label">Status</label>
                                        <select class="form-select" id="edit_institute_status" name="status">
                                            <option value="active">Active</option>
                                            <option value="inactive">Inactive</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                <button type="submit" class="btn btn-primary">Update Institute</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <!-- JavaScript Libraries -->
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
            <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
            <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

            <script>
                // ======================
                // DOM Ready Initialization
                // ======================
                $(document).ready(function() {
                    // Initialize DataTables for all tables
                    $('#usersTable, #institutesTable ,#studentsTable, #allFeesTable, #pendingFeesTable, #batchesTable').DataTable({
                        responsive: true,
                        language: {
                            search: "_INPUT_",
                            searchPlaceholder: "Search...",
                        },
                        dom: '<"top"f>rt<"bottom"lip><"clear">',
                        pageLength: 25,
                        initComplete: function() {
                            // Apply theme-specific styling after table initialization
                            this.api().columns().every(function() {
                                const column = this;
                                $('input', this.header()).on('keyup change', function() {
                                    if (column.search() !== this.value) {
                                        column.search(this.value).draw();
                                    }
                                });
                            });
                        }
                    });

                    // Initialize tooltips
                    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
                    tooltipTriggerList.map(function(tooltipTriggerEl) {
                        return new bootstrap.Tooltip(tooltipTriggerEl);
                    });

                    // Initialize dark mode from localStorage
                    initDarkMode();

                    // Initialize form validation
                    initFormValidation();
                });

                // ======================
                // Section Navigation
                // ======================
                function showSection(sectionId) {
                    // Update URL without reloading
                    const url = new URL(window.location.href);
                    url.searchParams.set('section', sectionId);
                    window.history.pushState({}, '', url);

                    // Hide all sections
                    document.querySelectorAll('.section').forEach(section => {
                        section.style.display = 'none';
                    });

                    // Update active link in sidebar
                    document.querySelectorAll('.sidebar a').forEach(link => {
                        link.classList.remove('active');
                    });

                    // Find and activate corresponding link
                    const links = document.querySelectorAll('.sidebar a');
                    links.forEach(link => {
                        if (link.getAttribute('onclick')?.includes(sectionId)) {
                            link.classList.add('active');
                        }
                    });

                    // Show the selected section
                    const sectionToShow = document.getElementById(sectionId);
                    if (sectionToShow) {
                        sectionToShow.style.display = 'block';

                        // Check if table exists and is a DataTable before trying to recalc
                        const table = sectionToShow.querySelector('table');
                        if (table && $.fn.DataTable.isDataTable(table)) {
                            try {
                                $(table).DataTable().columns.adjust().responsive.recalc();
                            } catch (e) {
                                console.error('DataTable recalculation error:', e);
                            }
                        }
                    }

                    // Scroll to top
                    window.scrollTo({
                        top: 0,
                        behavior: 'smooth'
                    });
                }

                // ======================
                // Form Handling
                // ======================
                function initFormValidation() {
                    // Add User Form Validation
                    document.getElementById('addUserForm')?.addEventListener('submit', function(e) {
                        if (!validateAddUserForm()) {
                            e.preventDefault();
                        }
                    });

                    // Edit User Form Validation
                    document.getElementById('editUserForm')?.addEventListener('submit', function(e) {
                        if (!validateEditUserForm()) {
                            e.preventDefault();
                        }
                    });

                    // Add Institute Form Validation
                    document.getElementById('addInstituteForm')?.addEventListener('submit', function(e) {
                        if (!validateAddInstituteForm()) {
                            e.preventDefault();
                        }
                    });

                    // Edit Institute Form Validation
                    document.getElementById('editInstituteForm')?.addEventListener('submit', function(e) {
                        if (!validateEditInstituteForm()) {
                            e.preventDefault();
                        }
                    });
                }

                function validateAddUserForm() {
                    let isValid = true;
                    const form = document.getElementById('addUserForm');

                    // Clear previous errors
                    form.querySelectorAll('.error-message').forEach(el => el.textContent = '');

                    // Validate username
                    const username = form.querySelector('#username');
                    if (!username.value.trim()) {
                        form.querySelector('#usernameError').textContent = 'Username is required';
                        isValid = false;
                    }

                    // Validate name
                    const name = form.querySelector('#name');
                    if (!name.value.trim()) {
                        form.querySelector('#nameError').textContent = 'Full name is required';
                        isValid = false;
                    }

                    // Validate email
                    const email = form.querySelector('#email');
                    if (!email.value.trim()) {
                        form.querySelector('#emailError').textContent = 'Email is required';
                        isValid = false;
                    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
                        form.querySelector('#emailError').textContent = 'Valid email is required';
                        isValid = false;
                    }

                    // Validate phone
                    const phone = form.querySelector('#phone');
                    if (!phone.value.trim()) {
                        form.querySelector('#phoneError').textContent = 'Phone is required';
                        isValid = false;
                    } else if (!/^\d{10}$/.test(phone.value)) {
                        form.querySelector('#phoneError').textContent = 'Valid phone number is required';
                        isValid = false;
                    }

                    // Validate password
                    const password = form.querySelector('#password');
                    if (!password.value.trim()) {
                        form.querySelector('#passwordError').textContent = 'Password is required';
                        isValid = false;
                    } else if (password.value.length < 8) {
                        form.querySelector('#passwordError').textContent = 'Password must be at least 8 characters';
                        isValid = false;
                    }

                    // Validate confirm password
                    const confirmPassword = form.querySelector('#confirmPassword');
                    if (!confirmPassword.value.trim()) {
                        form.querySelector('#confirmPasswordError').textContent = 'Please confirm password';
                        isValid = false;
                    } else if (confirmPassword.value !== password.value) {
                        form.querySelector('#confirmPasswordError').textContent = 'Passwords do not match';
                        isValid = false;
                    }

                    // Validate role
                    const role = form.querySelector('#role');
                    if (!role.value) {
                        form.querySelector('#roleError').textContent = 'Role is required';
                        isValid = false;
                    }

                    if (!isValid) {
                        showToast('Please fill all required fields correctly', 'warning');
                        scrollToFirstInvalid(form);
                    }

                    return isValid;
                }

                function validateEditUserForm() {
                    let isValid = true;
                    const form = document.getElementById('editUserForm');

                    // Clear previous errors
                    form.querySelectorAll('.error-message').forEach(el => el.textContent = '');

                    // Validate username
                    const username = form.querySelector('#edit_username');
                    if (!username.value.trim()) {
                        form.querySelector('#editUsernameError').textContent = 'Username is required';
                        isValid = false;
                    }

                    // Validate name
                    const name = form.querySelector('#edit_name');
                    if (!name.value.trim()) {
                        form.querySelector('#editNameError').textContent = 'Full name is required';
                        isValid = false;
                    }

                    // Validate email
                    const email = form.querySelector('#edit_email');
                    if (!email.value.trim()) {
                        form.querySelector('#editEmailError').textContent = 'Email is required';
                        isValid = false;
                    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
                        form.querySelector('#editEmailError').textContent = 'Valid email is required';
                        isValid = false;
                    }

                    // Validate phone
                    const phone = form.querySelector('#edit_phone');
                    if (!phone.value.trim()) {
                        form.querySelector('#editPhoneError').textContent = 'Phone is required';
                        isValid = false;
                    } else if (!/^\d{10}$/.test(phone.value)) {
                        form.querySelector('#editPhoneError').textContent = 'Valid phone number is required';
                        isValid = false;
                    }

                    // Validate role
                    const role = form.querySelector('#edit_role');
                    if (!role.value) {
                        form.querySelector('#editRoleError').textContent = 'Role is required';
                        isValid = false;
                    }

                    if (!isValid) {
                        showToast('Please fill all required fields correctly', 'warning');
                        scrollToFirstInvalid(form);
                    }

                    return isValid;
                }

                function validateAddInstituteForm() {
                    let isValid = true;
                    const form = document.getElementById('addInstituteForm');

                    // Clear previous errors
                    form.querySelectorAll('.error-message').forEach(el => el.textContent = '');

                    // Validate name
                    const name = form.querySelector('#institute_name');
                    if (!name.value.trim()) {
                        form.querySelector('#instituteNameError').textContent = 'Institute name is required';
                        isValid = false;
                    }

                    // Validate phone
                    const phone = form.querySelector('#institute_phone');
                    if (!phone.value.trim()) {
                        form.querySelector('#institutePhoneError').textContent = 'Phone is required';
                        isValid = false;
                    } else if (!/^\d{10}$/.test(phone.value)) {
                        form.querySelector('#institutePhoneError').textContent = 'Valid phone number is required';
                        isValid = false;
                    }

                    // Validate email if provided
                    const email = form.querySelector('#institute_email');
                    if (email.value.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
                        form.querySelector('#instituteEmailError').textContent = 'Valid email is required';
                        isValid = false;
                    }

                    // Validate website if provided
                    const website = form.querySelector('#institute_website');
                    if (website.value.trim() && !/^https?:\/\/.+\..+/.test(website.value)) {
                        form.querySelector('#instituteWebsiteError').textContent = 'Valid website URL is required';
                        isValid = false;
                    }

                    // Validate address
                    const address = form.querySelector('#institute_address');
                    if (!address.value.trim()) {
                        form.querySelector('#instituteAddressError').textContent = 'Address is required';
                        isValid = false;
                    }

                    if (!isValid) {
                        showToast('Please fill all required fields correctly', 'warning');
                        scrollToFirstInvalid(form);
                    }

                    return isValid;
                }

                function validateEditInstituteForm() {
                    let isValid = true;
                    const form = document.getElementById('editInstituteForm');

                    // Clear previous errors
                    form.querySelectorAll('.error-message').forEach(el => el.textContent = '');

                    // Validate name
                    const name = form.querySelector('#edit_institute_name');
                    if (!name.value.trim()) {
                        form.querySelector('#editInstituteNameError').textContent = 'Institute name is required';
                        isValid = false;
                    }

                    // Validate phone
                    const phone = form.querySelector('#edit_institute_phone');
                    if (!phone.value.trim()) {
                        form.querySelector('#editInstitutePhoneError').textContent = 'Phone is required';
                        isValid = false;
                    } else if (!/^\d{10}$/.test(phone.value)) {
                        form.querySelector('#editInstitutePhoneError').textContent = 'Valid phone number is required';
                        isValid = false;
                    }

                    // Validate email if provided
                    const email = form.querySelector('#edit_institute_email');
                    if (email.value.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
                        form.querySelector('#editInstituteEmailError').textContent = 'Valid email is required';
                        isValid = false;
                    }

                    // Validate website if provided
                    const website = form.querySelector('#edit_institute_website');
                    if (website.value.trim() && !/^https?:\/\/.+\..+/.test(website.value)) {
                        form.querySelector('#editInstituteWebsiteError').textContent = 'Valid website URL is required';
                        isValid = false;
                    }

                    // Validate address
                    const address = form.querySelector('#edit_institute_address');
                    if (!address.value.trim()) {
                        form.querySelector('#editInstituteAddressError').textContent = 'Address is required';
                        isValid = false;
                    }

                    if (!isValid) {
                        showToast('Please fill all required fields correctly', 'warning');
                        scrollToFirstInvalid(form);
                    }

                    return isValid;
                }

                function scrollToFirstInvalid(form) {
                    const firstInvalid = form.querySelector('.error-message:not(:empty)');
                    if (firstInvalid) {
                        const input = firstInvalid.previousElementSibling;
                        input.scrollIntoView({
                            behavior: 'smooth',
                            block: 'center'
                        });
                        input.focus();
                    }
                }
                // ======================
                // Batch Management Functions
                // ======================
                function confirmDeleteBatch(batchId) {
                    Swal.fire({
                        title: 'Are you sure?',
                        text: "You won't be able to revert this! All students in this batch will be removed.",
                        icon: 'warning',
                        showCancelButton: true,
                        confirmButtonColor: '#d33',
                        cancelButtonColor: '#3085d6',
                        confirmButtonText: 'Yes, delete it!'
                    }).then((result) => {
                        if (result.isConfirmed) {
                            // Create form data with CSRF token
                            const formData = new FormData();
                            formData.append('form_type', 'delete_batch');
                            formData.append('batch_id', batchId);
                            formData.append('csrf_token', '<?= $csrf_token ?>');

                            fetch('admin.php', {
                                    method: 'POST',
                                    body: formData
                                })
                                .then(response => {
                                    if (!response.ok) throw new Error('Network response was not ok');
                                    return response.text();
                                })
                                .then(() => {
                                    showToast('Batch deleted successfully', 'success');
                                    setTimeout(() => location.reload(), 1500);
                                })
                                .catch(error => {
                                    console.error('Error:', error);
                                    showToast('Error deleting batch', 'danger');
                                });
                        }
                    });
                }

                function addStudentToBatch(batchId) {
                    const studentSelect = document.getElementById(`studentSelect_${batchId}`);
                    const studentId = studentSelect.value;

                    if (!studentId) {
                        showToast('Please select a student', 'warning');
                        return;
                    }

                    // Create form data with CSRF token
                    const formData = new FormData();
                    formData.append('form_type', 'add_student_to_batch');
                    formData.append('batch_id', batchId);
                    formData.append('student_id', studentId);
                    formData.append('csrf_token', '<?= $csrf_token ?>');

                    fetch('admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(response => {
                            if (!response.ok) throw new Error('Network response was not ok');
                            return response.json();
                        })
                        .then(data => {
                            if (data.status) {
                                showToast(data.message, 'success');
                                setTimeout(() => location.reload(), 1500);
                            } else {
                                showToast(data.message, 'danger');
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            showToast('Network error', 'danger');
                        });
                }

                function removeStudentFromBatch(batchId, studentId) {
                    Swal.fire({
                        title: 'Are you sure?',
                        text: "This student will be removed from the batch.",
                        icon: 'warning',
                        showCancelButton: true,
                        confirmButtonColor: '#d33',
                        cancelButtonColor: '#3085d6',
                        confirmButtonText: 'Yes, remove!'
                    }).then((result) => {
                        if (result.isConfirmed) {
                            // Create form data with CSRF token
                            const formData = new FormData();
                            formData.append('form_type', 'remove_student_from_batch');
                            formData.append('batch_id', batchId);
                            formData.append('student_id', studentId);
                            formData.append('csrf_token', '<?= $csrf_token ?>');

                            fetch('admin.php', {
                                    method: 'POST',
                                    body: formData
                                })
                                .then(response => {
                                    if (!response.ok) throw new Error('Network response was not ok');
                                    return response.text();
                                })
                                .then(() => {
                                    showToast('Student removed from batch', 'success');
                                    setTimeout(() => location.reload(), 1500);
                                })
                                .catch(error => {
                                    console.error('Error:', error);
                                    showToast('Error removing student', 'danger');
                                });
                        }
                    });
                }

                function toggleBatchStudentStatus(batchId, studentId, currentStatus) {
                    // Create form data with CSRF token
                    const formData = new FormData();
                    formData.append('form_type', 'toggle_batch_student_status');
                    formData.append('batch_id', batchId);
                    formData.append('student_id', studentId);
                    formData.append('current_status', currentStatus);
                    formData.append('csrf_token', '<?= $csrf_token ?>');

                    fetch('admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(response => {
                            if (!response.ok) throw new Error('Network response was not ok');
                            return response.text();
                        })
                        .then(() => {
                            showToast('Student status updated', 'success');
                            setTimeout(() => location.reload(), 1500);
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            showToast('Error updating status', 'danger');
                        });
                }
                // ======================
                // Fee Management
                // ======================
                function markAsPaid(feeId) {
                    if (confirm('Are you sure you want to mark this fee as paid?')) {
                        fetch('admin.php', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                },
                                body: `form_type=update_fee_status&fee_id=${feeId}&status=paid&csrf_token=<?= $csrf_token ?>`
                            })
                            .then(response => response.json())
                            .then(data => {
                                if (data.success) {
                                    showToast('Fee marked as paid successfully', 'success');
                                    setTimeout(() => location.reload(), 1500);
                                } else {
                                    showToast(data.message || 'Error updating fee status', 'danger');
                                }
                            })
                            .catch(error => {
                                console.error('Error:', error);
                                showToast('Network error', 'danger');
                            });
                    }
                }

                function sendReminder(feeId) {
                    fetch('admin.php', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                            },
                            body: `form_type=send_reminder&fee_id=${feeId}&csrf_token=<?= $csrf_token ?>`
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                showToast('Reminder sent successfully', 'success');
                            } else {
                                showToast(data.message || 'Error sending reminder', 'danger');
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            showToast('Network error', 'danger');
                        });
                }
                // ======================
                // User Management Functions
                // ======================
                function editUser(userId) {
                    fetch(`get_user.php?id=${userId}`)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                const user = data.user;
                                const modal = new bootstrap.Modal(document.getElementById('editUserModal'));

                                // Populate form fields
                                document.getElementById('edit_user_id').value = user.id;
                                document.getElementById('edit_username').value = user.username;
                                document.getElementById('edit_name').value = user.name;
                                document.getElementById('edit_email').value = user.email;
                                document.getElementById('edit_phone').value = user.phone;
                                document.getElementById('edit_role').value = user.role;
                                document.getElementById('edit_institute_name').value = user.institute_name || '';
                                document.getElementById('edit_status').value = user.status;

                                // Show modal
                                modal.show();
                            } else {
                                showToast(data.message || 'Error loading user data', 'danger');
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            showToast('Network error loading user data', 'danger');
                        });
                }

                function confirmDeleteUser(userId) {
                    Swal.fire({
                        title: 'Are you sure?',
                        text: "You won't be able to revert this!",
                        icon: 'warning',
                        showCancelButton: true,
                        confirmButtonColor: '#d33',
                        cancelButtonColor: '#3085d6',
                        confirmButtonText: 'Yes, delete it!'
                    }).then((result) => {
                        if (result.isConfirmed) {
                            // Create form data with CSRF token
                            const formData = new FormData();
                            formData.append('form_type', 'delete_user');
                            formData.append('user_id', userId);
                            formData.append('csrf_token', '<?= $csrf_token ?>');

                            fetch('admin.php', {
                                    method: 'POST',
                                    body: formData
                                })
                                .then(response => {
                                    if (!response.ok) throw new Error('Network response was not ok');
                                    return response.text();
                                })
                                .then(() => {
                                    showToast('User deleted successfully', 'success');
                                    setTimeout(() => location.reload(), 1500);
                                })
                                .catch(error => {
                                    console.error('Error:', error);
                                    showToast('Error deleting user', 'danger');
                                });
                        }
                    });
                }

                // User status toggle
                document.querySelectorAll('.user-status-toggle').forEach(toggle => {
                    toggle.addEventListener('change', function() {
                        const userId = this.dataset.userId;
                        const formData = new FormData();
                        formData.append('form_type', 'toggle_user_status');
                        formData.append('user_id', userId);
                        formData.append('csrf_token', '<?= $csrf_token ?>');

                        fetch('admin.php', {
                                method: 'POST',
                                body: formData
                            })
                            .then(response => response.json())
                            .then(data => {
                                if (data.status) {
                                    showToast(data.message || 'Status updated', 'success');
                                } else {
                                    showToast(data.message || 'Failed to update status', 'danger');
                                    // Revert the toggle if failed
                                    this.checked = !this.checked;
                                }
                            })
                            .catch(() => {
                                showToast('Network error', 'danger');
                                this.checked = !this.checked;
                            });
                    });
                });


                // ======================
                // Utility Functions
                // ======================
                function makeRequest(url, data, method = 'POST') {
                    return new Promise((resolve, reject) => {
                        const xhr = new XMLHttpRequest();
                        xhr.open(method, url);
                        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

                        xhr.onload = function() {
                            if (xhr.status >= 200 && xhr.status < 300) {
                                try {
                                    resolve(JSON.parse(xhr.responseText));
                                } catch (e) {
                                    resolve(xhr.responseText);
                                }
                            } else {
                                reject(xhr.statusText);
                            }
                        };

                        xhr.onerror = function() {
                            reject('Network error');
                        };

                        const formData = new URLSearchParams();
                        for (const key in data) {
                            formData.append(key, data[key]);
                        }

                        xhr.send(formData);
                    });
                }

                // =============================================
                // ATTENDANCE SYSTEM FUNCTIONALITY
                // =============================================

                // Global variables for attendance tracking
                let currentAttendanceDate = new Date();
                let currentAttendanceMonth = currentAttendanceDate.getMonth();
                let currentAttendanceYear = currentAttendanceDate.getFullYear();
                let attendanceMarkedDates = [];

                // Initialize attendance system
                function initAttendanceSystem() {
                    // Set today's date in report form
                    document.getElementById('reportDate').valueAsDate = new Date();

                    // Load batch options
                    loadBatchOptions();

                    // Load batch summary cards
                    loadBatchSummaryCards();

                    // Initialize calendar
                    generateAttendanceCalendar(currentAttendanceMonth, currentAttendanceYear);

                    // Set up event listeners
                    setupAttendanceEventListeners();
                }

                // Set up event listeners for attendance section
                function setupAttendanceEventListeners() {
                    // Calendar navigation
                    document.getElementById('prevMonth').addEventListener('click', function() {
                        currentAttendanceMonth--;
                        if (currentAttendanceMonth < 0) {
                            currentAttendanceMonth = 11;
                            currentAttendanceYear--;
                        }
                        generateAttendanceCalendar(currentAttendanceMonth, currentAttendanceYear);
                    });

                    document.getElementById('nextMonth').addEventListener('click', function() {
                        currentAttendanceMonth++;
                        if (currentAttendanceMonth > 11) {
                            currentAttendanceMonth = 0;
                            currentAttendanceYear++;
                        }
                        generateAttendanceCalendar(currentAttendanceMonth, currentAttendanceYear);
                    });

                    // Today button in modal
                    document.getElementById('todayBtn').addEventListener('click', function() {
                        const today = new Date().toISOString().split('T')[0];
                        document.getElementById('attendanceDate').value = today;

                        const batchId = document.getElementById('attendanceBatch').value;
                        if (batchId) {
                            loadAttendanceForm(batchId, today);
                        }
                    });

                    // Batch select change in modal
                    document.getElementById('attendanceBatch').addEventListener('change', function() {
                        const batchId = this.value;
                        const date = document.getElementById('attendanceDate').value;

                        if (batchId && date) {
                            loadAttendanceForm(batchId, date);
                        }
                    });

                    // Report form submission
                    document.getElementById('attendanceReportForm').addEventListener('submit', function(e) {
                        e.preventDefault();
                        const batchId = this.elements['batch_id'].value;
                        const date = this.elements['date'].value;

                        if (batchId && date) {
                            loadAttendanceReport(batchId, date);
                        }
                    });

                    // Refresh button
                    document.getElementById('refreshAttendance').addEventListener('click', function() {
                        loadBatchSummaryCards();
                        generateAttendanceCalendar(currentAttendanceMonth, currentAttendanceYear);

                        const batchSelect = document.querySelector('#attendanceReportForm select[name="batch_id"]');
                        const dateInput = document.querySelector('#attendanceReportForm input[name="date"]');

                        if (batchSelect.value && dateInput.value) {
                            loadAttendanceReport(batchSelect.value, dateInput.value);
                        }
                    });

                    // Mark all present toggle
                    document.getElementById('selectAllPresent').addEventListener('change', function() {
                        const checkboxes = document.querySelectorAll('#attendanceListContainer select.attendance-select');
                        checkboxes.forEach(select => {
                            select.value = this.checked ? 'present' : 'absent';
                        });
                    });
                }

                // Load batch options for selects
                function loadBatchOptions() {
                    fetch('?ajax=get_batch_options')
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                const batches = data.batches;

                                // Update modal select
                                const modalSelect = document.getElementById('attendanceBatch');
                                modalSelect.innerHTML = '<option value="">Select Batch</option>' +
                                    batches.map(b => `<option value="${b.batch_id}">${b.batch_name} (${b.batch_code})</option>`).join('');

                                // Update report select
                                const reportSelect = document.getElementById('reportBatchSelect');
                                reportSelect.innerHTML = '<option value="">Select Batch</option>' +
                                    batches.map(b => `<option value="${b.batch_id}">${b.batch_name} (${b.batch_code})</option>`).join('');
                            }
                        })
                        .catch(error => {
                            console.error('Error loading batch options:', error);
                        });
                }

                // Load batch summary cards
                function loadBatchSummaryCards() {
                    const container = document.getElementById('batchSummaryCards');
                    container.innerHTML = `
        <div class="col-12 text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;

                    fetch('?ajax=get_batch_summaries')
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                renderBatchSummaryCards(data.batches);
                            } else {
                                container.innerHTML = `
                    <div class="col-12">
                        <div class="alert alert-danger">${data.message || 'Error loading batch summaries'}</div>
                    </div>
                `;
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            container.innerHTML = `
                <div class="col-12">
                    <div class="alert alert-danger">Network error loading batch summaries</div>
                </div>
            `;
                        });
                }

                // Render batch summary cards
                function renderBatchSummaryCards(batches) {
                    const container = document.getElementById('batchSummaryCards');
                    container.innerHTML = '';

                    if (batches.length === 0) {
                        container.innerHTML = `
            <div class="col-12">
                <div class="alert alert-info">No active batches found</div>
            </div>
        `;
                        return;
                    }

                    batches.forEach(batch => {
                        const attendancePercentage = batch.total_students > 0 ?
                            Math.round((batch.attendance_today / batch.total_students) * 100) : 0;

                        container.innerHTML += `
            <div class="col-md-4 mb-3">
                <div class="card h-100 batch-summary-card" data-batch-id="${batch.batch_id}">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                            <h5 class="card-title mb-0">${batch.batch_name}</h5>
                            <span class="badge bg-${batch.status === 'Active' ? 'success' : 'secondary'}">
                                ${batch.status}
                            </span>
                        </div>
                        <p class="text-muted small mb-2">${batch.batch_code} • ${batch.course || 'No course'}</p>
                        
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <div>
                                <span class="fw-bold">${batch.attendance_today}/${batch.total_students}</span>
                                <span class="text-muted small">Present Today</span>
                            </div>
                            <div class="text-end">
                                <span class="fw-bold">${attendancePercentage}%</span>
                                <div class="progress" style="height: 5px; width: 60px;">
                                    <div class="progress-bar bg-${getAttendancePercentageColor(attendancePercentage)}" 
                                         style="width: ${attendancePercentage}%"></div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="d-flex justify-content-between">
                            <button class="btn btn-sm btn-outline-primary" 
                                    onclick="loadAttendanceReport(${batch.batch_id}, '${new Date().toISOString().split('T')[0]}')">
                                <i class="bi bi-eye"></i> View
                            </button>
                            <button class="btn btn-sm btn-primary" 
                                    data-bs-toggle="modal" 
                                    data-bs-target="#markAttendanceModal"
                                    onclick="setModalBatch(${batch.batch_id})">
                                <i class="bi bi-plus-circle"></i> Mark
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
                    });
                }

                // Set batch in modal when clicking from summary card
                function setModalBatch(batchId) {
                    const modalSelect = document.getElementById('attendanceBatch');
                    modalSelect.value = batchId;

                    // Trigger change event to load students
                    const event = new Event('change');
                    modalSelect.dispatchEvent(event);
                }

                // Get color based on attendance percentage
                function getAttendancePercentageColor(percentage) {
                    if (percentage >= 80) return 'success';
                    if (percentage >= 50) return 'warning';
                    return 'danger';
                }

                // Generate attendance calendar
                function generateAttendanceCalendar(month, year) {
                    const calendarContainer = document.getElementById('calendarContainer');
                    calendarContainer.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;

                    // Load marked dates first
                    fetch(`?ajax=get_marked_dates&month=${month + 1}&year=${year}`)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                attendanceMarkedDates = data.dates;
                                renderAttendanceCalendar(month, year);
                            } else {
                                calendarContainer.innerHTML = `
                    <div class="alert alert-danger">${data.message || 'Error loading calendar data'}</div>
                `;
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            calendarContainer.innerHTML = `
                <div class="alert alert-danger">Network error loading calendar</div>
            `;
                        });
                }

                // Render the attendance calendar
                function renderAttendanceCalendar(month, year) {
                    const calendarContainer = document.getElementById('calendarContainer');
                    const monthNames = ["January", "February", "March", "April", "May", "June",
                        "July", "August", "September", "October", "November", "December"
                    ];

                    // Create calendar grid
                    let calendarHTML = `
        <div class="calendar-header mb-3">
            <h5 class="text-center mb-0">${monthNames[month]} ${year}</h5>
        </div>
        <div class="calendar-grid">
    `;

                    // Add day headers
                    const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                    dayNames.forEach(day => {
                        calendarHTML += `<div class="calendar-day-header">${day}</div>`;
                    });

                    // Get first day of month and total days
                    const firstDay = new Date(year, month, 1).getDay();
                    const daysInMonth = new Date(year, month + 1, 0).getDate();
                    const today = new Date();
                    const isCurrentMonth = month === today.getMonth() && year === today.getFullYear();

                    // Add empty cells for days before the first day
                    for (let i = 0; i < firstDay; i++) {
                        calendarHTML += `<div class="calendar-day empty"></div>`;
                    }

                    // Add day cells
                    for (let day = 1; day <= daysInMonth; day++) {
                        const date = new Date(year, month, day);
                        const dateString = date.toISOString().split('T')[0];
                        const isToday = isCurrentMonth && day === today.getDate();
                        const hasAttendance = attendanceMarkedDates.includes(dateString);

                        calendarHTML += `
            <div class="calendar-day 
                ${isToday ? 'today' : ''} 
                ${hasAttendance ? 'has-attendance' : ''}"
                data-date="${dateString}">
                ${day}
                ${hasAttendance ? '<span class="attendance-dot"></span>' : ''}
            </div>
        `;
                    }

                    calendarHTML += `</div>`;
                    calendarContainer.innerHTML = calendarHTML;

                    // Add click event to calendar days
                    document.querySelectorAll('.calendar-day:not(.empty)').forEach(day => {
                        day.addEventListener('click', function() {
                            const date = this.dataset.date;
                            document.getElementById('reportDate').value = date;

                            const batchSelect = document.querySelector('#attendanceReportForm select[name="batch_id"]');
                            if (batchSelect.value) {
                                loadAttendanceReport(batchSelect.value, date);
                            }
                        });
                    });
                }

                // Load attendance form when batch is selected in modal
                function loadAttendanceForm(batchId, date) {
                    const container = document.getElementById('attendanceListContainer');
                    container.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2">Loading student list...</p>
        </div>
    `;

                    fetch(`?ajax=get_attendance_form&batch_id=${batchId}&date=${date}`)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                renderAttendanceForm(data.data);
                            } else {
                                container.innerHTML = `
                    <div class="alert alert-danger">
                        ${data.message || 'Error loading attendance form'}
                    </div>
                `;
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            container.innerHTML = `
                <div class="alert alert-danger">
                    Network error loading attendance form
                </div>
            `;
                        });
                }

                // Render attendance form
                function renderAttendanceForm(data) {
                    const container = document.getElementById('attendanceListContainer');
                    const batch = data.batch;

                    let html = `
        <div class="mb-3">
            <h5>${batch.batch_name} (${batch.batch_code})</h5>
            <p class="text-muted mb-2">${batch.course || 'No course specified'}</p>
            <p class="mb-0"><strong>Date:</strong> ${formatDateForDisplay(document.getElementById('attendanceDate').value)}</p>
        </div>
    `;

                    Object.entries(data.attendance).forEach(([studentId, student]) => {
                        html += `
            <div class="student-attendance-item">
                <div class="student-avatar">
                    <img src="${student.photo || 'assets/images/default-profile.jpg'}" 
                         alt="${student.name}" 
                         class="student-photo"
                         onerror="this.src='assets/images/default-profile.jpg'">
                </div>
                <div class="student-info">
                    <div class="student-name">${student.name}</div>
                    <div class="student-id small text-muted">ID: ${studentId}</div>
                </div>
                <div class="attendance-actions">
                    <select name="attendance[${studentId}][status]" 
                            class="form-select form-select-sm attendance-select" required>
                        <option value="present" ${student.status === 'present' ? 'selected' : ''}>Present</option>
                        <option value="absent" ${student.status === 'absent' ? 'selected' : ''}>Absent</option>
                        <option value="late" ${student.status === 'late' ? 'selected' : ''}>Late</option>
                        <option value="half_day" ${student.status === 'half_day' ? 'selected' : ''}>Half Day</option>
                    </select>
                    <input type="text" name="attendance[${studentId}][notes]" 
                           class="form-control form-control-sm attendance-notes" 
                           placeholder="Notes"
                           value="${student.notes || ''}">
                </div>
            </div>
        `;
                    });

                    container.innerHTML = html;
                }

                // Load attendance report
                function loadAttendanceReport(batchId, date) {
                    const container = document.getElementById('attendanceReportContainer');
                    container.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2">Loading attendance report...</p>
        </div>
    `;

                    fetch(`?ajax=get_attendance_report&batch_id=${batchId}&date=${date}`)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                renderAttendanceReport(data.data, date);
                            } else {
                                container.innerHTML = `
                    <div class="alert alert-danger">
                        ${data.message || 'Error loading attendance report'}
                    </div>
                `;
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            container.innerHTML = `
                <div class="alert alert-danger">
                    Network error loading attendance report
                </div>
            `;
                        });
                }

                // Render attendance report
                function renderAttendanceReport(data, date) {
                    const container = document.getElementById('attendanceReportContainer');
                    const template = document.getElementById('attendanceReportTemplate').innerHTML;

                    container.innerHTML = template;

                    // Update report header
                    document.getElementById('reportBatchName').textContent =
                        `${data.batch.batch_name} (${data.batch.batch_code})`;
                    document.getElementById('reportDateDisplay').textContent =
                        formatDateForDisplay(date);

                    // Count attendance statuses
                    let presentCount = 0;
                    let absentCount = 0;
                    let lateCount = 0;
                    let halfDayCount = 0;

                    const reportBody = document.getElementById('attendanceReportBody');

                    data.attendance.forEach(record => {
                        let statusBadge = '';
                        let statusClass = '';
                        let statusIcon = '';

                        switch (record.status) {
                            case 'present':
                                statusBadge = 'Present';
                                statusClass = 'success';
                                statusIcon = 'bi-check-circle';
                                presentCount++;
                                break;
                            case 'absent':
                                statusBadge = 'Absent';
                                statusClass = 'danger';
                                statusIcon = 'bi-x-circle';
                                absentCount++;
                                break;
                            case 'late':
                                statusBadge = 'Late';
                                statusClass = 'warning';
                                statusIcon = 'bi-clock-history';
                                lateCount++;
                                break;
                            case 'half_day':
                                statusBadge = 'Half Day';
                                statusClass = 'info';
                                statusIcon = 'bi-hourglass-split';
                                halfDayCount++;
                                break;
                        }

                        reportBody.innerHTML += `
            <tr>
                <td>
                    <div class="d-flex align-items-center">
                        <img src="${record.photo_path || 'assets/images/default-profile.jpg'}" 
                             class="rounded-circle me-2" width="32" height="32"
                             onerror="this.src='assets/images/default-profile.jpg'">
                        <div>
                            <div>${record.first_name} ${record.last_name}</div>
                            <small class="text-muted">${record.student_id}</small>
                        </div>
                    </div>
                </td>
                <td>
                    <span class="badge bg-${statusClass}">
                        <i class="bi ${statusIcon} me-1"></i> ${statusBadge}
                    </span>
                </td>
                <td>${record.notes || '-'}</td>
                <td>${record.recorded_time || '-'}</td>
            </tr>
        `;
                    });

                    // Update counts
                    document.getElementById('presentCount').textContent = presentCount;
                    document.getElementById('absentCount').textContent = absentCount;
                    document.getElementById('lateCount').textContent = lateCount;
                    document.getElementById('halfDayCount').textContent = halfDayCount;

                    // Show students without attendance
                    const missingList = document.getElementById('missingAttendanceList');
                    if (data.missing_attendance.length > 0) {
                        let html = '<div class="list-group">';
                        data.missing_attendance.forEach(student => {
                            html += `
                <div class="list-group-item">
                    <div class="d-flex align-items-center">
                        <img src="${student.photo_path || 'assets/images/default-profile.jpg'}" 
                             class="rounded-circle me-2" width="32" height="32"
                             onerror="this.src='assets/images/default-profile.jpg'">
                        <div>
                            <div>${student.first_name} ${student.last_name}</div>
                            <small class="text-muted">${student.student_id}</small>
                        </div>
                        <span class="badge bg-secondary ms-auto">No record</span>
                    </div>
                </div>
            `;
                        });
                        html += '</div>';
                        missingList.innerHTML = html;
                    } else {
                        missingList.innerHTML = `
            <div class="alert alert-success">
                <i class="bi bi-check-circle me-2"></i>
                All students have attendance records for this date.
            </div>
        `;
                    }
                }

                // Format date for display
                function formatDateForDisplay(dateString) {
                    const date = new Date(dateString);
                    return date.toLocaleDateString('en-US', {
                        weekday: 'long',
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric'
                    });
                }

                // Print attendance report


                // Export attendance to Excel
                function exportAttendanceToExcel() {
                    // This would be implemented with a library like SheetJS
                    // For now, we'll just show a message
                    showToast('Excel export functionality will be implemented soon', 'info');
                }

                // Initialize attendance system when DOM is loaded
                document.addEventListener('DOMContentLoaded', function() {
                    initAttendanceSystem();
                });
                // ======================
                // Institute Management Functions
                // ======================
                function editInstitute(instituteId) {
                    fetch(`get_institute.php?id=${instituteId}`)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                const institute = data.institute;
                                const modal = new bootstrap.Modal(document.getElementById('editInstituteModal'));

                                // Populate form fields
                                document.getElementById('edit_institute_id').value = institute.id;
                                document.getElementById('edit_institute_name').value = institute.name;
                                document.getElementById('edit_institute_phone').value = institute.phone;
                                document.getElementById('edit_institute_email').value = institute.email || '';
                                document.getElementById('edit_office_incharge_name').value = institute.office_incharge_name || '';
                                document.getElementById('edit_office_incharge_contact').value = institute.office_incharge_contact || '';
                                document.getElementById('edit_institute_address').value = institute.address;
                                document.getElementById('edit_institute_status').value = institute.status;

                                // Show modal
                                modal.show();
                            } else {
                                showToast(data.message || 'Error loading institute data', 'danger');
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            showToast('Network error loading institute data', 'danger');
                        });
                }

                function confirmDeleteInstitute(instituteId) {
                    Swal.fire({
                        title: 'Are you sure?',
                        text: "You won't be able to revert this! All users associated with this institute will be affected.",
                        icon: 'warning',
                        showCancelButton: true,
                        confirmButtonColor: '#d33',
                        cancelButtonColor: '#3085d6',
                        confirmButtonText: 'Yes, delete it!'
                    }).then((result) => {
                        if (result.isConfirmed) {
                            // Create form data with CSRF token
                            const formData = new FormData();
                            formData.append('form_type', 'delete_institute');
                            formData.append('institute_id', instituteId);
                            formData.append('csrf_token', '<?= $csrf_token ?>');

                            fetch('admin.php', {
                                    method: 'POST',
                                    body: formData
                                })
                                .then(response => {
                                    if (!response.ok) throw new Error('Network response was not ok');
                                    return response.text();
                                })
                                .then(() => {
                                    showToast('Institute deleted successfully', 'success');
                                    setTimeout(() => location.reload(), 1500);
                                })
                                .catch(error => {
                                    console.error('Error:', error);
                                    showToast('Error deleting institute', 'danger');
                                });
                        }
                    });
                }

                // Institute status toggle
                document.querySelectorAll('.institute-status-toggle').forEach(toggle => {
                    toggle.addEventListener('change', function() {
                        const instituteId = this.dataset.instituteId;
                        const formData = new FormData();
                        formData.append('form_type', 'toggle_institute_status');
                        formData.append('institute_id', instituteId);
                        formData.append('csrf_token', '<?= $csrf_token ?>');

                        fetch('admin.php', {
                                method: 'POST',
                                body: formData
                            })
                            .then(response => response.json())
                            .then(data => {
                                if (data.status) {
                                    showToast(data.message || 'Status updated', 'success');
                                } else {
                                    showToast(data.message || 'Failed to update status', 'danger');
                                    // Revert the toggle if failed
                                    this.checked = !this.checked;
                                }
                            })
                            .catch(() => {
                                showToast('Network error', 'danger');
                                this.checked = !this.checked;
                            });
                    });
                });

                // ======================
                // Reports Functions
                // ======================
                document.getElementById('generateUserActivityReport')?.addEventListener('click', function() {
                    const dateRange = document.getElementById('userActivityDateRange').value;

                    // Show loading state
                    const container = document.getElementById('reportResultsContainer');
                    container.innerHTML = `
                            <div class="text-center py-4">
                                <div class="spinner-border text-primary" role="status">
                                    <span class="visually-hidden">Loading...</span>
                                </div>
                                <p class="mt-2">Generating report...</p>
                            </div>
                        `;

                    // Simulate API call
                    setTimeout(() => {
                        container.innerHTML = `
                                <div class="card">
                                    <div class="card-header bg-primary text-white">
                                        <h5 class="mb-0">User Activity Report</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="table-responsive">
                                            <table class="table table-hover">
                                                <thead>
                                                    <tr>
                                                        <th>User</th>
                                                        <th>Last Login</th>
                                                        <th>Activity Count</th>
                                                        <th>Status</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <tr>
                                                        <td>Admin User</td>
                                                        <td>${new Date().toLocaleString()}</td>
                                                        <td>42</td>
                                                        <td><span class="badge bg-success">Active</span></td>
                                                    </tr>
                                                    <tr>
                                                        <td>Office User</td>
                                                        <td>${new Date(Date.now() - 86400000).toLocaleString()}</td>
                                                        <td>15</td>
                                                        <td><span class="badge bg-success">Active</span></td>
                                                    </tr>
                                                    <tr>
                                                        <td>Teacher User</td>
                                                        <td>${new Date(Date.now() - 2592000000).toLocaleString()}</td>
                                                        <td>3</td>
                                                        <td><span class="badge bg-secondary">Inactive</span></td>
                                                    </tr>
                                                </tbody>
                                            </table>
                                        </div>
                                        <div class="mt-3">
                                            <button class="btn btn-primary">
                                                <i class="bi bi-download"></i> Download Report
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            `;
                    }, 1500);
                });

                document.getElementById('generateInstituteReport')?.addEventListener('click', function() {
                    const instituteId = document.getElementById('instituteReportSelect').value;

                    // Show loading state
                    const container = document.getElementById('reportResultsContainer');
                    container.innerHTML = `
                            <div class="text-center py-4">
                                <div class="spinner-border text-primary" role="status">
                                    <span class="visually-hidden">Loading...</span>
                                </div>
                                <p class="mt-2">Generating report...</p>
                            </div>
                        `;

                    // Simulate API call
                    setTimeout(() => {
                        container.innerHTML = `
                                <div class="card">
                                    <div class="card-header bg-primary text-white">
                                        <h5 class="mb-0">Institute Usage Report</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="row">
                                            <div class="col-md-6">
                                                <h6>Summary</h6>
                                                <ul class="list-group mb-3">
                                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                                        Total Users
                                                        <span class="badge bg-primary rounded-pill">12</span>
                                                    </li>
                                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                                        Active Users
                                                        <span class="badge bg-success rounded-pill">8</span>
                                                    </li>
                                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                                        Students
                                                        <span class="badge bg-info rounded-pill">150</span>
                                                    </li>
                                                </ul>
                                            </div>
                                            <div class="col-md-6">
                                                <h6>Activity</h6>
                                                <ul class="list-group mb-3">
                                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                                        Logins (30 days)
                                                        <span class="badge bg-primary rounded-pill">42</span>
                                                    </li>
                                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                                        Fee Transactions
                                                        <span class="badge bg-success rounded-pill">₹15,420</span>
                                                    </li>
                                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                                        Attendance Records
                                                        <span class="badge bg-warning rounded-pill">1,250</span>
                                                    </li>
                                                </ul>
                                            </div>
                                        </div>
                                        <div class="mt-3">
                                            <button class="btn btn-primary">
                                                <i class="bi bi-download"></i> Download Report
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            `;
                    }, 1500);
                });

                // ======================
                // UI Components
                // ======================
                // Toast notifications
                function showToast(message, type) {
                    const toastContainer = document.querySelector('.toast-container');
                    const toastId = 'toast-' + Date.now();
                    const toast = document.createElement('div');

                    toast.id = toastId;
                    toast.className = `toast show align-items-center text-white bg-${type} border-0`;
                    toast.setAttribute('role', 'alert');
                    toast.setAttribute('aria-live', 'assertive');
                    toast.setAttribute('aria-atomic', 'true');

                    toast.innerHTML = `
                            <div class="d-flex">
                                <div class="toast-body">
                                    <i class="bi ${type === 'success' ? 'bi-check-circle' :
                            type === 'danger' ? 'bi-exclamation-triangle' :
                                type === 'warning' ? 'bi-exclamation-circle' : 'bi-info-circle'} me-2"></i>
                                    ${message}
                                </div>
                                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
                            </div>
                        `;

                    toastContainer.appendChild(toast);

                    // Auto-remove after delay
                    setTimeout(() => {
                        const bsToast = bootstrap.Toast.getOrCreateInstance(toast);
                        bsToast.hide();
                        toast.addEventListener('hidden.bs.toast', () => toast.remove());
                    }, 5000);

                    // Position toasts
                    const toasts = document.querySelectorAll('.toast');
                    toasts.forEach((t, i) => {
                        t.style.bottom = `${i * 60 + 20}px`;
                    });
                }

                // ========================
                // Dark mode functionality
                // ========================
                function initDarkMode() {
                    const darkModeToggle = document.getElementById('darkModeToggle');
                    const htmlElement = document.documentElement;

                    // Check for saved preference or use OS preference
                    const savedTheme = localStorage.getItem('theme') ||
                        (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

                    // Apply the saved theme
                    if (savedTheme === 'dark') {
                        htmlElement.setAttribute('data-bs-theme', 'dark');
                        darkModeToggle.innerHTML = '<i class="bi bi-sun-fill"></i>';
                    } else {
                        htmlElement.removeAttribute('data-bs-theme');
                        darkModeToggle.innerHTML = '<i class="bi bi-moon-fill"></i>';
                    }

                    // Toggle dark mode
                    darkModeToggle.addEventListener('click', function() {
                        const html = document.documentElement;
                        const isDark = html.getAttribute('data-bs-theme') === 'dark';

                        if (isDark) {
                            html.removeAttribute('data-bs-theme');
                            localStorage.setItem('theme', 'light');
                            this.innerHTML = '<i class="bi bi-moon-fill"></i>';
                        } else {
                            html.setAttribute('data-bs-theme', 'dark');
                            localStorage.setItem('theme', 'dark');
                            this.innerHTML = '<i class="bi bi-sun-fill"></i>';
                        }

                        // Force redraw
                        html.style.display = 'none';
                        html.offsetHeight; // Trigger reflow
                        html.style.display = '';
                    });
                }

                // ======================
                // logout confirmation
                // ======================

                document.querySelectorAll('.logout-link').forEach(link => {
                    link.addEventListener('click', function(e) {
                        e.preventDefault();
                        Swal.fire({
                            title: 'Are you sure?',
                            text: "You will be logged out of the system",
                            icon: 'warning',
                            showCancelButton: true,
                            confirmButtonColor: '#3085d6',
                            cancelButtonColor: '#d33',
                            confirmButtonText: 'Yes, logout!'
                        }).then((result) => {
                            if (result.isConfirmed) {
                                window.location.href = 'logout.php';
                            }
                        });
                    });
                });
            </script>
</body>

</html>