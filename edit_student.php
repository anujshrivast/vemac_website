<?php
require_once 'db_connect.php';
session_start();

// Check if user is logged in and has permission
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Generate CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Check if student ID is provided
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    $_SESSION['error_message'] = "Invalid student ID.";
    if ($_SESSION['role'] === 'admin') {
        header("Location: admin.php");
    } else {
        header("Location: office.php");

    }
    exit();
}

$studentId = (int)$_GET['id'];

// Fetch student data from database
$query = "SELECT * FROM student_data WHERE student_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param('i', $studentId);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    $_SESSION['error_message'] = "Student not found.";
    header("Location: students.php");
    exit();
}

$studentData = $result->fetch_assoc();
$stmt->close();

// Course options (you can fetch these from database if needed)
$courseOptions = [
    'BCA' => 'Bachelor of Computer Applications',
    'BBA' => 'Bachelor of Business Administration',
    'BCOM' => 'Bachelor of Commerce',
    'BA' => 'Bachelor of Arts',
    'BSC' => 'Bachelor of Science'
];

// Status options
$statusOptions = [
    'Active' => 'Active',
    'Inactive' => 'Inactive',
    'Completed' => 'Completed',
    'Suspended' => 'Suspended'
];

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $_SESSION['error_message'] = "Invalid CSRF token. Please try again.";
        header("Location: student_edit.php?id=$studentId");
        exit();
    }

    // Sanitize input function
    function sanitizeInput($data)
    {
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
        return $data;
    }

    // Sanitize phone number
    function sanitizePhoneNumber($phone)
    {
        return preg_replace('/[^0-9]/', '', $phone);
    }

    // Validate phone number
    function validatePhoneNumber($phone)
    {
        return preg_match('/^[0-9]{10,15}$/', $phone);
    }

    // Validate date
    function validateDate($date, $format = 'Y-m-d')
    {
        $d = DateTime::createFromFormat($format, $date);
        return $d && $d->format($format) === $date;
    }

    // Handle file upload
    function handleFileUpload($file, $studentId)
    {
        $allowedTypes = ['image/jpeg', 'image/png'];
        $maxSize = 2 * 1024 * 1024; // 2MB

        // Validate file
        if (!in_array($file['type'], $allowedTypes)) {
            throw new Exception("Only JPG and PNG images are allowed.");
        }

        if ($file['size'] > $maxSize) {
            throw new Exception("Image size exceeds 2MB limit.");
        }

        // Generate unique filename
        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
        $filename = 'student_' . $studentId . '.' . $extension;
        $uploadDir = 'uploads/students/';

        // Create directory if it doesn't exist
        if (!file_exists($uploadDir)) {
            if (!mkdir($uploadDir, 0777, true)) {
                throw new Exception("Failed to create upload directory.");
            }
        }

        $destination = $uploadDir . $filename;

        if (!move_uploaded_file($file['tmp_name'], $destination)) {
            throw new Exception("Failed to upload file.");
        }

        return $destination;
    }

    // Validate required fields
    $requiredFields = [
        'first_name',
        'last_name',
        'email',
        'phone',
        'dob',
        'gender',
        'address',
        'course',
        'parent_name',
        'parent_phone',
        'institute_name',
        'status'
    ];

    foreach ($requiredFields as $field) {
        if (empty($_POST[$field])) {
            $errors[$field] = "This field is required.";
        }
    }

    // Sanitize and validate input data
    $formData = [
        'first_name' => sanitizeInput($_POST['first_name']),
        'last_name' => sanitizeInput($_POST['last_name']),
        'email' => filter_var($_POST['email'], FILTER_SANITIZE_EMAIL),
        'phone' => sanitizePhoneNumber($_POST['phone']),
        'dob' => $_POST['dob'],
        'gender' => sanitizeInput($_POST['gender']),
        'address' => sanitizeInput($_POST['address']),
        'city' => isset($_POST['city']) ? sanitizeInput($_POST['city']) : null,
        'state' => isset($_POST['state']) ? sanitizeInput($_POST['state']) : null,
        'postal_code' => isset($_POST['postal_code']) ? sanitizeInput($_POST['postal_code']) : null,
        'country' => isset($_POST['country']) ? sanitizeInput($_POST['country']) : null,
        'course' => sanitizeInput($_POST['course']),
        'school_type' => isset($_POST['school_type']) ? sanitizeInput($_POST['school_type']) : null,
        'school' => isset($_POST['school']) ? sanitizeInput($_POST['school']) : null,
        'parent_name' => sanitizeInput($_POST['parent_name']),
        'parent_phone' => sanitizePhoneNumber($_POST['parent_phone']),
        'parent_address' => isset($_POST['parent_address']) ? sanitizeInput($_POST['parent_address']) : null,
        'Referred_by_About' => isset($_POST['Referred_by_About']) ? sanitizeInput($_POST['Referred_by_About']) : null,
        'Admission_Accpted_by' => isset($_POST['Admission_Accpted_by']) ? sanitizeInput($_POST['Admission_Accpted_by']) : null,
        'institute_name' => sanitizeInput($_POST['institute_name']),
        'status' => sanitizeInput($_POST['status']),
        'notes' => isset($_POST['notes']) ? sanitizeInput($_POST['notes']) : null,
        'enrollment_date' => isset($_POST['enrollment_date']) ? $_POST['enrollment_date'] : date('Y-m-d'),
        'expected_graduation' => isset($_POST['expected_graduation']) ? $_POST['expected_graduation'] : null
    ];

    // Validate email
    if (!filter_var($formData['email'], FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = "Invalid email format.";
    }

    // Validate phone numbers
    if (!validatePhoneNumber($formData['phone'])) {
        $errors['phone'] = "Invalid phone number format.";
    }

    if (!validatePhoneNumber($formData['parent_phone'])) {
        $errors['parent_phone'] = "Invalid parent phone number format.";
    }

    // Validate date of birth
    if (!validateDate($formData['dob'], 'Y-m-d')) {
        $errors['dob'] = "Invalid date of birth format.";
    } else {
        $dob = new DateTime($formData['dob']);
        $today = new DateTime();
        $age = $today->diff($dob)->y;
        if ($age < 10 || $age > 100) {
            $errors['dob'] = "Age must be between 10 and 100 years.";
        }
    }

    // If there are errors, store them in session and redirect back
    if (!empty($errors)) {
        $_SESSION['form_errors'] = $errors;
        $_SESSION['old_form_data'] = $formData;
        header("Location: student_edit.php?id=$studentId");
        exit();
    }

    try {
        // Build the UPDATE query
        $updateFields = [];
        $updateValues = [];

        foreach ($formData as $field => $value) {
            $updateFields[] = "$field = ?";
            $updateValues[] = $value;
        }

        $updateQuery = "UPDATE student_data SET " . implode(', ', $updateFields) . " WHERE student_id = ?";
        $updateValues[] = $studentId;

        $stmt = $conn->prepare($updateQuery);

        if (!$stmt) {
            throw new Exception("Database prepare error: " . $conn->error);
        }

        // Create type string for bind_param (all strings + one integer for student_id)
        $types = str_repeat('s', count($formData)) . 'i';
        $stmt->bind_param($types, ...$updateValues);

        if (!$stmt->execute()) {
            throw new Exception("Database execute error: " . $stmt->error);
        }

        $stmt->close();

        // Process photo upload if present
        if (isset($_FILES['photo']) && $_FILES['photo']['error'] === UPLOAD_ERR_OK) {
            $photoPath = handleFileUpload($_FILES['photo'], $studentId);

            // Update the student record with photo path
            $updateQuery = "UPDATE student_data SET photo_path = ? WHERE student_id = ?";
            $updateStmt = $conn->prepare($updateQuery);
            $updateStmt->bind_param('si', $photoPath, $studentId);
            $updateStmt->execute();
            $updateStmt->close();
        }

        // Set success message and redirect to view page
        $_SESSION['success_message'] = "Student updated successfully!";
        header("Location: student_view.php?id=$studentId");
        exit();
    } catch (Exception $e) {
        $_SESSION['error_message'] = "Error: " . $e->getMessage();
        $_SESSION['old_form_data'] = $formData;
        header("Location: student_edit.php?id=$studentId");
        exit();
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Student - VEMAC</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/intl-tel-input/17.0.8/css/intlTelInput.css">
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
        }

        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        .card {
            border-radius: 0.5rem;
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.1);
            border: none;
        }

        .card-header {
            border-radius: 0.5rem 0.5rem 0 0 !important;
            padding: 1.25rem 1.5rem;
            background-color: var(--primary-color);
            color: white;
        }

        .form-section {
            background-color: white;
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.05);
            border: 1px solid rgba(0, 0, 0, 0.05);
        }

        .section-title {
            color: var(--primary-color);
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 0.5rem;
            margin-bottom: 1.25rem;
            font-weight: 600;
            font-size: 1.25rem;
        }

        .required-field::after {
            content: " *";
            color: var(--danger-color);
        }

        #photoPreview {
            width: 150px;
            height: 150px;
            border: 2px dashed var(--secondary-color);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 1rem;
            overflow: hidden;
            border-radius: 50%;
            background-color: var(--light-color);
            transition: all 0.3s ease;
        }

        #photoPreview:hover {
            border-color: var(--primary-color);
        }

        #photoPreview img {
            max-width: 100%;
            max-height: 100%;
            object-fit: cover;
        }

        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            padding: 0.5rem 1.25rem;
            font-weight: 500;
        }

        .btn-primary:hover {
            background-color: #3a5bc7;
            border-color: #3a5bc7;
        }

        .btn-secondary {
            padding: 0.5rem 1.25rem;
            font-weight: 500;
        }

        .form-control,
        .form-select {
            padding: 0.5rem 0.75rem;
            border-radius: 0.375rem;
            border: 1px solid #ced4da;
            transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
        }

        .form-control:focus,
        .form-select:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.25rem rgba(78, 115, 223, 0.25);
        }

        .invalid-feedback {
            font-size: 0.875rem;
        }

        .is-invalid {
            border-color: var(--danger-color);
        }

        .was-validated .form-control:invalid,
        .was-validated .form-select:invalid {
            border-color: var(--danger-color);
        }

        .was-validated .form-control:valid,
        .was-validated .form-select:valid {
            border-color: var(--success-color);
        }

        .iti {
            width: 100%;
        }

        .nav-tabs .nav-link {
            color: var(--secondary-color);
            font-weight: 500;
        }

        .nav-tabs .nav-link.active {
            color: var(--primary-color);
            font-weight: 600;
        }

        @media (max-width: 768px) {
            .card-body {
                padding: 1rem;
            }

            .form-section {
                padding: 1rem;
            }
        }
    </style>
</head>

<body>
    <div class="container py-4">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h3 class="mb-0">Edit Student</h3>
                        <span class="badge bg-light text-dark">
                            ID: <?= $studentId ?>
                        </span>
                    </div>
                    <div class="card-body">
                        <?php if (isset($_SESSION['error_message'])): ?>
                            <div class="alert alert-danger alert-dismissible fade show">
                                <?= $_SESSION['error_message'] ?>
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                            </div>
                            <?php unset($_SESSION['error_message']); ?>
                        <?php endif; ?>

                        <form method="POST" enctype="multipart/form-data" class="needs-validation" novalidate>
                            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

                            <ul class="nav nav-tabs mb-4" id="studentFormTabs" role="tablist">
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link active" id="personal-tab" data-bs-toggle="tab" data-bs-target="#personal" type="button" role="tab">
                                        <i class="bi bi-person-vcard me-1"></i> Personal
                                    </button>
                                </li>
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link" id="academic-tab" data-bs-toggle="tab" data-bs-target="#academic" type="button" role="tab">
                                        <i class="bi bi-book me-1"></i> Academic
                                    </button>
                                </li>
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link" id="contact-tab" data-bs-toggle="tab" data-bs-target="#contact" type="button" role="tab">
                                        <i class="bi bi-house-door me-1"></i> Contact
                                    </button>
                                </li>
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link" id="additional-tab" data-bs-toggle="tab" data-bs-target="#additional" type="button" role="tab">
                                        <i class="bi bi-info-circle me-1"></i> Additional
                                    </button>
                                </li>
                            </ul>

                            <div class="tab-content" id="studentFormTabsContent">
                                <!-- Personal Information Tab -->
                                <div class="tab-pane fade show active" id="personal" role="tabpanel">
                                    <div class="row">
                                        <div class="col-md-4 mb-4 text-center">
                                            <div id="photoPreview" class="mx-auto">
                                                <?php if (!empty($studentData['photo_path'])): ?>
                                                    <img src="<?= $studentData['photo_path'] ?>" alt="Student Photo">
                                                <?php else: ?>
                                                    <i class="bi bi-person-circle" style="font-size: 4rem;"></i>
                                                <?php endif; ?>
                                            </div>
                                            <label for="photo" class="btn btn-sm btn-outline-primary mt-2">
                                                <i class="bi bi-upload me-1"></i> Upload Photo
                                                <input type="file" class="d-none" id="photo" name="photo" accept="image/*">
                                            </label>
                                            <div class="text-muted small mt-1">Max 2MB (JPG, PNG)</div>
                                            <?php if (!empty($studentData['photo_path'])): ?>
                                                <div class="mt-2">
                                                    <button type="button" class="btn btn-sm btn-outline-danger" id="removePhoto">
                                                        <i class="bi bi-trash me-1"></i> Remove Photo
                                                    </button>
                                                    <input type="hidden" name="remove_photo" id="removePhotoFlag" value="0">
                                                </div>
                                            <?php endif; ?>
                                        </div>
                                        <div class="col-md-8">
                                            <div class="row">
                                                <div class="col-md-6 mb-3">
                                                    <label for="first_name" class="form-label required-field">First Name</label>
                                                    <input type="text" class="form-control <?= isset($_SESSION['form_errors']['first_name']) ? 'is-invalid' : '' ?>"
                                                        id="first_name" name="first_name"
                                                        value="<?= isset($_SESSION['old_form_data']['first_name']) ? $_SESSION['old_form_data']['first_name'] : htmlspecialchars($studentData['first_name']) ?>"
                                                        required>
                                                    <?php if (isset($_SESSION['form_errors']['first_name'])): ?>
                                                        <div class="invalid-feedback"><?= $_SESSION['form_errors']['first_name'] ?></div>
                                                    <?php else: ?>
                                                        <div class="invalid-feedback">Please enter first name</div>
                                                    <?php endif; ?>
                                                </div>
                                                <div class="col-md-6 mb-3">
                                                    <label for="last_name" class="form-label required-field">Last Name</label>
                                                    <input type="text" class="form-control <?= isset($_SESSION['form_errors']['last_name']) ? 'is-invalid' : '' ?>"
                                                        id="last_name" name="last_name"
                                                        value="<?= isset($_SESSION['old_form_data']['last_name']) ? $_SESSION['old_form_data']['last_name'] : htmlspecialchars($studentData['last_name']) ?>"
                                                        required>
                                                    <?php if (isset($_SESSION['form_errors']['last_name'])): ?>
                                                        <div class="invalid-feedback"><?= $_SESSION['form_errors']['last_name'] ?></div>
                                                    <?php else: ?>
                                                        <div class="invalid-feedback">Please enter last name</div>
                                                    <?php endif; ?>
                                                </div>
                                            </div>

                                            <div class="row">
                                                <div class="col-md-6 mb-3">
                                                    <label for="email" class="form-label required-field">Email</label>
                                                    <input type="email" class="form-control <?= isset($_SESSION['form_errors']['email']) ? 'is-invalid' : '' ?>"
                                                        id="email" name="email"
                                                        value="<?= isset($_SESSION['old_form_data']['email']) ? $_SESSION['old_form_data']['email'] : htmlspecialchars($studentData['email']) ?>"
                                                        required>
                                                    <?php if (isset($_SESSION['form_errors']['email'])): ?>
                                                        <div class="invalid-feedback"><?= $_SESSION['form_errors']['email'] ?></div>
                                                    <?php else: ?>
                                                        <div class="invalid-feedback">Please enter a valid email</div>
                                                    <?php endif; ?>
                                                </div>
                                                <div class="col-md-6 mb-3">
                                                    <label for="phone" class="form-label required-field">Phone</label>
                                                    <input type="tel" class="form-control <?= isset($_SESSION['form_errors']['phone']) ? 'is-invalid' : '' ?>"
                                                        id="phone" name="phone"
                                                        value="<?= isset($_SESSION['old_form_data']['phone']) ? $_SESSION['old_form_data']['phone'] : htmlspecialchars($studentData['phone']) ?>"
                                                        required>
                                                    <?php if (isset($_SESSION['form_errors']['phone'])): ?>
                                                        <div class="invalid-feedback"><?= $_SESSION['form_errors']['phone'] ?></div>
                                                    <?php else: ?>
                                                        <div class="invalid-feedback">Please enter a valid phone number</div>
                                                    <?php endif; ?>
                                                </div>
                                            </div>

                                            <div class="row">
                                                <div class="col-md-6 mb-3">
                                                    <label for="dob" class="form-label required-field">Date of Birth</label>
                                                    <input type="date" class="form-control <?= isset($_SESSION['form_errors']['dob']) ? 'is-invalid' : '' ?>"
                                                        id="dob" name="dob"
                                                        value="<?= isset($_SESSION['old_form_data']['dob']) ? $_SESSION['old_form_data']['dob'] : htmlspecialchars($studentData['dob']) ?>"
                                                        required>
                                                    <?php if (isset($_SESSION['form_errors']['dob'])): ?>
                                                        <div class="invalid-feedback"><?= $_SESSION['form_errors']['dob'] ?></div>
                                                    <?php else: ?>
                                                        <div class="invalid-feedback">Please select date of birth</div>
                                                    <?php endif; ?>
                                                </div>
                                                <div class="col-md-6 mb-3">
                                                    <label for="gender" class="form-label required-field">Gender</label>
                                                    <select class="form-select <?= isset($_SESSION['form_errors']['gender']) ? 'is-invalid' : '' ?>"
                                                        id="gender" name="gender" required>
                                                        <option value="">Select Gender</option>
                                                        <option value="Male" <?= (isset($_SESSION['old_form_data']['gender'])) ? ($_SESSION['old_form_data']['gender'] == 'Male' ? 'selected' : '') : ($studentData['gender'] == 'Male' ? 'selected' : '') ?>>Male</option>
                                                        <option value="Female" <?= (isset($_SESSION['old_form_data']['gender'])) ? ($_SESSION['old_form_data']['gender'] == 'Female' ? 'selected' : '') : ($studentData['gender'] == 'Female' ? 'selected' : '') ?>>Female</option>
                                                        <option value="Other" <?= (isset($_SESSION['old_form_data']['gender'])) ? ($_SESSION['old_form_data']['gender'] == 'Other' ? 'selected' : '') : ($studentData['gender'] == 'Other' ? 'selected' : '') ?>>Other</option>
                                                    </select>
                                                    <?php if (isset($_SESSION['form_errors']['gender'])): ?>
                                                        <div class="invalid-feedback"><?= $_SESSION['form_errors']['gender'] ?></div>
                                                    <?php else: ?>
                                                        <div class="invalid-feedback">Please select gender</div>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Academic Information Tab -->
                                <div class="tab-pane fade" id="academic" role="tabpanel">
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="course" class="form-label required-field">Course</label>
                                            <select class="form-select <?= isset($_SESSION['form_errors']['course']) ? 'is-invalid' : '' ?>"
                                                id="course" name="course" required>
                                                <option value="">Select Course</option>
                                                <?php foreach ($courseOptions as $value => $label): ?>
                                                    <option value="<?= $value ?>" <?= (isset($_SESSION['old_form_data']['course'])) ? ($_SESSION['old_form_data']['course'] == $value ? 'selected' : '') : ($studentData['course'] == $value ? 'selected' : '') ?>>
                                                        <?= $label ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                            <?php if (isset($_SESSION['form_errors']['course'])): ?>
                                                <div class="invalid-feedback"><?= $_SESSION['form_errors']['course'] ?></div>
                                            <?php else: ?>
                                                <div class="invalid-feedback">Please select course</div>
                                            <?php endif; ?>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="school_type" class="form-label">School Type</label>
                                            <input type="text" class="form-control" id="school_type" name="school_type"
                                                value="<?= isset($_SESSION['old_form_data']['school_type']) ? $_SESSION['old_form_data']['school_type'] : htmlspecialchars($studentData['school_type']) ?>">
                                        </div>
                                    </div>

                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="school" class="form-label">School</label>
                                            <input type="text" class="form-control" id="school" name="school"
                                                value="<?= isset($_SESSION['old_form_data']['school']) ? $_SESSION['old_form_data']['school'] : htmlspecialchars($studentData['school']) ?>">
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="Admission_code" class="form-label">Admission Code</label>
                                            <input type="text" class="form-control" id="Admission_code"
                                                value="<?= htmlspecialchars($studentData['Admission_code']) ?>" readonly>
                                        </div>
                                    </div>

                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="enrollment_date" class="form-label">Enrollment Date</label>
                                            <input type="date" class="form-control" id="enrollment_date" name="enrollment_date"
                                                value="<?= isset($_SESSION['old_form_data']['enrollment_date']) ? $_SESSION['old_form_data']['enrollment_date'] : htmlspecialchars($studentData['enrollment_date']) ?>">
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="expected_graduation" class="form-label">Expected Graduation</label>
                                            <input type="date" class="form-control" id="expected_graduation" name="expected_graduation"
                                                value="<?= isset($_SESSION['old_form_data']['expected_graduation']) ? $_SESSION['old_form_data']['expected_graduation'] : htmlspecialchars($studentData['expected_graduation']) ?>">
                                        </div>
                                    </div>
                                </div>

                                <!-- Contact Information Tab -->
                                <div class="tab-pane fade" id="contact" role="tabpanel">
                                    <div class="mb-3">
                                        <label for="address" class="form-label required-field">Address</label>
                                        <textarea class="form-control <?= isset($_SESSION['form_errors']['address']) ? 'is-invalid' : '' ?>"
                                            id="address" name="address" rows="3" required><?= isset($_SESSION['old_form_data']['address']) ? $_SESSION['old_form_data']['address'] : htmlspecialchars($studentData['address']) ?></textarea>
                                        <?php if (isset($_SESSION['form_errors']['address'])): ?>
                                            <div class="invalid-feedback"><?= $_SESSION['form_errors']['address'] ?></div>
                                        <?php else: ?>
                                            <div class="invalid-feedback">Please enter address</div>
                                        <?php endif; ?>
                                    </div>

                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="city" class="form-label">City</label>
                                            <input type="text" class="form-control" id="city" name="city"
                                                value="<?= isset($_SESSION['old_form_data']['city']) ? $_SESSION['old_form_data']['city'] : htmlspecialchars($studentData['city']) ?>">
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="state" class="form-label">State/Province</label>
                                            <input type="text" class="form-control" id="state" name="state"
                                                value="<?= isset($_SESSION['old_form_data']['state']) ? $_SESSION['old_form_data']['state'] : htmlspecialchars($studentData['state']) ?>">
                                        </div>
                                    </div>

                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="postal_code" class="form-label">Postal Code</label>
                                            <input type="text" class="form-control" id="postal_code" name="postal_code"
                                                value="<?= isset($_SESSION['old_form_data']['postal_code']) ? $_SESSION['old_form_data']['postal_code'] : htmlspecialchars($studentData['postal_code']) ?>">
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="country" class="form-label">Country</label>
                                            <input type="text" class="form-control" id="country" name="country"
                                                value="<?= isset($_SESSION['old_form_data']['country']) ? $_SESSION['old_form_data']['country'] : htmlspecialchars($studentData['country']) ?>">
                                        </div>
                                    </div>

                                    <h5 class="mt-4 mb-3 text-primary">Parent/Guardian Information</h5>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="parent_name" class="form-label required-field">Parent Name</label>
                                            <input type="text" class="form-control <?= isset($_SESSION['form_errors']['parent_name']) ? 'is-invalid' : '' ?>"
                                                id="parent_name" name="parent_name"
                                                value="<?= isset($_SESSION['old_form_data']['parent_name']) ? $_SESSION['old_form_data']['parent_name'] : htmlspecialchars($studentData['parent_name']) ?>"
                                                required>
                                            <?php if (isset($_SESSION['form_errors']['parent_name'])): ?>
                                                <div class="invalid-feedback"><?= $_SESSION['form_errors']['parent_name'] ?></div>
                                            <?php else: ?>
                                                <div class="invalid-feedback">Please enter parent name</div>
                                            <?php endif; ?>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="parent_phone" class="form-label required-field">Parent Phone</label>
                                            <input type="tel" class="form-control <?= isset($_SESSION['form_errors']['parent_phone']) ? 'is-invalid' : '' ?>"
                                                id="parent_phone" name="parent_phone"
                                                value="<?= isset($_SESSION['old_form_data']['parent_phone']) ? $_SESSION['old_form_data']['parent_phone'] : htmlspecialchars($studentData['parent_phone']) ?>"
                                                required>
                                            <?php if (isset($_SESSION['form_errors']['parent_phone'])): ?>
                                                <div class="invalid-feedback"><?= $_SESSION['form_errors']['parent_phone'] ?></div>
                                            <?php else: ?>
                                                <div class="invalid-feedback">Please enter parent phone number</div>
                                            <?php endif; ?>
                                        </div>
                                    </div>

                                    <div class="mb-3">
                                        <label for="parent_address" class="form-label">Parent Address</label>
                                        <textarea class="form-control" id="parent_address" name="parent_address" rows="2"><?= isset($_SESSION['old_form_data']['parent_address']) ? $_SESSION['old_form_data']['parent_address'] : htmlspecialchars($studentData['parent_address']) ?></textarea>
                                    </div>
                                </div>

                                <!-- Additional Information Tab -->
                                <div class="tab-pane fade" id="additional" role="tabpanel">
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="Referred_by_About" class="form-label">Referred By</label>
                                            <input type="text" class="form-control" id="Referred_by_About" name="Referred_by_About"
                                                value="<?= isset($_SESSION['old_form_data']['Referred_by_About']) ? $_SESSION['old_form_data']['Referred_by_About'] : htmlspecialchars($studentData['Referred_by_About']) ?>">
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="Admission_Accpted_by" class="form-label">Admission Accepted By</label>
                                            <input type="text" class="form-control" id="Admission_Accpted_by" name="Admission_Accpted_by"
                                                value="<?= isset($_SESSION['old_form_data']['Admission_Accpted_by']) ? $_SESSION['old_form_data']['Admission_Accpted_by'] : htmlspecialchars($studentData['Admission_Accpted_by']) ?>">
                                        </div>
                                    </div>

                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label for="institute_name" class="form-label required-field">Institute</label>
                                            <input type="text" class="form-control <?= isset($_SESSION['form_errors']['institute_name']) ? 'is-invalid' : '' ?>"
                                                id="institute_name" name="institute_name"
                                                value="<?= isset($_SESSION['old_form_data']['institute_name']) ? $_SESSION['old_form_data']['institute_name'] : htmlspecialchars($studentData['institute_name']) ?>"
                                                required>
                                            <?php if (isset($_SESSION['form_errors']['institute_name'])): ?>
                                                <div class="invalid-feedback"><?= $_SESSION['form_errors']['institute_name'] ?></div>
                                            <?php else: ?>
                                                <div class="invalid-feedback">Please enter institute name</div>
                                            <?php endif; ?>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label for="status" class="form-label required-field">Status</label>
                                            <select class="form-select <?= isset($_SESSION['form_errors']['status']) ? 'is-invalid' : '' ?>"
                                                id="status" name="status" required>
                                                <?php foreach ($statusOptions as $value => $label): ?>
                                                    <option value="<?= $value ?>" <?= (isset($_SESSION['old_form_data']['status'])) ? ($_SESSION['old_form_data']['status'] == $value ? 'selected' : '') : ($studentData['status'] == $value ? 'selected' : '') ?>>
                                                        <?= $label ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                            <?php if (isset($_SESSION['form_errors']['status'])): ?>
                                                <div class="invalid-feedback"><?= $_SESSION['form_errors']['status'] ?></div>
                                            <?php else: ?>
                                                <div class="invalid-feedback">Please select status</div>
                                            <?php endif; ?>
                                        </div>
                                    </div>

                                    <div class="mb-3">
                                        <label for="notes" class="form-label">Notes</label>
                                        <textarea class="form-control" id="notes" name="notes" rows="3"><?= isset($_SESSION['old_form_data']['notes']) ? $_SESSION['old_form_data']['notes'] : htmlspecialchars($studentData['notes']) ?></textarea>
                                    </div>
                                </div>
                            </div>

                            <div class="d-flex justify-content-between mt-4">
                                <div>
                                    <a href="student_view.php?id=<?= $studentId ?>" class="btn btn-outline-secondary me-2">
                                        <i class="bi bi-x-circle me-1"></i> Cancel
                                    </a>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="bi bi-save me-1"></i> Save Changes
                                    </button>
                                </div>
                                <div>
                                    <a href="student_delete.php?id=<?= $studentId ?>" class="btn btn-outline-danger" onclick="return confirm('Are you sure you want to delete this student? This action cannot be undone.');">
                                        <i class="bi bi-trash me-1"></i> Delete Student
                                    </a>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/intl-tel-input/17.0.8/js/intlTelInput.min.js"></script>
    <script>
        // Initialize phone input with international dial codes
        const phoneInput = document.querySelector("#phone");
        const parentPhoneInput = document.querySelector("#parent_phone");

        const iti = window.intlTelInput(phoneInput, {
            initialCountry: "in",
            separateDialCode: true,
            utilsScript: "https://cdnjs.cloudflare.com/ajax/libs/intl-tel-input/17.0.8/js/utils.js"
        });

        const parentIti = window.intlTelInput(parentPhoneInput, {
            initialCountry: "in",
            separateDialCode: true,
            utilsScript: "https://cdnjs.cloudflare.com/ajax/libs/intl-tel-input/17.0.8/js/utils.js"
        });

        // Photo preview
        document.getElementById('photo').addEventListener('change', function(e) {
            const preview = document.getElementById('photoPreview');
            const file = e.target.files[0];

            if (file) {
                // Validate file size (max 2MB)
                if (file.size > 2 * 1024 * 1024) {
                    alert('File size exceeds 2MB limit');
                    this.value = '';
                    return;
                }

                // Validate file type
                const validTypes = ['image/jpeg', 'image/png'];
                if (!validTypes.includes(file.type)) {
                    alert('Only JPG and PNG images are allowed');
                    this.value = '';
                    return;
                }

                const reader = new FileReader();
                reader.onload = function(e) {
                    preview.innerHTML = `<img src="${e.target.result}" alt="Preview">`;
                    document.getElementById('removePhotoFlag').value = '0';
                }
                reader.readAsDataURL(file);
            }
        });

        // Remove photo button
        document.getElementById('removePhoto')?.addEventListener('click', function() {
            const preview = document.getElementById('photoPreview');
            preview.innerHTML = '<i class="bi bi-person-circle" style="font-size: 4rem;"></i>';
            document.getElementById('photo').value = '';
            document.getElementById('removePhotoFlag').value = '1';
        });

        // Form validation
        (function() {
            'use strict';
            const forms = document.querySelectorAll('.needs-validation');

            Array.from(forms).forEach(form => {
                form.addEventListener('submit', event => {
                    if (!form.checkValidity()) {
                        event.preventDefault();
                        event.stopPropagation();

                        // Show the first tab with invalid fields
                        const invalidFields = form.querySelectorAll(':invalid');
                        if (invalidFields.length > 0) {
                            const firstInvalid = invalidFields[0];
                            const tabPane = firstInvalid.closest('.tab-pane');
                            if (tabPane) {
                                const tabId = tabPane.id;
                                const tabButton = document.querySelector(`[data-bs-target="#${tabId}"]`);
                                if (tabButton) {
                                    new bootstrap.Tab(tabButton).show();
                                }
                            }
                        }
                    }

                    form.classList.add('was-validated');
                }, false);
            });
        })();

        // Auto-format phone numbers
        function formatPhoneNumber(input) {
            // Remove all non-digit characters
            let phoneNumber = input.value.replace(/\D/g, '');

            // Format based on length
            if (phoneNumber.length > 10) {
                phoneNumber = phoneNumber.substring(0, 10);
            }

            // Apply formatting
            if (phoneNumber.length > 3 && phoneNumber.length <= 6) {
                phoneNumber = phoneNumber.replace(/(\d{3})(\d{0,3})/, '$1-$2');
            } else if (phoneNumber.length > 6) {
                phoneNumber = phoneNumber.replace(/(\d{3})(\d{3})(\d{0,4})/, '$1-$2-$3');
            }

            input.value = phoneNumber;
        }

        // Add input event listeners for phone fields
        phoneInput.addEventListener('input', function() {
            formatPhoneNumber(this);
        });

        parentPhoneInput.addEventListener('input', function() {
            formatPhoneNumber(this);
        });
    </script>
</body>

</html>

<?php
// Clear form errors and old data after displaying them
if (isset($_SESSION['form_errors'])) {
    unset($_SESSION['form_errors']);
}
if (isset($_SESSION['old_form_data'])) {
    unset($_SESSION['old_form_data']);
}
?>