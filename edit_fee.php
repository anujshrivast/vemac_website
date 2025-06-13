<?php
require_once 'db_connect.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check if user is authenticated
if (!isset($_SESSION['user_id'])) {
    $_SESSION['error_message'] = "You must be logged in to access this page.";
    header("Location: login.php");
    exit;
}

// Check if fee ID is provided
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    $_SESSION['error_message'] = "Invalid fee ID provided.";
    if ($_SESSION['role'] === 'admin') {
        header("Location: admin.php");
    } else {
        header("Location: office.php");
        exit();
    }
}

$fee_id = (int)$_GET['id'];
$instituteName = $_SESSION['institute_name'] ?? '';

// Fetch fee data
$fee_data = [];
$fee_details = [];
try {
    // Get main fee record
    $stmt = $conn->prepare("SELECT f.*, s.first_name, s.last_name 
                           FROM fees f
                           JOIN student_data s ON f.student_id = s.student_id
                           WHERE f.fee_id = ? AND s.institute_name = ?");
    $stmt->bind_param("is", $fee_id, $instituteName);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        throw new Exception("Fee record not found or you don't have permission to access it.");
    }

    $fee_data = $result->fetch_assoc();
    $stmt->close();

    // Get fee details (month ranges)
    $stmt = $conn->prepare("SELECT * FROM fee_details WHERE fee_id = ?");
    $stmt->bind_param("i", $fee_id);
    $stmt->execute();
    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        $fee_details[] = $row;
    }
    $stmt->close();
} catch (Exception $e) {
    $_SESSION['error_message'] = "Error: " . $e->getMessage();
    if ($_SESSION['role'] === 'admin') {
        header("Location: admin.php");
    } else {
        header("Location: office.php");
        exit();
    }
}

// Handle form submission for updates
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['form_type'] === 'edit_fee') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $_SESSION['error_message'] = "Invalid CSRF token. Please try again.";
        header("Location: edit_fee.php?id=" . $fee_id);
        exit;
    }

    try {
        // Validate and sanitize inputs
        $student_id = filter_input(INPUT_POST, 'student_id', FILTER_VALIDATE_INT);
        if (!$student_id) {
            throw new Exception("Invalid student ID");
        }

        $payment_method = sanitizeInput($_POST['payment_method']);
        $transaction_id = isset($_POST['transaction_id']) ? sanitizeInput($_POST['transaction_id']) : null;
        $payment_date = sanitizeInput($_POST['payment_date']);
        $status = in_array($_POST['status'], ['paid', 'pending', 'partial']) ? $_POST['status'] : 'paid';
        $notes = sanitizeInput($_POST['notes'] ?? '');
        $total_amount = filter_input(INPUT_POST, 'total_amount', FILTER_VALIDATE_FLOAT);

        if ($total_amount === false || $total_amount <= 0) {
            throw new Exception("Invalid total amount");
        }

        // Begin transaction
        $conn->begin_transaction();

        // Update fees table
        $stmt = $conn->prepare("UPDATE fees SET 
                               student_id = ?,
                               payment_method = ?,
                               transaction_id = ?,
                               payment_date = ?,
                               status = ?,
                               remarks = ?,
                               total_amount = ?
                               WHERE fee_id = ?");
        $stmt->bind_param(
            "isssssdi",
            $student_id,
            $payment_method,
            $transaction_id,
            $payment_date,
            $status,
            $notes,
            $total_amount,
            $fee_id
        );

        if (!$stmt->execute()) {
            throw new Exception("Failed to update fee payment: " . $stmt->error);
        }

        $stmt->close();

        // Delete existing fee details
        $stmt = $conn->prepare("DELETE FROM fee_details WHERE fee_id = ?");
        $stmt->bind_param("i", $fee_id);
        if (!$stmt->execute()) {
            throw new Exception("Failed to remove old fee details: " . $stmt->error);
        }
        $stmt->close();

        // Insert new fee details if provided
        if (!empty($_POST['fee_from_months']) && !empty($_POST['fee_to_months']) && !empty($_POST['fee_month_amounts'])) {
            $fromMonths = $_POST['fee_from_months'];
            $toMonths = $_POST['fee_to_months'];
            $amounts = $_POST['fee_month_amounts'];

            // Validate that all arrays have same length
            if (count($fromMonths) !== count($toMonths) || count($fromMonths) !== count($amounts)) {
                throw new Exception("Month range and amount counts don't match");
            }

            $detailStmt = $conn->prepare("INSERT INTO fee_details (fee_id, from_month, to_month, amount) VALUES (?, ?, ?, ?)");

            foreach ($fromMonths as $idx => $fromMonth) {
                $fromMonthVal = sanitizeInput($fromMonth);
                $toMonthVal = sanitizeInput($toMonths[$idx]);
                $amountVal = filter_var($amounts[$idx], FILTER_VALIDATE_FLOAT);

                if (strtotime($fromMonthVal) > strtotime($toMonthVal)) {
                    throw new Exception("Invalid date range - from date cannot be after to date");
                }

                if ($amountVal === false || $amountVal <= 0) {
                    throw new Exception("Invalid amount for month range " . $fromMonthVal . " to " . $toMonthVal);
                }

                $detailStmt->bind_param("issd", $fee_id, $fromMonthVal, $toMonthVal, $amountVal);
                if (!$detailStmt->execute()) {
                    throw new Exception("Failed to add fee details: " . $detailStmt->error);
                }
            }

            $detailStmt->close();
        }

        // Commit transaction
        $conn->commit();

        $_SESSION['success_message'] = "Fee payment updated successfully.";
        header("Location: fee_details.php?id=" . $fee_id);
        exit;
    } catch (Exception $e) {
        // Rollback transaction on error
        $conn->rollback();

        $_SESSION['error_message'] = "Error: " . $e->getMessage();
        header("Location: edit_fee.php?id=" . $fee_id);
        exit;
    }
}

// Fetch students for dropdown
$students = [];
$stmt = $conn->prepare("SELECT student_id, first_name, last_name, 
                       (SELECT COALESCE(SUM(total_amount), 0) FROM fees WHERE student_id = sd.student_id AND status = 'paid') as paid_amount,
                       (SELECT COALESCE(SUM(total_amount), 0) FROM fees WHERE student_id = sd.student_id AND status IN ('pending', 'partial')) as pending_amount
                       FROM student_data sd
                       WHERE institute_name = ?
                       ORDER BY first_name, last_name");
$stmt->bind_param("s", $instituteName);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $students[] = $row;
}
$stmt->close();

// Generate CSRF token
$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;

function sanitizeInput($data)
{
    return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
}
?>

<!DOCTYPE html>
<html lang="en" data-bs-theme="auto">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Fee Payment - <?= htmlspecialchars($instituteName) ?></title>

    <!-- Preload critical resources -->
    <link rel="preload" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css"
        as="style">
    <link rel="preload" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" as="style">

    <!-- Bootstrap CSS with dark mode support -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet"
        crossorigin="anonymous">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css"
        crossorigin="anonymous">

    <!-- Select2 for enhanced dropdowns -->
    <link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />
    <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/select2-bootstrap-5-theme@1.3.0/dist/select2-bootstrap-5-theme.min.css" />

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
            --input-bg: #ffffff;
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
            --input-bg: #1e2a4a;
        }

        body {
            background-color: var(--body-bg);
            color: var(--dark-color);
            transition: background-color 0.3s ease, color 0.3s ease;
        }

        .card {
            background-color: var(--card-bg);
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border: none;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.15);
        }

        .card-header {
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
        }

        [data-bs-theme="dark"] .card-header {
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .form-section {
            background-color: var(--card-bg);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            border: 1px solid rgba(0, 0, 0, 0.05);
        }

        [data-bs-theme="dark"] .form-section {
            border: 1px solid rgba(255, 255, 255, 0.05);
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

        .required-field::after {
            content: " *";
            color: var(--danger-color);
        }

        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }

        .btn-primary:hover {
            background-color: #3d5ec5;
            border-color: #3d5ec5;
        }

        .btn-success {
            background-color: var(--success-color);
            border-color: var(--success-color);
        }

        .btn-success:hover {
            background-color: #17a673;
            border-color: #17a673;
        }

        .form-control,
        .form-select,
        .form-control:focus,
        .form-select:focus {
            background-color: var(--input-bg);
            color: var(--dark-color);
            border-color: var(--secondary-color);
        }

        .form-control:focus,
        .form-select:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(78, 115, 223, 0.25);
        }

        .select2-container--default .select2-selection--single {
            background-color: var(--input-bg);
            border-color: var(--secondary-color);
            color: var(--dark-color);
            height: 38px;
        }

        .select2-container--default .select2-selection--single .select2-selection__rendered {
            color: var(--dark-color);
            line-height: 36px;
        }

        .select2-container--default .select2-selection--single .select2-selection__arrow {
            height: 36px;
        }

        .student-info-card {
            border-left: 4px solid var(--primary-color);
            padding: 15px;
            margin-bottom: 20px;
            background-color: var(--card-bg);
            border-radius: 5px;
            transition: all 0.3s ease;
        }

        .fee-summary {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            gap: 10px;
        }

        .fee-summary-item {
            text-align: center;
            padding: 15px;
            border-radius: 5px;
            flex: 1;
            transition: all 0.3s ease;
        }

        .paid-fee {
            background-color: rgba(28, 200, 138, 0.1);
            border: 1px solid var(--success-color);
        }

        .pending-fee {
            background-color: rgba(246, 194, 62, 0.1);
            border: 1px solid var(--warning-color);
        }

        .fee-amount {
            font-weight: bold;
            font-size: 1.1rem;
        }

        .dark-mode-toggle {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 1000;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
            background-color: var(--primary-color);
            color: white;
            border: none;
            transition: all 0.3s ease;
        }

        .dark-mode-toggle:hover {
            transform: scale(1.1);
        }

        .month-input-group {
            margin-bottom: 10px;
        }

        .remove-month-btn {
            transition: all 0.2s ease;
        }

        .remove-month-btn:hover {
            background-color: var(--danger-color);
            color: white;
        }

        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1100;
        }

        @media (max-width: 768px) {
            .fee-summary {
                flex-direction: column;
            }
        }

        /* Accessibility improvements */
        a:focus,
        button:focus,
        input:focus,
        select:focus,
        textarea:focus {
            outline: 2px solid var(--primary-color);
            outline-offset: 2px;
        }

        /* Print styles */
        @media print {
            body {
                background-color: white !important;
                color: black !important;
            }

            .card {
                box-shadow: none !important;
                border: 1px solid #ddd !important;
            }

            .no-print {
                display: none !important;
            }

            .dark-mode-toggle {
                display: none !important;
            }
        }
    </style>
</head>

<body>
    <div class="container py-4">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <!-- Toast Notifications -->
                <div class="toast-container">
                    <?php if (isset($_SESSION['error_message'])): ?>
                        <div class="toast show align-items-center text-white bg-danger border-0" role="alert"
                            aria-live="assertive" aria-atomic="true">
                            <div class="d-flex">
                                <div class="toast-body">
                                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                    <?= htmlspecialchars($_SESSION['error_message']) ?>
                                </div>
                                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"
                                    aria-label="Close"></button>
                            </div>
                        </div>
                        <?php unset($_SESSION['error_message']); ?>
                    <?php endif; ?>

                    <?php if (isset($_SESSION['success_message'])): ?>
                        <div class="toast show align-items-center text-white bg-success border-0" role="alert"
                            aria-live="assertive" aria-atomic="true">
                            <div class="d-flex">
                                <div class="toast-body">
                                    <i class="bi bi-check-circle-fill me-2"></i>
                                    <?= htmlspecialchars($_SESSION['success_message']) ?>
                                </div>
                                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"
                                    aria-label="Close"></button>
                            </div>
                        </div>
                        <?php unset($_SESSION['success_message']); ?>
                    <?php endif; ?>
                </div>

                <!-- Page Header -->
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h1 class="h3 mb-0">
                        <i class="bi bi-cash-stack me-2"></i> Edit Fee Payment
                    </h1>
                    <a href="fee_details.php?id=<?= $fee_id ?>" class="btn btn-outline-secondary">
                        <i class="bi bi-arrow-left me-1"></i> Back to Details
                    </a>
                </div>

                <!-- Main Card -->
                <div class="card">
                    <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                        <h2 class="h5 mb-0">Edit Fee Payment #<?= $fee_id ?></h2>
                        <span class="badge bg-light text-primary">
                            <?= htmlspecialchars($instituteName) ?>
                        </span>
                    </div>

                    <div class="card-body">
                        <!-- Fee Payment Form -->
                        <form id="feePaymentForm" action="edit_fee.php?id=<?= $fee_id ?>" method="POST" class="needs-validation"
                            novalidate>
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                            <input type="hidden" name="form_type" value="edit_fee">
                            <input type="hidden" name="institute_name" value="<?= htmlspecialchars($instituteName) ?>">

                            <!-- Student Information Section -->
                            <div class="mb-4">
                                <h3 class="section-title">
                                    <i class="bi bi-person-vcard"></i> Student Information
                                </h3>

                                <div class="row g-3">
                                    <div class="col-md-6">
                                        <label for="student_id" class="form-label required-field">Select Student</label>
                                        <select class="form-select select2-student" id="student_id" name="student_id"
                                            required>
                                            <option value="">Search student by name or ID...</option>
                                            <?php foreach ($students as $student): ?>
                                                <option value="<?= htmlspecialchars($student['student_id']) ?>"
                                                    data-paid="<?= htmlspecialchars($student['paid_amount'] ?? 0) ?>"
                                                    data-pending="<?= htmlspecialchars($student['pending_amount'] ?? 0) ?>"
                                                    <?= $student['student_id'] == $fee_data['student_id'] ? 'selected' : '' ?>>
                                                    <?= htmlspecialchars($student['first_name']) ?>
                                                    <?= htmlspecialchars($student['last_name']) ?>
                                                    (ID:
                                                    <?= htmlspecialchars($student['student_id']) ?>)
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                        <div class="invalid-feedback">Please select a student</div>
                                    </div>

                                    <div class="col-md-6">
                                        <label for="payment_date" class="form-label required-field">Payment Date</label>
                                        <input type="date" class="form-control" id="payment_date" name="payment_date"
                                            value="<?= htmlspecialchars($fee_data['payment_date']) ?>" max="<?= date('Y-m-d') ?>" required>
                                        <div class="invalid-feedback">Please select a valid payment date</div>
                                    </div>
                                </div>

                                <!-- Student Fee Summary -->
                                <div class="student-info-card mt-3" id="studentFeeInfo">
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <h4 class="h5 mb-0" id="studentName">
                                            <?= htmlspecialchars($fee_data['first_name'] . ' ' . $fee_data['last_name']) ?>
                                        </h4>
                                        <span class="badge bg-primary" id="studentIdBadge">
                                            ID: <?= htmlspecialchars($fee_data['student_id']) ?>
                                        </span>
                                    </div>
                                    <div class="fee-summary">
                                        <div class="fee-summary-item paid-fee">
                                            <div class="text-muted small">Paid Fees</div>
                                            <div class="fee-amount text-success" id="paidAmount">
                                                ₹<?= number_format($students[array_search($fee_data['student_id'], array_column($students, 'student_id'))]['paid_amount'] ?? 0, 2) ?>
                                            </div>
                                        </div>
                                        <div class="fee-summary-item pending-fee">
                                            <div class="text-muted small">Pending Fees</div>
                                            <div class="fee-amount text-warning" id="pendingAmount">
                                                ₹<?= number_format($students[array_search($fee_data['student_id'], array_column($students, 'student_id'))]['pending_amount'] ?? 0, 2) ?>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <!-- Fee Details Section -->
                            <div class="mb-4">
                                <h3 class="section-title">
                                    <i class="bi bi-cash-stack"></i> Fee Details
                                </h3>

                                <div class="row g-3">
                                    <div class="col-md-4">
                                        <label for="institute_name" class="form-label required-field">Institute
                                            Name</label>
                                        <input type="text" class="form-control" id="institute_name"
                                            name="institute_name" value="<?= htmlspecialchars($instituteName) ?>"
                                            readonly required>
                                        <div class="invalid-feedback">Please select institute</div>
                                    </div>

                                    <div class="col-md-4">
                                        <label for="total_amount" class="form-label required-field">Amount (₹)</label>
                                        <div class="input-group">
                                            <span class="input-group-text">₹</span>
                                            <input type="number" class="form-control" id="total_amount"
                                                name="total_amount" step="0.01" min="0" placeholder="0.00"
                                                value="<?= htmlspecialchars($fee_data['total_amount']) ?>" required>
                                        </div>
                                        <div class="invalid-feedback">Please enter a valid amount</div>
                                    </div>
                                </div>
                                <div class="mt-4" id="multiMonthSection">
                                    <div class="d-flex justify-content-between align-items-center mb-3">
                                        <label class="form-label mb-0">Fee Date Ranges</label>
                                        <button type="button" class="btn btn-sm btn-outline-primary" id="addMonthBtn">
                                            <i class="bi bi-plus-circle me-1"></i> Add Date Range
                                        </button>
                                    </div>
                                    <div id="monthsContainer" class="row g-2">
                                        <?php foreach ($fee_details as $detail): ?>
                                            <div class="col-md-12 month-range-group mb-3">
                                                <div class="card">
                                                    <div class="card-body">
                                                        <div class="row g-3">
                                                            <div class="col-md-4">
                                                                <label class="form-label">From Date</label>
                                                                <input type="date" class="form-control from-month"
                                                                    name="fee_from_months[]"
                                                                    value="<?= htmlspecialchars($detail['from_month']) ?>" required>
                                                            </div>
                                                            <div class="col-md-4">
                                                                <label class="form-label">To Date</label>
                                                                <input type="date" class="form-control to-month"
                                                                    name="fee_to_months[]"
                                                                    value="<?= htmlspecialchars($detail['to_month']) ?>" required>
                                                            </div>
                                                            <div class="col-md-3">
                                                                <label class="form-label">Amount (₹)</label>
                                                                <input type="number" class="form-control"
                                                                    name="fee_month_amounts[]" placeholder="0.00"
                                                                    min="0" step="0.01"
                                                                    value="<?= htmlspecialchars($detail['amount']) ?>" required>
                                                            </div>
                                                            <div class="col-md-1 d-flex align-items-end">
                                                                <button type="button" class="btn btn-outline-danger remove-month-btn" title="Remove">
                                                                    <i class="bi bi-trash"></i>
                                                                </button>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            </div>

                            <!-- Payment Information Section -->
                            <div class="mb-4">
                                <h3 class="section-title">
                                    <i class="bi bi-credit-card"></i> Payment Information
                                </h3>

                                <div class="row g-3">
                                    <div class="col-md-4">
                                        <label for="payment_method" class="form-label required-field">Payment
                                            Method</label>
                                        <select class="form-select" id="payment_method" name="payment_method" required>
                                            <option value="">Select Method</option>
                                            <option value="Cash" <?= $fee_data['payment_method'] === 'Cash' ? 'selected' : '' ?>>Cash</option>
                                            <option value="Cheque" <?= $fee_data['payment_method'] === 'Cheque' ? 'selected' : '' ?>>Cheque</option>
                                            <option value="Bank Transfer" <?= $fee_data['payment_method'] === 'Bank Transfer' ? 'selected' : '' ?>>Bank Transfer</option>
                                            <option value="Credit Card" <?= $fee_data['payment_method'] === 'Credit Card' ? 'selected' : '' ?>>Credit Card</option>
                                            <option value="Debit Card" <?= $fee_data['payment_method'] === 'Debit Card' ? 'selected' : '' ?>>Debit Card</option>
                                            <option value="UPI" <?= $fee_data['payment_method'] === 'UPI' ? 'selected' : '' ?>>UPI</option>
                                            <option value="Online Payment" <?= $fee_data['payment_method'] === 'Online Payment' ? 'selected' : '' ?>>Online Payment</option>
                                        </select>
                                        <div class="invalid-feedback">Please select payment method</div>
                                    </div>

                                    <div class="col-md-4" id="transactionIdField">
                                        <label for="transaction_id" class="form-label">Transaction ID/Reference</label>
                                        <input type="text" class="form-control" id="transaction_id"
                                            name="transaction_id" placeholder="Optional reference number"
                                            value="<?= htmlspecialchars($fee_data['transaction_id'] ?? '') ?>">
                                    </div>

                                    <div class="col-md-4">
                                        <label for="status" class="form-label required-field">Payment Status</label>
                                        <select class="form-select" id="status" name="status" required>
                                            <option value="paid" <?= $fee_data['status'] === 'paid' ? 'selected' : '' ?>>Paid</option>
                                            <option value="pending" <?= $fee_data['status'] === 'pending' ? 'selected' : '' ?>>Pending</option>
                                            <option value="partial" <?= $fee_data['status'] === 'partial' ? 'selected' : '' ?>>Partial Payment</option>
                                        </select>
                                    </div>
                                </div>

                                <div class="mt-3">
                                    <label for="notes" class="form-label">Notes</label>
                                    <textarea class="form-control" id="notes" name="notes" rows="2"
                                        placeholder="Any additional information about this payment"><?= htmlspecialchars($fee_data['remarks'] ?? '') ?></textarea>
                                </div>
                            </div>

                            <!-- Form Actions -->
                            <div class="d-flex justify-content-between align-items-center pt-3 border-top">
                                <button type="reset" class="btn btn-outline-secondary">
                                    <i class="bi bi-arrow-counterclockwise me-1"></i> Reset Form
                                </button>
                                <div>
                                    <button type="button" class="btn btn-outline-info me-2" id="printFormBtn">
                                        <i class="bi bi-printer me-1"></i> Print
                                    </button>
                                    <button type="submit" class="btn btn-primary" id="submitBtn">
                                        <i class="bi bi-save me-1"></i> Update Fee Payment
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Dark Mode Toggle Button -->
    <button class="dark-mode-toggle" id="darkModeToggle" aria-label="Toggle dark mode">
        <i class="bi bi-moon-fill"></i>
    </button>

    <!-- JavaScript Libraries -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"
        crossorigin="anonymous"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>

    <script>
        // Document ready function
        $(document).ready(function() {
            // Initialize Select2 for student dropdown
            $('.select2-student').select2({
                placeholder: "Search student by name or ID...",
                width: '100%',
                theme: 'bootstrap-5',
                minimumInputLength: 1,
                allowClear: true,
                dropdownParent: $('#feePaymentForm')
            });

            // Initialize dark mode from localStorage or system preference
            initDarkMode();

            // Initialize form validation and event handlers
            initFormHandlers();

            // Auto-hide toasts after 5 seconds
            setTimeout(() => {
                $('.toast').toast('hide');
            }, 5000);
        });

        // Initialize form validation and event handlers
        function initFormHandlers() {
            // Student selection change handler
            $('#student_id').on('change', function() {
                const selectedOption = this.options[this.selectedIndex];
                const studentInfo = $('#studentFeeInfo');

                if (this.value) {
                    const studentName = selectedOption.text.split('(ID:')[0].trim();
                    const studentId = this.value;
                    const paidAmount = parseFloat(selectedOption.getAttribute('data-paid')) || 0;
                    const pendingAmount = parseFloat(selectedOption.getAttribute('data-pending')) || 0;

                    $('#studentName').text(studentName);
                    $('#studentIdBadge').text('ID: ' + studentId);
                    $('#paidAmount').text('₹' + paidAmount.toFixed(2));
                    $('#pendingAmount').text('₹' + pendingAmount.toFixed(2));

                    studentInfo.fadeIn();
                } else {
                    studentInfo.fadeOut();
                }
            }).trigger('change');

            // Payment method change handler
            $('#payment_method').on('change', function() {
                const txnField = $('#transactionIdField');
                const onlineMethods = ['Bank Transfer', 'Credit Card', 'Debit Card', 'UPI', 'Online Payment'];

                if (onlineMethods.includes(this.value)) {
                    txnField.show();
                    $('#transaction_id').prop('required', true);
                } else {
                    txnField.hide();
                    $('#transaction_id').prop('required', false).val('');
                }
            }).trigger('change');

            // Add month range button handler
            $('#addMonthBtn').on('click', function() {
                const monthInput = `
                    <div class="col-md-12 month-range-group mb-3">
                        <div class="card">
                            <div class="card-body">
                                <div class="row g-3">
                                    <div class="col-md-4">
                                        <label class="form-label">From Date</label>
                                        <input type="date" class="form-control from-month" name="fee_from_months[]" required>
                                    </div>
                                    <div class="col-md-4">
                                        <label class="form-label">To Date</label>
                                        <input type="date" class="form-control to-month" name="fee_to_months[]" required>
                                    </div>
                                    <div class="col-md-3">
                                        <label class="form-label">Amount (₹)</label>
                                        <input type="number" class="form-control" name="fee_month_amounts[]"
                                            placeholder="0.00" min="0" step="0.01" required>
                                    </div>
                                    <div class="col-md-1 d-flex align-items-end">
                                        <button type="button" class="btn btn-outline-danger remove-month-btn" title="Remove">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;

                $('#monthsContainer').append(monthInput);

                // Set default dates (current month)
                const today = new Date();
                const firstDay = new Date(today.getFullYear(), today.getMonth(), 1);
                const lastDay = new Date(today.getFullYear(), today.getMonth() + 1, 0);

                const $newGroup = $('#monthsContainer .month-range-group:last');
                $newGroup.find('.from-month').val(formatDate(firstDay));
                $newGroup.find('.to-month').val(formatDate(lastDay));

                // Add date validation
                $newGroup.find('.to-month').on('change', function() {
                    validateDateRange($newGroup);
                });

                $newGroup.find('.from-month').on('change', function() {
                    validateDateRange($newGroup);
                });

                // Focus on the first field
                $newGroup.find('.from-month').focus();
            });

            // Remove month button handler (delegated)
            $('#monthsContainer').on('click', '.remove-month-btn', function() {
                $(this).closest('.month-range-group').remove();
                calculateTotalFromMonths();
            });

            // Validate existing month ranges on load
            $('.month-range-group').each(function() {
                const $group = $(this);
                validateDateRange($group);
            });

            // Auto-calculate total from month amounts
            $('#monthsContainer').on('blur', 'input[name="fee_month_amounts[]"]', function() {
                calculateTotalFromMonths();
            });

            // Calculate initial total from existing month amounts
            calculateTotalFromMonths();

            // Print form button
            $('#printFormBtn').on('click', function() {
                window.print();
            });

            // Form submission handler
            $('#feePaymentForm').on('submit', function(e) {
                // Validate all date ranges first
                let isValid = true;
                $('.month-range-group').each(function() {
                    const $group = $(this);
                    validateDateRange($group);
                    if ($group.find('.is-invalid').length > 0) {
                        isValid = false;
                    }
                });

                if (!isValid || !this.checkValidity()) {
                    e.preventDefault();
                    e.stopPropagation();

                    // Scroll to the first invalid field
                    const firstInvalid = $(this).find(':invalid').first();
                    if (firstInvalid.length) {
                        $('html, body').animate({
                            scrollTop: firstInvalid.offset().top - 100
                        }, 500);
                        firstInvalid.focus();
                    }
                } else {
                    // Disable submit button to prevent double submission
                    $('#submitBtn').prop('disabled', true).html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...');
                }

                $(this).addClass('was-validated');
            });

            // Auto-format amount input
            $('#total_amount').on('blur', function() {
                if (this.value) {
                    this.value = parseFloat(this.value).toFixed(2);
                }
            });
        }

        // Helper function to format date as YYYY-MM-DD
        function formatDate(date) {
            const year = date.getFullYear();
            const month = String(date.getMonth() + 1).padStart(2, '0');
            const day = String(date.getDate()).padStart(2, '0');
            return `${year}-${month}-${day}`;
        }

        // Validate that from date <= to date
        function validateDateRange($group) {
            const fromDate = $group.find('.from-month').val();
            const toDate = $group.find('.to-month').val();

            if (fromDate && toDate && new Date(fromDate) > new Date(toDate)) {
                $group.find('.to-month')[0].setCustomValidity('To date must be after from date');
                $group.find('.to-month').addClass('is-invalid');
            } else {
                $group.find('.to-month')[0].setCustomValidity('');
                $group.find('.to-month').removeClass('is-invalid');
            }
        }

        // Calculate total from month amounts
        function calculateTotalFromMonths() {
            let total = 0;
            $('input[name="fee_month_amounts[]"]').each(function() {
                const amount = parseFloat($(this).val()) || 0;
                total += amount;
            });

            if (total > 0) {
                $('#total_amount').val(total.toFixed(2));
            }
        }

        // Dark mode functionality
        function initDarkMode() {
            const darkModeToggle = $('#darkModeToggle');
            const htmlElement = document.documentElement;

            // Check for saved preference or use OS preference
            const savedTheme = localStorage.getItem('theme') ||
                (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

            // Apply the saved theme
            if (savedTheme === 'dark') {
                htmlElement.setAttribute('data-bs-theme', 'dark');
                darkModeToggle.html('<i class="bi bi-sun-fill"></i>');
            } else {
                htmlElement.removeAttribute('data-bs-theme');
                darkModeToggle.html('<i class="bi bi-moon-fill"></i>');
            }

            // Watch for system theme changes
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
                if (!localStorage.getItem('theme')) {
                    if (e.matches) {
                        htmlElement.setAttribute('data-bs-theme', 'dark');
                        darkModeToggle.html('<i class="bi bi-sun-fill"></i>');
                    } else {
                        htmlElement.removeAttribute('data-bs-theme');
                        darkModeToggle.html('<i class="bi bi-moon-fill"></i>');
                    }
                }
            });

            // Toggle dark mode
            darkModeToggle.on('click', function() {
                const html = document.documentElement;
                const isDark = html.getAttribute('data-bs-theme') === 'dark';

                if (isDark) {
                    html.removeAttribute('data-bs-theme');
                    localStorage.setItem('theme', 'light');
                    $(this).html('<i class="bi bi-moon-fill"></i>');
                } else {
                    html.setAttribute('data-bs-theme', 'dark');
                    localStorage.setItem('theme', 'dark');
                    $(this).html('<i class="bi bi-sun-fill"></i>');
                }
            });
        }
    </script>
</body>

</html>