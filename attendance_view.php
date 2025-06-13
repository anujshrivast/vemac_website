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

// Validate and sanitize input
function sanitizeInput($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

// Pagination configuration
$limit = 20;
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$offset = ($page - 1) * $limit;

// Initialize filter variables with sanitized values
$filters = [
    'user_type' => $_GET['user_type'] ?? '',
    'date_from' => $_GET['date_from'] ?? '',
    'date_to' => $_GET['date_to'] ?? '',
    'status' => $_GET['status'] ?? ''
];

// Validate date range
if (!empty($filters['date_from']) && !empty($filters['date_to'])) {
    if (strtotime($filters['date_from']) > strtotime($filters['date_to'])) {
        $temp = $filters['date_from'];
        $filters['date_from'] = $filters['date_to'];
        $filters['date_to'] = $temp;
    }
}

// Build base SQL query
$base_sql = "SELECT * FROM attendance WHERE 1=1";
$count_sql = "SELECT COUNT(*) FROM attendance WHERE 1=1";
$params = [];
$count_params = [];

// Apply filters
$filter_clauses = [];
$valid_user_types = ['student', 'teacher', 'staff', 'office_incharge'];
$valid_statuses = ['present', 'absent', 'late', 'half_day'];

if (!empty($filters['user_type']) && in_array($filters['user_type'], $valid_user_types)) {
    $filter_clauses[] = "user_type = ?";
    $params[] = $filters['user_type'];
    $count_params[] = $filters['user_type'];
}

if (!empty($filters['date_from'])) {
    $filter_clauses[] = "date >= ?";
    $params[] = $filters['date_from'];
    $count_params[] = $filters['date_from'];
}

if (!empty($filters['date_to'])) {
    $filter_clauses[] = "date <= ?";
    $params[] = $filters['date_to'];
    $count_params[] = $filters['date_to'];
}

if (!empty($filters['status']) && in_array($filters['status'], $valid_statuses)) {
    $filter_clauses[] = "status = ?";
    $params[] = $filters['status'];
    $count_params[] = $filters['status'];
}

// Add WHERE clauses if filters exist
if (!empty($filter_clauses)) {
    $where_clause = " AND " . implode(" AND ", $filter_clauses);
    $base_sql .= $where_clause;
    $count_sql .= $where_clause;
}

// Add sorting and pagination
$order_sql = " ORDER BY date DESC, recorded_time DESC LIMIT ? OFFSET ?";
$sql = $base_sql . $order_sql;
$params[] = $limit;
$params[] = $offset;

// Execute main query
try {
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $attendances = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get total records count
    $count_stmt = $pdo->prepare($count_sql);
    $count_stmt->execute($count_params);
    $total_records = $count_stmt->fetchColumn();
    $total_pages = max(1, ceil($total_records / $limit));
} catch (PDOException $e) {
    error_log("Database error: " . $e->getMessage());
    $attendances = [];
    $total_records = 0;
    $total_pages = 1;
}

// Generate pagination URL
function getPaginationUrl($page) {
    $query = $_GET;
    $query['page'] = $page;
    return '?' . http_build_query($query);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View Attendance</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        .status-badge {
            min-width: 80px;
            display: inline-block;
            text-align: center;
        }
        .table-responsive {
            overflow-x: auto;
        }
        .pagination .page-item.active .page-link {
            background-color: #0d6efd;
            border-color: #0d6efd;
        }
        .action-buttons {
            white-space: nowrap;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <h2 class="mb-4">Attendance Records</h2>
        
        <!-- Filter Form -->
        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0">Filters</h5>
            </div>
            <div class="card-body">
                <form method="get" class="row g-3">
                    <div class="col-md-3">
                        <label for="user_type" class="form-label">User Type</label>
                        <select class="form-select" id="user_type" name="user_type">
                            <option value="">All Types</option>
                            <option value="student" <?= $filters['user_type'] === 'student' ? 'selected' : '' ?>>Student</option>
                            <option value="teacher" <?= $filters['user_type'] === 'teacher' ? 'selected' : '' ?>>Teacher</option>
                            <option value="staff" <?= $filters['user_type'] === 'staff' ? 'selected' : '' ?>>Staff</option>
                            <option value="office_incharge" <?= $filters['user_type'] === 'office_incharge' ? 'selected' : '' ?>>Office Incharge</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label for="status" class="form-label">Status</label>
                        <select class="form-select" id="status" name="status">
                            <option value="">All Statuses</option>
                            <option value="present" <?= $filters['status'] === 'present' ? 'selected' : '' ?>>Present</option>
                            <option value="absent" <?= $filters['status'] === 'absent' ? 'selected' : '' ?>>Absent</option>
                            <option value="late" <?= $filters['status'] === 'late' ? 'selected' : '' ?>>Late</option>
                            <option value="half_day" <?= $filters['status'] === 'half_day' ? 'selected' : '' ?>>Half Day</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label for="date_from" class="form-label">From Date</label>
                        <input type="date" class="form-control" id="date_from" name="date_from" 
                               value="<?= htmlspecialchars($filters['date_from']) ?>" max="<?= date('Y-m-d') ?>">
                    </div>
                    <div class="col-md-3">
                        <label for="date_to" class="form-label">To Date</label>
                        <input type="date" class="form-control" id="date_to" name="date_to" 
                               value="<?= htmlspecialchars($filters['date_to']) ?>" max="<?= date('Y-m-d') ?>">
                    </div>
                    <div class="col-12">
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-funnel"></i> Apply Filters
                        </button>
                        <a href="view_attendance.php" class="btn btn-outline-secondary">
                            <i class="bi bi-arrow-counterclockwise"></i> Reset
                        </a>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Attendance Table -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center bg-light">
                <h5 class="mb-0">Attendance Records</h5>
                <div>
                    <a href="add_attendance.php" class="btn btn-success">
                        <i class="bi bi-plus-circle"></i> Add New
                    </a>
                    <button class="btn btn-outline-primary" id="export-btn">
                        <i class="bi bi-download"></i> Export
                    </button>
                </div>
            </div>
            <div class="card-body">
                <?php if (empty($attendances)): ?>
                    <div class="alert alert-info">No attendance records found.</div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover table-bordered">
                            <thead class="table-dark">
                                <tr>
                                    <th>ID</th>
                                    <th>User Type</th>
                                    <th>User ID</th>
                                    <th>Batch ID</th>
                                    <th>Date</th>
                                    <th>Status</th>
                                    <th>Recorded Time</th>
                                    <th>Notes</th>
                                    <th class="action-buttons">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($attendances as $attendance): ?>
                                <tr>
                                    <td><?= htmlspecialchars($attendance['attendance_id']) ?></td>
                                    <td><?= ucwords(str_replace('_', ' ', htmlspecialchars($attendance['user_type']))) ?></td>
                                    <td><?= htmlspecialchars($attendance['user_id']) ?></td>
                                    <td><?= $attendance['batch_id'] ? htmlspecialchars($attendance['batch_id']) : '-' ?></td>
                                    <td><?= date('M j, Y', strtotime($attendance['date'])) ?></td>
                                    <td>
                                        <?php 
                                            $status_class = [
                                                'present' => 'bg-success',
                                                'absent' => 'bg-danger',
                                                'late' => 'bg-warning text-dark',
                                                'half_day' => 'bg-info'
                                            ][$attendance['status']] ?? 'bg-secondary';
                                        ?>
                                        <span class="badge rounded-pill status-badge <?= $status_class ?>">
                                            <?= ucfirst(htmlspecialchars($attendance['status'])) ?>
                                        </span>
                                    </td>
                                    <td><?= date('h:i A', strtotime($attendance['recorded_time'])) ?></td>
                                    <td><?= $attendance['notes'] ? htmlspecialchars($attendance['notes']) : '-' ?></td>
                                    <td class="action-buttons">
                                        <a href="edit_attendance.php?id=<?= $attendance['attendance_id'] ?>" 
                                           class="btn btn-sm btn-primary" title="Edit">
                                            <i class="bi bi-pencil"></i>
                                        </a>
                                        <button class="btn btn-sm btn-danger delete-btn" 
                                                data-id="<?= $attendance['attendance_id'] ?>" title="Delete">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                        <a href="attendance_details.php?id=<?= $attendance['attendance_id'] ?>" 
                                           class="btn btn-sm btn-info" title="View Details">
                                            <i class="bi bi-eye"></i>
                                        </a>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    
                    <!-- Pagination -->
                    <?php if ($total_pages > 1): ?>
                    <nav aria-label="Page navigation">
                        <ul class="pagination justify-content-center mt-4">
                            <li class="page-item <?= $page <= 1 ? 'disabled' : '' ?>">
                                <a class="page-link" href="<?= getPaginationUrl(1) ?>" aria-label="First">
                                    <span aria-hidden="true">&laquo;&laquo;</span>
                                </a>
                            </li>
                            <li class="page-item <?= $page <= 1 ? 'disabled' : '' ?>">
                                <a class="page-link" href="<?= getPaginationUrl($page - 1) ?>" aria-label="Previous">
                                    <span aria-hidden="true">&laquo;</span>
                                </a>
                            </li>
                            
                            <?php 
                                // Show limited pagination links
                                $start_page = max(1, $page - 2);
                                $end_page = min($total_pages, $page + 2);
                                
                                if ($start_page > 1) {
                                    echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                                }
                                
                                for ($i = $start_page; $i <= $end_page; $i++): 
                            ?>
                                <li class="page-item <?= $i === $page ? 'active' : '' ?>">
                                    <a class="page-link" href="<?= getPaginationUrl($i) ?>"><?= $i ?></a>
                                </li>
                            <?php 
                                endfor;
                                
                                if ($end_page < $total_pages) {
                                    echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                                }
                            ?>
                            
                            <li class="page-item <?= $page >= $total_pages ? 'disabled' : '' ?>">
                                <a class="page-link" href="<?= getPaginationUrl($page + 1) ?>" aria-label="Next">
                                    <span aria-hidden="true">&raquo;</span>
                                </a>
                            </li>
                            <li class="page-item <?= $page >= $total_pages ? 'disabled' : '' ?>">
                                <a class="page-link" href="<?= getPaginationUrl($total_pages) ?>" aria-label="Last">
                                    <span aria-hidden="true">&raquo;&raquo;</span>
                                </a>
                            </li>
                        </ul>
                    </nav>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div class="modal fade" id="deleteModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header bg-danger text-white">
                    <h5 class="modal-title" id="deleteModalLabel">Confirm Deletion</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete this attendance record? This action cannot be undone.</p>
                    <p class="fw-bold">This will permanently remove the record from the system.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                        <i class="bi bi-x-circle"></i> Cancel
                    </button>
                    <a href="#" class="btn btn-danger" id="confirm-delete">
                        <i class="bi bi-trash"></i> Delete
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Export Modal -->
    <div class="modal fade" id="exportModal" tabindex="-1" aria-labelledby="exportModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header bg-primary text-white">
                    <h5 class="modal-title" id="exportModalLabel">Export Attendance Data</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="exportForm" method="post" action="export_attendance.php">
                        <div class="mb-3">
                            <label for="exportFormat" class="form-label">Format</label>
                            <select class="form-select" id="exportFormat" name="format">
                                <option value="csv">CSV</option>
                                <option value="excel">Excel</option>
                                <option value="pdf">PDF</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label for="exportColumns" class="form-label">Columns to Include</label>
                            <select class="form-select" id="exportColumns" name="columns[]" multiple>
                                <option value="attendance_id" selected>ID</option>
                                <option value="user_type" selected>User Type</option>
                                <option value="user_id" selected>User ID</option>
                                <option value="batch_id" selected>Batch ID</option>
                                <option value="date" selected>Date</option>
                                <option value="status" selected>Status</option>
                                <option value="recorded_time" selected>Recorded Time</option>
                                <option value="notes" selected>Notes</option>
                            </select>
                        </div>
                        <input type="hidden" name="filters" value="<?= htmlspecialchars(json_encode($filters)) ?>">
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" form="exportForm" class="btn btn-primary">
                        <i class="bi bi-download"></i> Export
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function() {
            // Delete button click handler
            $('.delete-btn').click(function() {
                var id = $(this).data('id');
                $('#confirm-delete').attr('href', 'delete_attendance.php?id=' + id);
                $('#deleteModal').modal('show');
            });
            
            // Export button click handler
            $('#export-btn').click(function() {
                $('#exportModal').modal('show');
            });
            
            // Date validation
            $('#date_from, #date_to').change(function() {
                const fromDate = $('#date_from').val();
                const toDate = $('#date_to').val();
                
                if (fromDate && toDate && new Date(fromDate) > new Date(toDate)) {
                    alert('From date cannot be after To date. Dates will be swapped.');
                    $('#date_from').val(toDate);
                    $('#date_to').val(fromDate);
                }
            });
            
            // Make table rows clickable
            $('tbody tr').click(function(e) {
                // Don't navigate if clicking on action buttons
                if ($(e.target).closest('a, button').length === 0) {
                    window.location = $(this).find('a[title="View Details"]').attr('href');
                }
            }).css('cursor', 'pointer');
        });
    </script>
</body>
</html>