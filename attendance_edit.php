<?php
require_once 'config.php';

if (!isset($_GET['id'])) {
    header('Location: attendance_view.php');
    exit();
}

$attendance_id = $_GET['id'];

// Fetch the record to edit
$stmt = $pdo->prepare("SELECT * FROM attendance WHERE attendance_id = ?");
$stmt->execute([$attendance_id]);
$attendance = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$attendance) {
    header('Location: attendance_view.php');
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $stmt = $pdo->prepare("UPDATE attendance SET 
                              user_type = :user_type, 
                              user_id = :user_id, 
                              batch_id = :batch_id, 
                              date = :date, 
                              status = :status, 
                              notes = :notes 
                              WHERE attendance_id = :attendance_id");
        
        $stmt->execute([
            ':user_type' => $_POST['user_type'],
            ':user_id' => $_POST['user_id'],
            ':batch_id' => $_POST['batch_id'] ?: null,
            ':date' => $_POST['date'],
            ':status' => $_POST['status'],
            ':notes' => $_POST['notes'] ?: null,
            ':attendance_id' => $attendance_id
        ]);
        
        header('Location: attendance_view.php?success=1');
        exit();
    } catch (PDOException $e) {
        $error = "Error updating attendance record: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Attendance Record</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="mb-4">Edit Attendance Record</h1>
        
        <?php if (isset($error)): ?>
            <div class="alert alert-danger"><?php echo $error; ?></div>
        <?php endif; ?>
        
        <form method="POST">
            <div class="row mb-3">
                <div class="col-md-6">
                    <label for="user_type" class="form-label">User Type</label>
                    <select class="form-select" id="user_type" name="user_type" required>
                        <option value="student" <?php echo $attendance['user_type'] === 'student' ? 'selected' : ''; ?>>Student</option>
                        <option value="teacher" <?php echo $attendance['user_type'] === 'teacher' ? 'selected' : ''; ?>>Teacher</option>
                        <option value="staff" <?php echo $attendance['user_type'] === 'staff' ? 'selected' : ''; ?>>Staff</option>
                        <option value="office_incharge" <?php echo $attendance['user_type'] === 'office_incharge' ? 'selected' : ''; ?>>Office Incharge</option>
                    </select>
                </div>
                <div class="col-md-6">
                    <label for="user_id" class="form-label">User ID</label>
                    <input type="number" class="form-control" id="user_id" name="user_id" value="<?php echo htmlspecialchars($attendance['user_id']); ?>" required>
                </div>
            </div>
            
            <div class="row mb-3">
                <div class="col-md-6">
                    <label for="batch_id" class="form-label">Batch ID (Optional)</label>
                    <input type="number" class="form-control" id="batch_id" name="batch_id" value="<?php echo htmlspecialchars($attendance['batch_id'] ?? ''); ?>">
                </div>
                <div class="col-md-6">
                    <label for="date" class="form-label">Date</label>
                    <input type="date" class="form-control" id="date" name="date" value="<?php echo htmlspecialchars($attendance['date']); ?>" required>
                </div>
            </div>
            
            <div class="row mb-3">
                <div class="col-md-6">
                    <label for="status" class="form-label">Status</label>
                    <select class="form-select" id="status" name="status" required>
                        <option value="present" <?php echo $attendance['status'] === 'present' ? 'selected' : ''; ?>>Present</option>
                        <option value="absent" <?php echo $attendance['status'] === 'absent' ? 'selected' : ''; ?>>Absent</option>
                        <option value="late" <?php echo $attendance['status'] === 'late' ? 'selected' : ''; ?>>Late</option>
                        <option value="half_day" <?php echo $attendance['status'] === 'half_day' ? 'selected' : ''; ?>>Half Day</option>
                    </select>
                </div>
                <div class="col-md-6">
                    <label for="notes" class="form-label">Notes (Optional)</label>
                    <input type="text" class="form-control" id="notes" name="notes" value="<?php echo htmlspecialchars($attendance['notes'] ?? ''); ?>">
                </div>
            </div>
            
            <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                <a href="attendance_view.php" class="btn btn-secondary me-md-2">Cancel</a>
                <button type="submit" class="btn btn-primary">Update Record</button>
            </div>
        </form>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>