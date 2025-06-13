<?php
require_once 'config.php';

// Get summary data
$summaryStmt = $pdo->query("
    SELECT 
        date,
        SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) as present_count,
        SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) as absent_count,
        SUM(CASE WHEN status = 'late' THEN 1 ELSE 0 END) as late_count,
        SUM(CASE WHEN status = 'half_day' THEN 1 ELSE 0 END) as half_day_count,
        COUNT(*) as total
    FROM attendance
    GROUP BY date
    ORDER BY date DESC
");
$summaryData = $summaryStmt->fetchAll(PDO::FETCH_ASSOC);

// Get user type distribution
$userTypeStmt = $pdo->query("
    SELECT 
        user_type,
        COUNT(*) as count
    FROM attendance
    GROUP BY user_type
");
$userTypeData = $userTypeStmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attendance Summary</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container mt-5">
        <h1 class="mb-4">Attendance Summary</h1>
        
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="card-title">Daily Attendance Overview</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="dailyChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="card-title">User Type Distribution</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="userTypeChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="card-title">Detailed Summary</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>Present</th>
                                <th>Absent</th>
                                <th>Late</th>
                                <th>Half Day</th>
                                <th>Total</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($summaryData as $row): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($row['date']); ?></td>
                                    <td><?php echo htmlspecialchars($row['present_count']); ?></td>
                                    <td><?php echo htmlspecialchars($row['absent_count']); ?></td>
                                    <td><?php echo htmlspecialchars($row['late_count']); ?></td>
                                    <td><?php echo htmlspecialchars($row['half_day_count']); ?></td>
                                    <td><?php echo htmlspecialchars($row['total']); ?></td>
                                    <td>
                                        <a href="attendance_view.php?date=<?php echo $row['date']; ?>" class="btn btn-sm btn-outline-primary">
                                            View Details
                                        </a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Daily Attendance Chart
        const dailyCtx = document.getElementById('dailyChart').getContext('2d');
        const dailyChart = new Chart(dailyCtx, {
            type: 'bar',
            data: {
                labels: <?php echo json_encode(array_column($summaryData, 'date')); ?>,
                datasets: [
                    {
                        label: 'Present',
                        data: <?php echo json_encode(array_column($summaryData, 'present_count')); ?>,
                        backgroundColor: 'rgba(40, 167, 69, 0.7)'
                    },
                    {
                        label: 'Absent',
                        data: <?php echo json_encode(array_column($summaryData, 'absent_count')); ?>,
                        backgroundColor: 'rgba(220, 53, 69, 0.7)'
                    },
                    {
                        label: 'Late',
                        data: <?php echo json_encode(array_column($summaryData, 'late_count')); ?>,
                        backgroundColor: 'rgba(255, 193, 7, 0.7)'
                    },
                    {
                        label: 'Half Day',
                        data: <?php echo json_encode(array_column($summaryData, 'half_day_count')); ?>,
                        backgroundColor: 'rgba(108, 117, 125, 0.7)'
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    x: {
                        stacked: true
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true
                    }
                }
            }
        });

        // User Type Distribution Chart
        const userTypeCtx = document.getElementById('userTypeChart').getContext('2d');
        const userTypeChart = new Chart(userTypeCtx, {
            type: 'pie',
            data: {
                labels: <?php echo json_encode(array_column($userTypeData, 'user_type')); ?>,
                datasets: [{
                    data: <?php echo json_encode(array_column($userTypeData, 'count')); ?>,
                    backgroundColor: [
                        'rgba(0, 123, 255, 0.7)',
                        'rgba(23, 162, 184, 0.7)',
                        'rgba(111, 66, 193, 0.7)',
                        'rgba(253, 126, 20, 0.7)'
                    ]
                }]
            },
            options: {
                responsive: true
            }
        });
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>