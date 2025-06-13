-- USERS TABLE
CREATE TABLE `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100) NOT NULL UNIQUE,
    `phone` VARCHAR(15) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `role` ENUM('admin','office','student','teacher') NOT NULL,
    `institute_name` VARCHAR(100),
    `status` ENUM('active','inactive') DEFAULT 'active',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- INSTITUTES TABLE
CREATE TABLE `institutes` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(100) NOT NULL UNIQUE,
    `address` VARCHAR(255) NOT NULL,
    `phone` VARCHAR(15) NOT NULL,
    `email` VARCHAR(100),
    `office_incharge_name` VARCHAR(100),            -- New: Name of the Office Incharge
    `office_incharge_contact` VARCHAR(15), 
    `status` ENUM('active','inactive') DEFAULT 'active',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- STUDENT DATA TABLE
CREATE TABLE `student_data` (
    `student_id` INT AUTO_INCREMENT PRIMARY KEY,
    `first_name` VARCHAR(100) NOT NULL,
    `last_name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100) NOT NULL,
    `phone` VARCHAR(15) NOT NULL,
    `dob` DATE NOT NULL,
    `gender` VARCHAR(10) NOT NULL,
    `photo_path` VARCHAR(255),
    `address` VARCHAR(255) NOT NULL,
    `course` VARCHAR(100) NOT NULL,
    `school_type` VARCHAR(50),
    `school` VARCHAR(100),
    `parent_name` VARCHAR(100) NOT NULL,
    `parent_phone` VARCHAR(15) NOT NULL,
    `Referred_by_About` VARCHAR(100),
    `Admission_Accpted_by` VARCHAR(100),
    `institute_name` VARCHAR(100) NOT NULL,
    `status` VARCHAR(20) NOT NULL,
    `Admission_code` VARCHAR(50) NOT NULL,
    `admission_date` DATE DEFAULT CURRENT_DATE,
    `is_active` TINYINT(1) DEFAULT 1,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- FEES TABLE
CREATE TABLE `fees` (
    `fee_id` INT AUTO_INCREMENT PRIMARY KEY,
    `student_id` INT NOT NULL,
    `student_name` VARCHAR(200),
    `total_amount` DECIMAL(10,2) NOT NULL,
    `payment_method` VARCHAR(50),
    `transaction_id` VARCHAR(100)  DEFAULT NULL,
    `payment_date` DATETIME NOT NULL,
    `status` ENUM('paid','pending') DEFAULT 'paid',
    `remarks` TEXT,
    FOREIGN KEY (`student_id`) REFERENCES `student_data`(`student_id`)
);

CREATE TABLE `fee_details` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `fee_id` INT NOT NULL,
    `from_month` DATE NOT NULL,         -- e.g., '2025-06-01'
    `to_month` DATE NOT NULL,           -- e.g., '2025-08-01'
    `amount` DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (`fee_id`) REFERENCES `fees`(`fee_id`) ON DELETE CASCADE
);



-- BATCHES TABLE
CREATE TABLE `batches` (
    `batch_id` INT AUTO_INCREMENT PRIMARY KEY,
    `institute_name` VARCHAR(100) NOT NULL,
    `batch_name` VARCHAR(100) NOT NULL,
    `batch_code` VARCHAR(50) NOT NULL,
    `course` VARCHAR(100),
    `start_date` DATE,
    `end_date` DATE,
    `status` ENUM('Active','Inactive') DEFAULT 'Active'
);

-- TEACHERS TABLE
CREATE TABLE `teachers` (
    `teacher_id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100),
    `phone` VARCHAR(15),
    `address` VARCHAR(255),                            -- New: Full address of the teacher
    `subject` VARCHAR(100),                            -- New: Subject specialization
    `qualification` VARCHAR(100),                      -- New: Highest qualification
    `photo` VARCHAR(255),                              -- New: Path or URL to teacher's photo
    `resume` VARCHAR(255),                             -- New: Path or URL to uploaded resume
    `status` ENUM('active', 'inactive') DEFAULT 'active', -- New: Current employment status
    `joining_date` DATE,                               -- New: Date of joining
`institute_id` INT,
FOREIGN KEY (`institute_id`) REFERENCES `institutes`(`id`)

);


-- BATCH_TEACHERS TABLE
CREATE TABLE `batch_teachers` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `batch_id` INT NOT NULL,
    `teacher_id` INT NOT NULL,
    FOREIGN KEY (`batch_id`) REFERENCES `batches`(`batch_id`),
    FOREIGN KEY (`teacher_id`) REFERENCES `teachers`(`teacher_id`)
);

-- BATCH_STUDENTS TABLE
CREATE TABLE `batch_students` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `batch_id` INT NOT NULL,
    `student_id` INT NOT NULL,
    `status` ENUM('active','inactive') DEFAULT 'active',
    FOREIGN KEY (`batch_id`) REFERENCES `batches`(`batch_id`),
    FOREIGN KEY (`student_id`) REFERENCES `student_data`(`student_id`)
);

-- ATTENDANCE TABLE
CREATE TABLE `attendance` (
    `attendance_id` INT AUTO_INCREMENT PRIMARY KEY,
    `student_id` INT NOT NULL,
    `batch_id` INT,
    `date` DATE NOT NULL,
    `status` ENUM('present','absent','late','half_day') NOT NULL,
    `notes` VARCHAR(255),
    `recorded_time` TIME DEFAULT CURRENT_TIME,
    FOREIGN KEY (`student_id`) REFERENCES `student_data`(`student_id`),
    FOREIGN KEY (`batch_id`) REFERENCES `batches`(`batch_id`)
);

CREATE TABLE `inquiries` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `role` ENUM('student','teacher') NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100) NOT NULL,
    `phone` VARCHAR(20) NOT NULL,
    `subjects` VARCHAR(255) NOT NULL,
    `grade` VARCHAR(50), -- For students
    `qualification` VARCHAR(100), -- For teachers
    `preferred_time` VARCHAR(100), -- For teachers
    `message` TEXT, -- For teachers
    `cv_file` VARCHAR(255), -- For teachers (filename)
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);