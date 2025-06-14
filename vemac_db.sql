-- USERS TABLE
CREATE TABLE `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100) NOT NULL UNIQUE,
    `phone` VARCHAR(15) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `role` ENUM('admin','office','student','teacher') NOT NULL,
    `institute_id` INT,
    `status` ENUM('active','inactive') DEFAULT 'active',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`institute_id`) REFERENCES `institutes`(`id`)
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
    `institute_id` INT NOT NULL,
    `status` VARCHAR(20) NOT NULL,
    `Admission_code` VARCHAR(50) NOT NULL,
    `admission_date` DATE DEFAULT CURRENT_DATE,
    `is_active` TINYINT(1) DEFAULT 1,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`institute_id`) REFERENCES `institutes`(`id`)
);

-- BATCHES TABLE
CREATE TABLE `batches` (
    `batch_id` INT AUTO_INCREMENT PRIMARY KEY,
    `institute_id` INT NOT NULL,
    `batch_name` VARCHAR(100) NOT NULL,
    `batch_code` VARCHAR(50) NOT NULL,
    `course` VARCHAR(100),
    `start_date` DATE,
    `end_date` DATE,
    `status` ENUM('Active','Inactive') DEFAULT 'Active',
    FOREIGN KEY (`institute_id`) REFERENCES `institutes`(`id`)
);
