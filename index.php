<?php
include 'db_connect.php';


// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize and validate input data
    $name = htmlspecialchars($_POST['name']);
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $phone = preg_replace('/[^0-9]/', '', $_POST['phone']); // Remove non-numeric characters
    $subjects = htmlspecialchars($_POST['subjects']);
    $role = $_POST['role']; // Corrected field name

    // Validate required fields
    if (empty($name) || empty($email) || empty($phone) || empty($subjects) || empty($role)) {
        die("All fields are required.");
    }

    // Prepare SQL query based on role
    if ($role === 'student') {
        $grade = isset($_POST['grade']) ? htmlspecialchars($_POST['grade']) : null;
        $sql = "INSERT INTO inquiries (role, name, email, phone, subjects, grade) VALUES (:role, :name, :email, :phone, :subjects, :grade)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':grade', $grade);
    } elseif ($role === 'teacher') {
        $qualification = isset($_POST['qualification']) ? htmlspecialchars($_POST['qualification']) : null;
        $preferredTime = isset($_POST['preferred_time']) ? $_POST['preferred_time'] : null;
        $message = isset($_POST['message']) ? htmlspecialchars($_POST['message']) : null;
        $cv = null;

        // Handle file upload if a file was provided
        if (isset($_FILES['cv']) && $_FILES['cv']['error'] === UPLOAD_ERR_OK) {
            $cv = $_FILES['cv']['name']; // Get the file name
            $allowedExtensions = ['pdf', 'doc', 'docx'];
            $fileExtension = strtolower(pathinfo($cv, PATHINFO_EXTENSION));

            // Validate file extension
            if (!in_array($fileExtension, $allowedExtensions)) {
                die("Invalid file format. Only PDF, DOC, and DOCX files are allowed.");
            }

            // Move uploaded file to a directory
            $uploadDir = 'uploads/';
            if (!is_dir($uploadDir)) {
                mkdir($uploadDir, 0755, true);
            }
            $uploadPath = $uploadDir . basename($cv);
            if (!move_uploaded_file($_FILES['cv']['tmp_name'], $uploadPath)) {
                die("File upload failed.");
            }
        }

        $sql = "INSERT INTO inquiries (role, name, email, phone, subjects, qualification, preferred_time, message, cv_file) VALUES (:role, :name, :email, :phone, :subjects, :qualification, :preferredTime, :message, :cvFile)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':qualification', $qualification);
        $stmt->bindParam(':preferredTime', $preferredTime);
        $stmt->bindParam(':message', $message);
        $stmt->bindParam(':cvFile', $cv);
    } else {
        die("Invalid role selected.");
    }

    // Bind common parameters
    $stmt->bindParam(':role', $role);
    $stmt->bindParam(':name', $name);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':phone', $phone);
    $stmt->bindParam(':subjects', $subjects);

    // Execute the query
    try {
        $stmt->execute();
        echo "Form submitted successfully!";
    } catch (PDOException $e) {
        die("Database error: " . $e->getMessage());
    }
} else {
    die("Invalid request method.");
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vemac - Vedic Maths Classes</title>
  <!-- Bootstrap CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet">
  <!-- Font Awesome Icons -->
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
  <!-- Google Fonts -->
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <!-- Animate.css -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
  <!-- AOS Animation Library -->
  <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
  <style>
    :root {
      --primary-color: #4361ee;
      --secondary-color: #3f37c9;
      --accent-color: #4cc9f0;
      --light-color: #f8f9fa;
      --dark-color: #212529;
    }
    
    body {
      font-family: 'Poppins', sans-serif;
      overflow-x: hidden;
      scroll-behavior: smooth;
    }
    
    .navbar {
      transition: all 0.3s ease;
      padding: 15px 0;
    }
    
    .navbar.scrolled {
      padding: 10px 0;
      box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
    }
    
    .nav-link {
      position: relative;
      margin: 0 10px;
    }
    
    .nav-link::after {
      content: '';
      position: absolute;
      width: 0;
      height: 2px;
      bottom: 0;
      left: 0;
      background-color: var(--primary-color);
      transition: width 0.3s ease;
    }
    
    .nav-link:hover::after {
      width: 100%;
    }
    
    .home {
      background: linear-gradient(135deg, rgba(67, 97, 238, 0.9), rgba(76, 201, 240, 0.9)), url('./images/math-bg.jpg') no-repeat center center;
      background-size: cover;
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    
    .home::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.3);
      z-index: 1;
    }
    
    .home-content {
      position: relative;
      z-index: 2;
    }
    
    #join {
      font-size: 1.2rem;
      padding: 12px 30px;
      border-radius: 50px;
      font-weight: 600;
      letter-spacing: 1px;
      transition: all 0.3s ease;
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
      position: relative;
      overflow: hidden;
    }
    
    #join:hover {
      transform: translateY(-3px);
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3);
    }
    
    #join::after {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: linear-gradient(45deg, transparent, rgba(255, 255, 255, 0.2), transparent);
      transform: translateX(-100%);
      transition: transform 0.6s ease;
    }
    
    #join:hover::after {
      transform: translateX(100%);
    }
    
    .features {
      padding: 80px 0;
      background-color: var(--light-color);
    }
    
    .feature-item {
      text-align: center;
      padding: 30px 20px;
      border-radius: 10px;
      transition: all 0.3s ease;
      margin-bottom: 30px;
      background: white;
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
    }
    
    .feature-item:hover {
      transform: translateY(-10px);
      box-shadow: 0 15px 30px rgba(0, 0, 0, 0.1);
    }
    
    .feature-item i {
      font-size: 3rem;
      margin-bottom: 20px;
      color: var(--primary-color);
      background: linear-gradient(135deg, var(--primary-color), var(--accent-color));
      -webkit-text-fill-color: transparent;
    }
    
    .feature-item h4 {
      font-weight: 600;
      margin-bottom: 15px;
    }
    
    .bg-light {
      background-color: var(--light-color) !important;
    }
    
    .rounded-circle {
      transition: all 0.3s ease;
      border: 5px solid white;
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
    }
    
    .rounded-circle:hover {
      transform: scale(1.05);
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
    }
    
    .bg-white {
      transition: all 0.3s ease;
    }
    
    .bg-white:hover {
      transform: translateY(-5px);
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1) !important;
    }
    
    #inquiry {
      padding: 80px 0;
      background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
    }
    
    .form-control {
      padding: 12px 15px;
      border-radius: 8px;
      border: 1px solid #ddd;
      transition: all 0.3s ease;
    }
    
    .form-control:focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 0.25rem rgba(67, 97, 238, 0.25);
    }
    
    .form-control-icon {
      position: absolute;
      right: 15px;
      top: 50%;
      transform: translateY(-50%);
      color: #aaa;
    }
    
    .form-group {
      position: relative;
    }
    
    .btn-primary {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
      transition: all 0.3s ease;
    }
    
    .btn-primary:hover {
      background-color: var(--secondary-color);
      border-color: var(--secondary-color);
      transform: translateY(-2px);
    }
    
    footer {
      background-color: var(--dark-color);
      color: white;
      padding: 30px 0;
      text-align: center;
    }
    
    footer a {
      color: white;
      transition: all 0.3s ease;
      display: inline-block;
    }
    
    footer a:hover {
      color: var(--accent-color);
      transform: translateY(-3px);
    }
    
    /* Animation Classes */
    .fade-in {
      animation: fadeIn 1s ease-in;
    }
    
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    
    .float {
      animation: float 3s ease-in-out infinite;
    }
    
    @keyframes float {
      0% { transform: translateY(0px); }
      50% { transform: translateY(-10px); }
      100% { transform: translateY(0px); }
    }
    
    /* Pulse Animation */
    @keyframes pulse {
      0% { transform: scale(1); }
      50% { transform: scale(1.05); }
      100% { transform: scale(1); }
    }
    
    .pulse {
      animation: pulse 2s infinite;
    }
    
    /* Hide teacher fields initially */
    .hide {
      display: none;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
      width: 10px;
    }
    
    ::-webkit-scrollbar-track {
      background: #f1f1f1;
    }
    
    ::-webkit-scrollbar-thumb {
      background: var(--primary-color);
      border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
      background: var(--secondary-color);
    }
    
    /* Responsive adjustments */
    @media (max-width: 768px) {
      .home h1 {
        font-size: 2.5rem;
      }
      
      .feature-item {
        margin-bottom: 20px;
      }
    }
  </style>
</head>

<body>
  <!-- Modern Navbar -->
  <nav class="navbar navbar-expand-lg navbar-light bg-white fixed-top">
    <div class="container-fluid px-4">
      <!-- Logo and Brand -->
      <a class="navbar-brand d-flex align-items-center" href="#">
        <img src="./images/logo.png" alt="Logo" width="40" height="35" class="me-2">
        <span class="fw-bold fs-5" style="color: var(--primary-color);">Vemac</span>
      </a>

      <!-- Mobile Toggle -->
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarCollapse">
        <span class="navbar-toggler-icon"></span>
      </button>

      <!-- Navbar Links -->
      <div class="collapse navbar-collapse" id="navbarCollapse">
        <ul class="navbar-nav mx-auto mb-2 mb-lg-0">
          <li class="nav-item">
            <a class="nav-link fw-semibold" aria-current="page" href="#home">Home</a>
          </li>
          <li class="nav-item">
            <a class="nav-link fw-semibold" href="#about">Profile</a>
          </li>
          <li class="nav-item">
            <a class="nav-link fw-semibold" href="#inquiry">Inquiry</a>
          </li>
          <li class="nav-item">
            <a class="nav-link fw-semibold" href="#contact">Contact</a>
          </li>
        </ul>

        <!-- Login Button -->
        <div class="d-flex">
          <a href="./login.php" class="btn btn-outline-primary rounded-pill px-4">Login</a>
        </div>
      </div>
    </div>
  </nav>

  <!-- Home Section -->
  <section id="home" class="home">
    <div class="home-content container text-center">
      <h1 class="display-3 fw-bold mb-4 animate__animated animate__fadeInDown">Master Vedic Maths with Ease</h1>
      <p class="lead mb-5 animate__animated animate__fadeInUp animate__delay-1s">Unlock the ancient secrets of rapid mental calculation and mathematical problem-solving</p>
      <a href="register.html" id="join" class="btn btn-primary btn-lg pulse animate__animated animate__fadeInUp animate__delay-2s">Join Now</a>
      
      <div class="mt-5 animate__animated animate__fadeIn animate__delay-3s">
        <div class="d-flex justify-content-center gap-4">
          <div class="text-center">
            <div class="fs-2 fw-bold" data-count="2500">0</div>
            <div>Students Taught</div>
          </div>
          <div class="text-center">
            <div class="fs-2 fw-bold" data-count="11">0</div>
            <div>Years Experience</div>
          </div>
          <div class="text-center">
            <div class="fs-2 fw-bold" data-count="100">0</div>
            <div>% Satisfaction</div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Animated floating shapes -->
    <div class="shape shape-1 animate__animated animate__pulse animate__infinite"></div>
    <div class="shape shape-2 animate__animated animate__pulse animate__infinite animate__delay-1s"></div>
    <div class="shape shape-3 animate__animated animate__pulse animate__infinite animate__delay-2s"></div>
  </section>

  <!-- Features Section -->
  <section class="features container py-5" data-aos="fade-up">
    <div class="text-center mb-5">
      <h2 class="display-5 fw-bold mb-3">Why Choose Vemac?</h2>
      <p class="lead text-muted">Our unique approach to Vedic Maths makes learning fun and effective</p>
    </div>
    
    <div class="row g-4">
      <div class="col-md-4" data-aos="fade-up" data-aos-delay="100">
        <div class="feature-item">
          <i class="fas fa-brain"></i>
          <h4>Mental Agility</h4>
          <p>Develop lightning-fast mental calculation skills that will amaze everyone around you.</p>
        </div>
      </div>
      <div class="col-md-4" data-aos="fade-up" data-aos-delay="200">
        <div class="feature-item">
          <i class="fas fa-chalkboard-teacher"></i>
          <h4>Expert Guidance</h4>
          <p>Learn from Roshan Sir with over 11 years of experience in teaching Vedic Maths.</p>
        </div>
      </div>
      <div class="col-md-4" data-aos="fade-up" data-aos-delay="300">
        <div class="feature-item">
          <i class="fas fa-certificate"></i>
          <h4>Proven Results</h4>
          <p>Our students consistently achieve top grades and develop a love for mathematics.</p>
        </div>
      </div>
    </div>
  </section>

  <!-- About Section -->
  <section id="about" class="py-5 bg-light">
    <div class="container py-5">
      <div class="row g-4">
        <div class="col-lg-5" data-aos="fade-right">
          <div class="text-center mb-4">
            <img 
              alt="Roshan Sir's profile picture"
              class="rounded-circle mb-3 mx-auto img-fluid"
              src="./images/profile.jpg"
              width="250"
              height="250"
              style="border: 5px solid white; box-shadow: 0 10px 30px rgba(0,0,0,0.1);">
              
            <h2 class="fw-bold">Roshan Sir</h2>
            <p class="text-muted">Vedic Maths Expert | Mathematics Educator</p>
            
            <div class="d-flex justify-content-center gap-3 mb-4">
              <a href="#" class="text-primary fs-4"><i class="fab fa-facebook-f"></i></a>
              <a href="#" class="text-info fs-4"><i class="fab fa-twitter"></i></a>
              <a href="https://www.instagram.com/vemac__" class="text-danger fs-4"><i class="fab fa-instagram"></i></a>
              <a href="mailto:vemacroot@gmail.com" class="text-secondary fs-4"><i class="fas fa-envelope"></i></a>
            </div>
            
            <div class="card mb-4 shadow-sm">
              <div class="card-body">
                <h5 class="card-title fw-bold">Tutoring Subjects</h5>
                <ul class="list-unstyled">
                  <li><i class="fas fa-check-circle text-primary me-2"></i> Vedic Maths</li>
                  <li><i class="fas fa-check-circle text-primary me-2"></i> Mathematics</li>
                  <li><i class="fas fa-check-circle text-primary me-2"></i> Physics</li>
                  <li><i class="fas fa-check-circle text-primary me-2"></i> Chemistry</li>
                </ul>
              </div>
            </div>
            
            <div class="card shadow-sm">
              <div class="card-body">
                <h5 class="card-title fw-bold">Contact Information</h5>
                <p class="mb-3">Book your session now:</p>
                <div class="d-flex flex-column gap-2">
                  <a href="#" class="d-flex align-items-center text-primary">
                    <i class="fas fa-calendar-alt me-2"></i> Calendly
                  </a>
                  <a href="https://wa.me/919267939622" class="d-flex align-items-center text-success">
                    <i class="fab fa-whatsapp me-2"></i> WhatsApp
                  </a>
                  <a href="tel:9267939622" class="d-flex align-items-center text-info">
                    <i class="fas fa-phone me-2"></i> Call Now
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="col-lg-7" data-aos="fade-left">
          <div class="card mb-4 shadow-sm">
            <div class="card-body">
              <h3 class="card-title fw-bold mb-3">Educator Profile</h3>
              <p class="card-text mb-3">
                <strong>Passionate and improvement-driven Mathematics educator</strong> with over 11 years of expertise, 
                specializing in IB, IGCSE, British and American Curriculum, and CBSE.
              </p>
              <p class="card-text mb-3">
                Beyond traditional methods, my role as a <strong>VEDIC MATHS teacher</strong> enhances tutoring, making 
                academic understanding both accessible and engaging.
              </p>
              <p class="card-text mb-3">
                Having guided more than 2500 students to conquer challenges in Math and Science, join me on a 
                transformative learning journey where excellence meets enthusiasm.
              </p>
              <p class="card-text">
                Elevate your academic experience with a dedicated educator who goes beyond the textbook to inspire 
                a lifelong love for learning.
              </p>
            </div>
          </div>
          
          <div class="card shadow-sm">
            <div class="card-body">
              <h3 class="card-title fw-bold mb-3">Education & Qualifications</h3>
              <ul class="list-unstyled timeline">
                <li class="mb-3">
                  <div class="d-flex">
                    <div class="me-3">
                      <i class="fas fa-graduation-cap text-primary fs-4"></i>
                    </div>
                    <div>
                      <h6 class="fw-bold">Primary Education</h6>
                      <p class="text-muted mb-0">Morden Era English School, Biratnagar, Nepal</p>
                    </div>
                  </div>
                </li>
                <li class="mb-3">
                  <div class="d-flex">
                    <div class="me-3">
                      <i class="fas fa-school text-primary fs-4"></i>
                    </div>
                    <div>
                      <h6 class="fw-bold">High School</h6>
                      <p class="text-muted mb-0">GTB Public School Model Town Delhi, India (IN)</p>
                    </div>
                  </div>
                </li>
                <li class="mb-3">
                  <div class="d-flex">
                    <div class="me-3">
                      <i class="fas fa-university text-primary fs-4"></i>
                    </div>
                    <div>
                      <h6 class="fw-bold">Graduation (BSc)</h6>
                      <p class="text-muted mb-0">Delhi University, India (IN)</p>
                    </div>
                  </div>
                </li>
                <li>
                  <div class="d-flex">
                    <div class="me-3">
                      <i class="fas fa-master text-primary fs-4"></i>
                    </div>
                    <div>
                      <h6 class="fw-bold">Post Graduation (MSc)</h6>
                      <p class="text-muted mb-0">Delhi University (IN)</p>
                    </div>
                  </div>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
      
      <div class="text-center mt-5 pt-3">
        <p class="text-muted">© VEMAC INDIA - Transforming Mathematical Learning Since 2012</p>
      </div>
    </div>
  </section>

  <!-- Testimonials Section -->
  <section class="py-5 bg-white">
    <div class="container py-5">
      <div class="text-center mb-5" data-aos="fade-up">
        <h2 class="display-5 fw-bold">What Our Students Say</h2>
        <p class="lead text-muted">Success stories from our Vedic Maths learners</p>
      </div>
      
      <div class="row g-4">
        <div class="col-md-4" data-aos="fade-up" data-aos-delay="100">
          <div class="card h-100 shadow-sm">
            <div class="card-body">
              <div class="mb-3 text-warning">
                <i class="fas fa-star"></i>
                <i class="fas fa-star"></i>
                <i class="fas fa-star"></i>
                <i class="fas fa-star"></i>
                <i class="fas fa-star"></i>
              </div>
              <p class="card-text mb-4">"Vemac's Vedic Maths classes completely transformed how I approach mathematics. I can now solve complex calculations mentally in seconds!"</p>
              <div class="d-flex align-items-center">
                <img src="https://randomuser.me/api/portraits/women/32.jpg" class="rounded-circle me-3" width="50" height="50" alt="Student">
                <div>
                  <h6 class="mb-0 fw-bold">Priya Sharma</h6>
                  <small class="text-muted">Grade 10 Student</small>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="col-md-4" data-aos="fade-up" data-aos-delay="200">
          <div class="card h-100 shadow-sm">
            <div class="card-body">
              <div class="mb-3 text-warning">
                <i class="fas fa-star"></i>
                <i class="fas fa-star"></i>
                <i class="fas fa-star"></i>
                <i class="fas fa-star"></i>
                <i class="fas fa-star"></i>
              </div>
              <p class="card-text mb-4">"Roshan Sir's teaching methods are exceptional. My son's confidence in math has skyrocketed, and he actually looks forward to his math classes now."</p>
              <div class="d-flex align-items-center">
                <img src="https://randomuser.me/api/portraits/men/45.jpg" class="rounded-circle me-3" width="50" height="50" alt="Parent">
                <div>
                  <h6 class="mb-0 fw-bold">Rahul Gupta</h6>
                  <small class="text-muted">Parent</small>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="col-md-4" data-aos="fade-up" data-aos-delay="300">
          <div class="card h-100 shadow-sm">
            <div class="card-body">
              <div class="mb-3 text-warning">
                <i class="fas fa-star"></i>
                <i class="fas fa-star"></i>
                <i class="fas fa-star"></i>
                <i class="fas fa-star"></i>
                <i class="fas fa-star-half-alt"></i>
              </div>
              <p class="card-text mb-4">"The Vedic Maths techniques I learned here helped me ace my competitive exams. I solved the quantitative section in half the time!"</p>
              <div class="d-flex align-items-center">
                <img src="https://randomuser.me/api/portraits/women/68.jpg" class="rounded-circle me-3" width="50" height="50" alt="Student">
                <div>
                  <h6 class="mb-0 fw-bold">Ananya Patel</h6>
                  <small class="text-muted">JEE Aspirant</small>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Inquiry Section -->
  <section id="inquiry" class="py-5">
    <div class="container py-5">
      <div class="row justify-content-center">
        <div class="col-lg-8">
          <div class="card shadow-lg border-0" data-aos="zoom-in">
            <div class="card-body p-5">
              <h2 class="text-center mb-4 fw-bold">Join Vemac Today</h2>
              <p class="text-center text-muted mb-5">Fill out the form below to start your Vedic Maths journey</p>
              
              <form id="inquiryForm" method="POST" enctype="multipart/form-data">
                <!-- Role Selector -->
                <div class="mb-4 text-center">
                  <div class="btn-group" role="group">
                    <input type="radio" class="btn-check" name="role" id="studentRole" autocomplete="off" checked onclick="toggleFields()">
                    <label class="btn btn-outline-primary" for="studentRole">Student</label>
                    
                    <input type="radio" class="btn-check" name="role" id="teacherRole" autocomplete="off" onclick="toggleFields()">
                    <label class="btn btn-outline-primary" for="teacherRole">Teacher</label>

                    
                  </div>
                </div>

                <!-- Shared Fields -->
                <div class="row g-3 mb-4">
                  <div class="col-md-6">
                    <div class="form-floating">
                      <input type="text" class="form-control" id="name" placeholder="Name" name="name" required>
                      <label for="name">Full Name</label>
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="form-floating">
                      <input type="email" class="form-control" id="email" placeholder="Email" name="email" required>
                      <label for="email">Email Address</label>
                    </div>
                  </div>
                </div>
                
                <div class="row g-3 mb-4">
                  <div class="col-md-6">
                    <div class="form-floating">
                      <input type="tel" class="form-control" id="phone" placeholder="Phone" name="phone" pattern="[0-9]{10}" required>
                      <label for="phone">Phone Number</label>
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="form-floating">
                      <select class="form-select" id="subjects" name="subjects" required>
                        <option value="">Select Subject</option>
                        <option value="Vedic Maths">Vedic Maths</option>
                        <option value="Mathematics">Mathematics</option>
                        <option value="Physics">Physics</option>
                        <option value="Chemistry">Chemistry</option>
                        <option value="Multiple Subjects">Multiple Subjects</option>
                      </select>
                      <label for="subjects">Subject of Interest</label>
                    </div>
                  </div>
                </div>

                <!-- Student-Specific Fields -->
                <div id="studentFields">
                  <div class="mb-4">
                    <div class="form-floating">
                      <select class="form-select" id="grade" name="grade">
                        <option value="">Select Grade</option>
                        <option value="6-8">Grades 6-8</option>
                        <option value="9-10">Grades 9-10</option>
                        <option value="11-12">Grades 11-12</option>
                        <option value="College">College/University</option>
                        <option value="Competitive Exams">Competitive Exams</option>
                      </select>
                      <label for="grade">Current Grade/Level</label>
                    </div>
                  </div>
                  
                  <div class="mb-4">
                    <div class="form-floating">
                      <textarea class="form-control" placeholder="Leave a message here" id="studentMessage" name="message" style="height: 100px"></textarea>
                      <label for="studentMessage">Your Learning Goals (Optional)</label>
                    </div>
                  </div>
                </div>

                <!-- Teacher-Specific Fields -->
                <div id="teacherFields" class="hide">
                  <div class="row g-3 mb-4">
                    <div class="col-md-6">
                      <div class="form-floating">
                        <input type="text" class="form-control" id="qualification" placeholder="Qualification" name="qualification">
                        <label for="qualification">Highest Qualification</label>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="form-floating">
                        <input type="text" class="form-control" id="experience" placeholder="Experience" name="experience">
                        <label for="experience">Teaching Experience</label>
                      </div>
                    </div>
                  </div>
                  
                  <div class="mb-4">
                    <div class="form-floating">
                      <textarea class="form-control" placeholder="Leave a message here" id="teacherMessage" name="message" style="height: 100px"></textarea>
                      <label for="teacherMessage">Why are you interested in joining Vemac?</label>
                    </div>
                  </div>
                  
                  <div class="mb-4">
                    <label for="cv" class="form-label">Upload Your CV (Optional)</label>
                    <input class="form-control" type="file" id="cv" name="cv" accept=".pdf,.doc,.docx">
                  </div>
                </div>

                <!-- Submit Button -->
                <div class="d-grid mt-4">
                  <button type="submit" class="btn btn-primary btn-lg">
                    <span class="submit-text">Submit Application</span>
                    <span class="spinner-border spinner-border-sm d-none" role="status" aria-hidden="true"></span>
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- FAQ Section -->
  <section class="py-5 bg-light">
    <div class="container py-5">
      <div class="text-center mb-5" data-aos="fade-up">
        <h2 class="display-5 fw-bold">Frequently Asked Questions</h2>
        <p class="lead text-muted">Find answers to common questions about our Vedic Maths program</p>
      </div>
      
      <div class="row justify-content-center">
        <div class="col-lg-8">
          <div class="accordion" id="faqAccordion">
            <div class="accordion-item shadow-sm mb-3" data-aos="fade-up" data-aos-delay="100">
              <h3 class="accordion-header" id="headingOne">
                <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapseOne" aria-expanded="true" aria-controls="collapseOne">
                  What is Vedic Maths and how is it different?
                </button>
              </h3>
              <div id="collapseOne" class="accordion-collapse collapse show" aria-labelledby="headingOne" data-bs-parent="#faqAccordion">
                <div class="accordion-body">
                  Vedic Maths is an ancient Indian system of mathematics based on 16 sutras (formulas) and 13 sub-sutras. It differs from conventional math by providing simpler, faster, and more efficient calculation methods. Our program teaches these techniques to enhance calculation speed, improve accuracy, and develop a deeper understanding of mathematical concepts.
                </div>
              </div>
            </div>
            
            <div class="accordion-item shadow-sm mb-3" data-aos="fade-up" data-aos-delay="200">
              <h3 class="accordion-header" id="headingTwo">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseTwo" aria-expanded="false" aria-controls="collapseTwo">
                  What age group is this program suitable for?
                </button>
              </h3>
              <div id="collapseTwo" class="accordion-collapse collapse" aria-labelledby="headingTwo" data-bs-parent="#faqAccordion">
                <div class="accordion-body">
                  Our Vedic Maths program is designed for students aged 10 and above, including adults. We offer different levels tailored to various age groups and skill levels, from middle school students to competitive exam aspirants and even professionals who want to enhance their mental calculation abilities.
                </div>
              </div>
            </div>
            
            <div class="accordion-item shadow-sm mb-3" data-aos="fade-up" data-aos-delay="300">
              <h3 class="accordion-header" id="headingThree">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseThree" aria-expanded="false" aria-controls="collapseThree">
                  How will Vedic Maths help in school/competitive exams?
                </button>
              </h3>
              <div id="collapseThree" class="accordion-collapse collapse" aria-labelledby="headingThree" data-bs-parent="#faqAccordion">
                <div class="accordion-body">
                  Vedic Maths techniques can significantly reduce calculation time in exams, allowing students to solve problems faster and have more time for complex questions. It improves accuracy, builds confidence, and enhances problem-solving skills. Many of our students have reported improved scores in school exams and competitive tests like JEE, NEET, SAT, and Olympiads.
                </div>
              </div>
            </div>
            
            <div class="accordion-item shadow-sm mb-3" data-aos="fade-up" data-aos-delay="400">
              <h3 class="accordion-header" id="headingFour">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseFour" aria-expanded="false" aria-controls="collapseFour">
                  What is the class schedule and duration?
                </button>
              </h3>
              <div id="collapseFour" class="accordion-collapse collapse" aria-labelledby="headingFour" data-bs-parent="#faqAccordion">
                <div class="accordion-body">
                  We offer flexible scheduling with both weekday and weekend batches. Each level typically consists of 24 sessions (3 months) with classes held twice a week for 1 hour each. We also provide intensive crash courses during vacations. After enrollment, you'll receive a personalized schedule based on your availability.
                </div>
              </div>
            </div>
            
            <div class="accordion-item shadow-sm" data-aos="fade-up" data-aos-delay="500">
              <h3 class="accordion-header" id="headingFive">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseFive" aria-expanded="false" aria-controls="collapseFive">
                  Do you offer trial classes or demo sessions?
                </button>
              </h3>
              <div id="collapseFive" class="accordion-collapse collapse" aria-labelledby="headingFive" data-bs-parent="#faqAccordion">
                <div class="accordion-body">
                  Yes! We offer a free 30-minute demo session where you can experience our teaching methodology and see how Vedic Maths works. This helps you make an informed decision before enrolling in the full program. Contact us to schedule your free demo session at a convenient time.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Contact Section -->
  <footer id="contact" class="bg-dark text-white pt-5 pb-4">
    <div class="container">
      <div class="row g-4">
        <!-- Contact Info -->
        <div class="col-lg-4 mb-4" data-aos="fade-up">
          <h5 class="fw-bold mb-4">Vemac - Vedic Maths Classes</h5>
          <p class="mb-4">Unlocking the power of ancient mathematical techniques for modern learners.</p>
          <div class="d-flex flex-column gap-3">
            <div class="d-flex align-items-center">
              <i class="fas fa-phone-alt me-3 text-primary fs-5"></i>
              <a href="tel:9267939622" class="text-white">+91 9267939622</a>
            </div>
            <div class="d-flex align-items-center">
              <i class="fas fa-envelope me-3 text-primary fs-5"></i>
              <a href="mailto:vemacroot@gmail.com" class="text-white">vemacroot@gmail.com</a>
            </div>
            <div class="d-flex align-items-center">
              <i class="fas fa-map-marker-alt me-3 text-primary fs-5"></i>
              <span>New Delhi, India</span>
            </div>
          </div>
        </div>
        
        <!-- Quick Links -->
        <div class="col-lg-2 col-md-6 mb-4" data-aos="fade-up" data-aos-delay="100">
          <h5 class="fw-bold mb-4">Quick Links</h5>
          <ul class="list-unstyled">
            <li class="mb-2"><a href="#home" class="text-white">Home</a></li>
            <li class="mb-2"><a href="#about" class="text-white">About</a></li>
            <li class="mb-2"><a href="#inquiry" class="text-white">Courses</a></li>
            <li class="mb-2"><a href="#inquiry" class="text-white">Inquiry</a></li>
            <li class="mb-2"><a href="./login.php" class="text-white">Login</a></li>
          </ul>
        </div>
        
        <!-- Social Media -->
        <div class="col-lg-3 col-md-6 mb-4" data-aos="fade-up" data-aos-delay="200">
          <h5 class="fw-bold mb-4">Connect With Us</h5>
          <div class="d-flex gap-3 mb-4">
            <a href="https://www.facebook.com/" class="text-white fs-4"><i class="fab fa-facebook-f"></i></a>
            <a href="https://www.instagram.com/vemac__" class="text-white fs-4"><i class="fab fa-instagram"></i></a>
            <a href="https://twitter.com/" class="text-white fs-4"><i class="fab fa-twitter"></i></a>
            <a href="https://wa.me/919267939622" class="text-white fs-4"><i class="fab fa-whatsapp"></i></a>
            <a href="https://www.youtube.com/" class="text-white fs-4"><i class="fab fa-youtube"></i></a>
          </div>
          <div class="input-group mb-3">
            <input type="email" class="form-control" placeholder="Your Email" aria-label="Your Email">
            <button class="btn btn-primary" type="button">Subscribe</button>
          </div>
        </div>
        
        <!-- Map -->
        <div class="col-lg-3 mb-4" data-aos="fade-up" data-aos-delay="300">
          <h5 class="fw-bold mb-4">Our Location</h5>
          <div class="ratio ratio-16x9">
            <iframe 
              src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3502.376785903225!2d77.20956231508245!3d28.62864498242395!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x390cfd5e2f1a7a0f%3A0x7b99817f112c6b97!2sNew%20Delhi%2C%20Delhi!5e0!3m2!1sen!2sin!4v1620000000000!5m2!1sen!2sin"
              style="border:0; border-radius: 8px;"
              allowfullscreen=""
              loading="lazy">
            </iframe>
          </div>
        </div>
      </div>
      
      <hr class="my-4">
      
      <div class="row">
        <div class="col-md-6 text-center text-md-start">
          <p class="mb-0">&copy; 2023 Vemac - Vedic Maths Classes. All rights reserved.</p>
        </div>
        <div class="col-md-6 text-center text-md-end">
          <p class="mb-0">Designed with <i class="fas fa-heart text-danger"></i> by Vemac Team</p>
        </div>
      </div>
    </div>
  </footer>

  <!-- Back to Top Button -->
  <a href="#" class="btn btn-primary btn-lg back-to-top" id="backToTop">
    <i class="fas fa-arrow-up"></i>
  </a>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/js/bootstrap.bundle.min.js"></script>
  <!-- AOS Animation Library -->
  <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
  <!-- jQuery -->
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  
  <script>
    // Initialize AOS animation library
    AOS.init({
      duration: 800,
      easing: 'ease-in-out',
      once: true
    });
    
    // Navbar scroll effect
    $(window).scroll(function() {
      if ($(this).scrollTop() > 100) {
        $('.navbar').addClass('scrolled');
      } else {
        $('.navbar').removeClass('scrolled');
      }
    });
    
    // Back to top button
    $(window).scroll(function() {
      if ($(this).scrollTop() > 300) {
        $('#backToTop').fadeIn('slow');
      } else {
        $('#backToTop').fadeOut('slow');
      }
    });
    
    $('#backToTop').click(function(e) {
      e.preventDefault();
      $('html, body').animate({scrollTop: 0}, 800);
      return false;
    });
    
    // Smooth scrolling for navigation links
    $('a[href*="#"]').not('[href="#"]').not('[href="#0"]').click(function(event) {
      if (location.pathname.replace(/^\//, '') == this.pathname.replace(/^\//, '') && 
          location.hostname == this.hostname) {
        var target = $(this.hash);
        target = target.length ? target : $('[name=' + this.hash.slice(1) + ']');
        if (target.length) {
          event.preventDefault();
          $('html, body').animate({
            scrollTop: target.offset().top - 70
          }, 800, function() {
            var $target = $(target);
            $target.focus();
            if ($target.is(":focus")) {
              return false;
            } else {
              $target.attr('tabindex','-1');
              $target.focus();
            }
          });
        }
      }
    });
    
    // Toggle student/teacher fields in inquiry form
    function toggleFields() {
      const role = document.querySelector('input[name="role"]:checked').value;
      if (role === 'teacher') {
        document.getElementById('studentFields').classList.add('hide');
        document.getElementById('teacherFields').classList.remove('hide');
        document.querySelector('.submit-text').textContent = 'Submit Application';
      } else {
        document.getElementById('teacherFields').classList.add('hide');
        document.getElementById('studentFields').classList.remove('hide');
        document.querySelector('.submit-text').textContent = 'Join Now';
      }
    }
    
    // Form submission handler
    document.getElementById('inquiryForm').addEventListener('submit', function(e) {
      const submitBtn = this.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.querySelector('.submit-text').classList.add('d-none');
      submitBtn.querySelector('.spinner-border').classList.remove('d-none');
      
      // Simulate form submission (replace with actual AJAX call)
      setTimeout(() => {
        submitBtn.disabled = false;
        submitBtn.querySelector('.submit-text').classList.remove('d-none');
        submitBtn.querySelector('.spinner-border').classList.add('d-none');
        
        // Show success message (you can replace this with actual form handling)
        alert('Thank you for your submission! We will contact you shortly.');
        this.reset();
      }, 1500);
      
      e.preventDefault();
    });
    
    // Animated counter for stats
    $(document).ready(function() {
      $('[data-count]').each(function() {
        $(this).prop('Counter', 0).animate({
          Counter: $(this).data('count')
        }, {
          duration: 2000,
          easing: 'swing',
          step: function(now) {
            if ($(this).data('count') > 1000) {
              $(this).text(Math.ceil(now) + '+');
            } else {
              $(this).text(Math.ceil(now));
            }
          }
        });
      });
    });
  </script>
</body>

</html>