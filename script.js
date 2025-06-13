// Password toggle functionality
function setupPasswordToggle(passwordId, toggleId) {
  const togglePassword = document.querySelector(toggleId);
  const password = document.querySelector(passwordId);
  
  if (togglePassword && password) {
    togglePassword.addEventListener('click', function() {
      const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
      password.setAttribute('type', type);
      this.classList.toggle('bi-eye');
      this.classList.toggle('bi-eye-slash');
    });
  }
}

// Initialize password toggles
document.addEventListener('DOMContentLoaded', function() {
  // For login page
  setupPasswordToggle('#password', '#togglePassword');
  
  // For registration page
  setupPasswordToggle('#password', '#togglePassword');
  setupPasswordToggle('#confirm_password', '#toggleConfirmPassword');
  
  // Password match validation for registration form
  const registrationForm = document.getElementById('registrationForm');
  if (registrationForm) {
    registrationForm.addEventListener('submit', function(event) {
      const password = document.getElementById('password').value;
      const confirmPassword = document.getElementById('confirm_password').value;
      
      if (password !== confirmPassword) {
        event.preventDefault();
        alert('Passwords do not match!');
        document.getElementById('confirm_password').focus();
      }
    });
  }
});