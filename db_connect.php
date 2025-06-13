<?php 
 // Database configuration
 $host = 'localhost'; // Replace with your database host
 $dbname = 'vemac_db'; // Replace with your database name
 $username = 'root'; // Replace with your database username
 $password = ''; // Replace with your database password
 
 // Establish database connectio
     $conn = mysqli_connect($host, $username, $password,$dbname);
     if(!$conn){

        header("Location: error.html");
         
     }

  


?>


