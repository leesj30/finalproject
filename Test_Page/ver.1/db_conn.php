<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname= "Final";
 
$conn = new mysqli($servername, $username, $password, $dbname);
 
// db 연결 실패
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>