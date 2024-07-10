<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname= "Final";

$conn = new mysqli($servername, $username, $password, $dbname);
 
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$dsn = 'mysql:host='.$servername.';dbname='.$dbname;

try{
    $pdo = new PDO($dsn, $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} 

catch (PDOException $e) {
    echo 'Connect failed : ' . $e->getMessage() . '';
}
?>