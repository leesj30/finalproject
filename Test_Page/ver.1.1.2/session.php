<?php
session_start();

function isLoggedIn(){
    return isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true;
}
?>