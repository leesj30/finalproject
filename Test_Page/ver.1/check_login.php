<?php
    include('session.php');

    $response = [
        'loggedin' => isLoggedIn(),
        'username' => isset($_SESSION['username']) ? $_SESSION['username'] : ''
    ];
    echo json_encode($response);
?>