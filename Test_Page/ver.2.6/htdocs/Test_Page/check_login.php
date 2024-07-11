<?php
    include('session.php');

    $response = [
        'loggedin' => isLoggedIn(),
        'userid' => isset($_SESSION['userid']) ? $_SESSION['userid'] : ''
    ];
    echo json_encode($response);
?>