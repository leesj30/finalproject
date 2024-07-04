<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>비밀번호 변경</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
        }

        .container {
            width: 400px;
            margin: 100px auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }

        h1 {
            text-align: center;
            color: #333;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .input-label {
            display: block;
            margin-bottom: 5px;
            color: #333;
        }

        input[type="password"] {
            width: 100%;
            padding: 8px;
            margin-top: 5px;
            margin-bottom: 10px;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        
        input[type="submit"] {
            width: 100%;
            padding: 10px;
            background-color: #3498db;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        input[type="submit"]:hover {
            background-color: #2980b9;
        }

        .message {
            color: red;
        }

        .link {
            text-align: center;
        }

        .btn a {
            text-decoration: none;
            color: #3498db;
        }

        .btn a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>비밀번호 변경</h1>
        <form action="" method="POST">
            <input type="password" name="new_password" placeholder="새 비밀번호" required>
            <input type="password" name="confirm_password" placeholder="새 비밀번호 확인" required>
            <input type="submit" value="비밀번호 변경">
        </form>
        <div class="link">
            <p class="btn">메인 페이지로 <a href="index.php">Main page</a></p>
        </div>
    </div>
    
    <?php
    include('session.php');
    include('db_conn.php');

    if (!isLoggedIn()) {
        header("Location: index.php");
        exit();
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $newPassword = $_POST['new_password'];
        $confirmPassword = $_POST['confirm_password'];
        $userid = $_SESSION['userid'];

        if ($newPassword != $confirmPassword) {
            echo "<script>alert('새 비밀번호가 일치하지 않습니다!');</script>";
            exit();
        }

        $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
        $sql = "UPDATE user SET userpw = '$hashedPassword' WHERE userid = '$userid'";
    
        if ($conn->query($sql) === TRUE) {
            echo "<script>alert('비밀번호가 성공적으로 변경되었습니다!');</script>";
            echo "<script>window.location.href='index.php';</script>";
        } else {
            echo "비밀번호 변경 중 오류 발생: " . mysqli_error($conn);
        }
    }
    ?>
</body>
</html>