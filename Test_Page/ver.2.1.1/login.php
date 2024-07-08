<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
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

        input[type="text"],
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
        <h1>Login Page</h1>
        <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post">
            <div class="form-group">
                <label for="userid" class="input-label">ID: </label>
                <input type="text" placeholder="ID" id="userid" name="userid" required>
            </div>
            <div class="form-group">
                <label for="userpw" class="input-label">Password: </label>
                <input type="password" placeholder="Password" id="userpw" name="userpw" required>
            </div>
            <input type="submit" value="Login">
            <div class="link">
                <p class="btn">회원가입 바로가기 <a href="join.php">Sign Up</a></p>
                <p class="btn">메인 페이지로 <a href="index.php">Main page</a></p>
            </div>
        </form>

        <?php
        include "db_conn.php";
        include "session.php";

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $userid = $_POST['userid'];
            $userpw = $_POST['userpw'];
            
            $sql = "SELECT userpw, login_attempts, last_attempt_time FROM user WHERE userid = :userid";
            $stmt = $pdo->prepare($sql);
            $stmt->bindParam(':userid', $userid, PDO::PARAM_STR);
            $stmt->execute();

            if ($stmt->rowCount() > 0) {
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                $hashedPassword = $row['userpw'];
                $loginAttempts = $row['login_attempts'];
                $lastAttemptTime = $row['last_attempt_time'];

            // 현재 시간과 마지막 로그인 시도 시간의 차이 계산
            $currentTime = new DateTime();
            $seconds = 0;  // $seconds 변수를 초기화
                if ($lastAttemptTime) {
                    $lastAttemptDateTime = new DateTime($lastAttemptTime);
                    $interval = $currentTime->diff($lastAttemptDateTime);
                    $seconds = $interval->days * 24 * 60 * 60 +
                               $interval->h * 60 * 60 +
                               $interval->i * 60 +
                               $interval->s;
                }
                if ($loginAttempts < 5) {
                    if (password_verify($userpw, $hashedPassword)) {
                        $_SESSION['loggedin'] = true;
                        $_SESSION['userid'] = $userid;
                        echo "<script>alert('로그인을 성공하였습니다!');</script>";
                        echo "<script>window.location.href='index.php';</script>";

                        // 로그인 성공 시 로그인 시도 횟수와 마지막 시도 시간 초기화
                        $sql = "UPDATE user SET login_attempts = 0, last_attempt_time = NULL WHERE userid = :userid";
                        $stmt = $pdo->prepare($sql);
                        $stmt->bindParam(':userid', $userid, PDO::PARAM_STR);
                        $stmt->execute();

                    } else {
                        // 비밀번호가 틀리면 로그인 시도 횟수를 증가
                        $loginAttempts++;
                        $sql = "UPDATE user SET login_attempts = :login_attempts, last_attempt_time = NOW() WHERE userid = :userid";
                        $stmt = $pdo->prepare($sql);
                        $stmt->bindParam(':login_attempts', $loginAttempts, PDO::PARAM_INT);
                        $stmt->bindParam(':userid', $userid, PDO::PARAM_STR);
                        $stmt->execute();

                        echo "<script>alert('로그인을 실패하였습니다! 5회 이상 틀릴 시 로그인이 제한됩니다. 실패 횟수: $loginAttempts');</script>";
                    }
                } 
                else {
                    // 5분(300초) 이상 지났으면 로그인 시도 횟수를 초기화
                    if ($seconds > 300) {
                        $loginAttempts = 0;
                        $sql = "UPDATE user SET login_attempts = 0, last_attempt_time = NULL WHERE userid = :userid";
                        $stmt = $pdo->prepare($sql);
                        $stmt->bindParam(':userid', $userid, PDO::PARAM_STR);
                        $stmt->execute();
                    }  

                    else{               
                        echo "<script>alert('로그인 시도 횟수가 초과되었습니다. 5분 후에 다시 시도해주세요.');</script>";
                    }
                }
            } else {
                echo "<script>alert('로그인을 실패하였습니다!');</script>";
            }
        }
        ?>

    </div>
</body>
</html>
