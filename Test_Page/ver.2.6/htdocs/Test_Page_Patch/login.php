<?php
// display_errors 설정 비활성화 및 로깅 설정
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/path/to/php-error.log');

// 사용자 정의 오류 핸들러
function customErrorHandler($errno, $errstr, $errfile, $errline) {
    error_log("Error: [$errno] $errstr - $errfile:$errline");
    echo "Something went wrong. Please try again later.";
    return true;
}
set_error_handler("customErrorHandler");

// HTTPS 강제 사용
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}

// 데이터베이스 연결
include "db_conn.php";
include "session.php";

// 로그인 처리 함수
function processLogin($pdo, $userid, $userpw) {
    try {
        $sql = "SELECT userpw, login_attempts, last_attempt_time FROM user WHERE userid = :userid";
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':userid', $userid, PDO::PARAM_STR);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $hashedPassword = $row['userpw'];
            $loginAttempts = $row['login_attempts'];
            $lastAttemptTime = $row['last_attempt_time'];

            $currentTime = new DateTime();
            $lastAttemptDateTime = $lastAttemptTime ? new DateTime($lastAttemptTime) : $currentTime;
            $timeDiff = $currentTime->diff($lastAttemptDateTime);
            $minutes = ($timeDiff->days * 24 * 60) + ($timeDiff->h * 60) + $timeDiff->i;

            if ($loginAttempts < 5) {
                if (password_verify($userpw, $hashedPassword)) {
                    // 로그인 성공
                    session_regenerate_id(true); // 세션 ID 재생성
                    $_SESSION['loggedin'] = true;
                    $_SESSION['userid'] = $userid;
                    resetLoginAttempts($pdo, $userid);
                    return "로그인을 성공하였습니다!";
                } else {
                    // 로그인 실패
                    incrementLoginAttempts($pdo, $userid, $loginAttempts);
                    return "로그인을 실패하였습니다! 5회 이상 틀릴 시 로그인이 제한됩니다. 실패 횟수 : " . ($loginAttempts + 1);
                }
            } else {
                if ($minutes >= 5) {
                    resetLoginAttempts($pdo, $userid);
                    return "로그인 시도 제한이 초기화되었습니다. 다시 로그인을 시도해주세요.";
                } else {
                    $remainingTime = 5 - $minutes;
                    return "로그인 시도 횟수가 초과되었습니다. {$remainingTime}분 후에 다시 시도해주세요.";
                }
            }
        } else {
            return "로그인을 실패하였습니다!";
        }
    } catch (PDOException $e) {
        error_log("로그인 처리 중 오류 발생: " . $e->getMessage());
        return "시스템 오류가 발생했습니다. 나중에 다시 시도해주세요.";
    }
}

// 로그인 시도 횟수 증가 함수
function incrementLoginAttempts($pdo, $userid, $currentAttempts) {
    $newAttempts = $currentAttempts + 1;
    $sql = "UPDATE user SET login_attempts = :login_attempts, last_attempt_time = NOW() WHERE userid = :userid";
    $stmt = $pdo->prepare($sql);
    $stmt->bindParam(':login_attempts', $newAttempts, PDO::PARAM_INT);
    $stmt->bindParam(':userid', $userid, PDO::PARAM_STR);
    $stmt->execute();
}

// 로그인 시도 횟수 초기화 함수
function resetLoginAttempts($pdo, $userid) {
    $sql = "UPDATE user SET login_attempts = 0, last_attempt_time = NULL WHERE userid = :userid";
    $stmt = $pdo->prepare($sql);
    $stmt->bindParam(':userid', $userid, PDO::PARAM_STR);
    $stmt->execute();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userid = htmlspecialchars($_POST['userid'], ENT_QUOTES, 'UTF-8');
    $userpw = htmlspecialchars($_POST['userpw'], ENT_QUOTES, 'UTF-8');

    $result = processLogin($pdo, $userid, $userpw);
    echo "<script>alert('$result');</script>";
    if (strpos($result, '성공') !== false) {
        echo "<script>window.location.href='index.php';</script>";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Secure Login Page</title>
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
        <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
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
    </div>
</body>
</html>
