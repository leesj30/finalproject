<!DOCTYPE html>
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
        input[type="password"],
        input[type="email"] {
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

        .login_btn {
            text-align: center;
        }

        .login_btn a {
            text-decoration: none;
            color: #3498db;
        }

        .login_btn a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Join Page</h1>
        <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post" name="regiform" onsubmit="return sendit()">
            <div class="form-group">
                <label for="username" class="input-label">Name: </label>
                <input type="text" name="username" id="username" required>
            </div>
            <div class="form-group">
                <label for="userid" class="input-label">ID: </label>
                <input type="text" name="userid" id="userid" required>
            </div>
            <div class="form-group">
                <label for="userpw" class="input-label">Password: </label>
                <input type="password" name="userpw" id="userpw" required>
            </div>
            <div class="form-group">
                <label for="userpw_ch" class="input-label">Password Check: </label>
                <input type="password" name="userpw_ch" id="userpw_ch" required>
            </div>
            <div class="form-group">
                <label for="Email" class="input-label">Email: </label>
                <input type="email" name="Email" id="Email" required>
            </div>
            <input type="submit" value="회원가입" class="join_btn">
            <p class="login_btn">로그인 바로가기 <a href="login.php">Sign In</a></p>
        </form>

        <?php
        include "db_conn.php";

        if($_SERVER['REQUEST_METHOD'] === 'POST'){
            $username = $_POST['username'];
            $userid = $_POST['userid'];
            $userpw = $_POST['userpw'];
            $userpw_ch = $_POST['userpw_ch'];
            $Email = $_POST['Email'];

            if($userpw === $userpw_ch){
                $sql = "INSERT INTO User (username, userid, userpw, Email) VALUES ('$username', '$userid', '$userpw', '$Email')";
                $result = $conn->query($sql);

                echo "<script>alert('회원가입 되었습니다! 로그인을 시도해 주세요.');</script>";
                echo "<script>location.href='login.php'</script>";
            }
        }
        ?>
    </div>
    <script src="join.js"></script>
</body>
