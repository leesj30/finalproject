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

        .login-link {
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
    <title>아이디 찾기</title>
</head>
<body>
    <div class="container">
        <h1>아이디 찾기</h1>
        <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post">
            <div class="form-group">
                <label for="username" class="input-label">이름: </label>
                <input type="text" placeholder="Username" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="email" class="input-label">Email: </label>
                <input type="email" placeholder="Email" id="email" name="email" required>
            </div>
            <input type="submit" name="find_id" value="Find ID">
        </form>
        <div class="login-link">
            <p class="login_btn">로그인 바로가기 <a href="login.php">Sign In</a></p>
        </div>

        <?php
        include "db_conn.php";

        if($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['find_id'])) {
            $username = $_POST['username'];
            $email = $_POST['email'];

            $sql = "SELECT userid FROM User WHERE username='$username' AND email='$email'";
            $result = $conn->query($sql);

            if(mysqli_num_rows($result) > 0) {
                $row = mysqli_fetch_assoc($result);
                $userid = $row['userid'];
                echo "<script>alert('아이디는 [ $userid ] 입니다.');</script>";
                echo "<script>window.location.href='login.php';</script>";
            } 
            else{
                echo "<script>alert('ID를 찾을 수 없습니다. 이름과 이메일을 확인해 주세요.');</script>";
            }
        }
        ?>
    </div>
</body>
