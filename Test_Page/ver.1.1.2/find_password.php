<head>
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
    <title>비밀번호 찾기</title>
</head>
<body>
    <div class="container">
        <h1>비밀번호 찾기</h1>
        <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post">
            <div class="form-group">
                <label for="username" class="input-label">Name: </label>
                <input type="text" placeholder="Name" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="userid" class="input-label">ID: </label>
                <input type="text" placeholder="ID" id="userid" name="userid" required>
            </div>
            <div class="form-group">
                <label for="email" class="input-label">Email: </label>
                <input type="email" placeholder="Email" id="email" name="email" required>
            </div>
            <input type="submit" name="userpw" value="Find Password">
        </form>
        <div class="login-link">
            <p class="login_btn">로그인 바로가기 <a href="login.php">Sign In</a></p>
        </div>

        <?php
        include "db_conn.php";

        if($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['userpw'])){
            $userid = $_POST['userid'];
            $email = $_POST['email'];
            $username = $_POST['username'];

            $sql = "SELECT userpw FROM User WHERE userid='$userid' AND email='$email' AND username='$username'";
            $result = $conn->query($sql);

            if(mysqli_num_rows($result) > 0){
                $row = mysqli_fetch_assoc($result);
                $userpw = $row['userpw'];
                echo "<script>alert('비밀번호는 [ $userpw ] 입니다.');</script>";
                echo "<script>window.location.href='login.php';</script>";
            } 

            else{
                echo "<script>alert('비밀번호를 찾을 수 없습니다. 입력 내용을 확인해 주세요.');</script>";
            }
        }
        ?>
    </div>
</body>
