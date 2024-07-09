<?php
include('session.php');

?>

<head>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            text-align: center;
        }

        .container {
            width: 400px;
            margin: 100px auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }

        h1, p {
            color: #333;
        }

        button {
            margin: 20px;
            padding: 10px 20px;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            transition: opacity 0.3s ease;
            background-color: #3498db;
            color: #fff;
        }

        button:hover {
            opacity: 0.8;
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
    <title>Main Page</title>
<body>
    <div class="container">
        <h1>Main Page</h1>
        <p>이용하고 싶은 서비스를 선택해 주세요.</p>
        <button onclick="checkLogin('main.php')">게시판</button>
        <div class="login-message" id="loginMessage">
            <?php if (isLoggedIn()): ?>
                <?php echo $_SESSION['userid']; ?>님 환영합니다!
                <a id="logoutLink" class="logout_btn" href="logout.php">Logout</a>
                <p class="password_btn">비밀번호 변경 <a href="change_password.php">Change Password</a></p>
            <?php else: ?>
                <div class="login-link" id="loginLink">
                    <p class="login_btn">로그인 해 주세요. <a href="login.php">Sign Up</a></p>
                </div>
            <?php endif; ?>
        </div>
    </div>
    <script>
        function checkLogin(target){
            var xhr = new XMLHttpRequest();
            xhr.open('GET', 'check_login.php', true);
            xhr.onload = function() {
                if (xhr.status === 200){
                    var response = JSON.parse(xhr.responseText);
                    if(response.loggedin) {
                        location.href = target;
                    } 
                    else{
                        alert("로그인이 필요한 서비스 입니다.");
                    }
                }
            };
            xhr.send();
        }
    </script>
</body>