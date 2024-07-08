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

        if($_SERVER['REQUEST_METHOD'] === 'POST'){
            $userid = $_POST['userid'];
            $userpw = $_POST['userpw'];


            $sql = "SELECT userpw, userrole FROM user WHERE userid = :userid";
            $stmt = $pdo->prepare($sql);
            $stmt->bindParam(':userid', $userid, PDO::PARAM_STR);
            $stmt->execute();
            
            if($stmt->rowCount() > 0){
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                $hashedPassword = $row['userpw'];

                if(password_verify($userpw, $hashedPassword)){
                    $_SESSION['loggedin'] = true;
                    $_SESSION['userid'] = $userid;
                    //$_SESSION['userrole'] = $userrole;

                    echo "<script>alert('로그인을 성공하였습니다!');</script>";
                    echo "<script>window.location.href='index.php';</script>";
                } 

                else{
                    echo "<script>alert('로그인을 실패하였습니다!');</script>";
                }
            } 
            
            else{
                echo "<script>alert('로그인을 실패하였습니다!');</script>";
            }
        }
        ?>
    </div>
</body>
</html>