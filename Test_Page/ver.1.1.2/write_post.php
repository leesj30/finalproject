<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
        }

        h1 {
            color: #333;
            text-align: center;
        }

        .notice {
            font-family: 'Arial', sans-serif;
            padding: 10px;
            margin-bottom: 20px;
            text-align: center;
        }

        .container {
            max-width: 800px;
            width: 100%;
            margin: 0px auto;
            background-color: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 5px;
        }

        input[type="text"],
        textarea {
            width: calc(100% - 30px);
            padding: 15px;
            border: 1px solid #ccc;
            border-radius: 4px;
            resize: vertical;
        }

        .button {
            text-align: center;
        }

        .button input[type="submit"],
        .button input[type="button"] {
            padding: 10px 20px;
            background-color: #3498db;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
        }

        .button input[type="submit"]:hover,
        .button input[type="button"]:hover {
            background-color: #2980b9;
        }
    </style>
</head>
<body>
    <h1>게시물 작성</h1>
    <div class="notice" name="notice">제목과 글 내용을 작성해주세요</div>
    <div class="container">
        <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post">
            <div class="form-group">
                <label for="title">제목</label>
                <input id="title" name="title" type="text" placeholder="제목을 입력해주세요" required>
            </div>
            <div class="form-group">
                <label for="title">작성자</label>
                <input id="writer" name="writer" type="text" placeholder="이름을 입력해주세요" required>
            </div>
            <div class="form-group">
                <label for="content">내용</label>
                <textarea id="content" name="content" rows="20" placeholder="내용을 입력해주세요" required></textarea>
            </div>
            <div class="button">
                <input type="submit" value="저장">
                <input type="button" value="이전" onclick="location.href = 'main.php'">
            </div>
        </form>
        <?php
        include "db_conn.php";

        if(session_status() === PHP_SESSION_NONE){
            session_start();
        }

        if($_SERVER['REQUEST_METHOD'] === 'POST'){
            $title = $_POST['title'];
            $writer = $_POST['writer'];
            $content = $_POST['content'];
            
            $sql = "INSERT INTO Posts (title, content, writer) VALUES ('$title', '$content', '$writer')";
            $result = $conn->query($sql);
            
            if($result){
                echo "<script>alert('게시물이 저장되었습니다!');</script>";
                echo "<script>location.href='main.php'</script>";
            }
            else{
                $error_message = mysqli_error($conn);
                echo "<script>alert('게시물이 저장에 실패하였습니다!');</script>";
            }
        }
        else{
            $error_message = mysqli_error($conn);
        }
        ?>
    </div>
</body>
</html>