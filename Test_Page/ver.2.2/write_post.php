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
        <form action="write_post.php" method="post" enctype="multipart/form-data">
            <div class="form-group">
                <label for="title">제목</label>
                <input id="title" name="title" type="text" required>
            </div>
            <div class="form-group">
                <label for="writer">작성자</label>
                <input id="writer" name="writer" type="text" required>
            </div>
            <div class="form-group">
                <label for="content">내용</label>
                <textarea id="content" name="content" rows="5" required></textarea>
            </div>
            <div class="form-group">
                <label for="file">파일 업로드</label>
                <input id="file" name="file" type="file">
            </div>
            <div class="button">
                <input type="submit" value="작성">
                <input type="button" value="파일 다운로드 페이지로 이동" onclick="location.href='download.php'">
            </div>
        </form>
    </div>
</body>
</html>

<?php
include 'db_conn.php';

function input_XSS($data) {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

if($_SERVER['REQUEST_METHOD'] == 'POST'){
    $title = input_XSS($_POST['title'] ?? '');
    $writer = input_XSS($_POST['writer'] ?? '');
    $content = input_XSS($_POST['content'] ?? '');
    $file = $_FILES['file'] ?? null;

    $upload_file = '';

    if($file && $file['error'] == UPLOAD_ERR_OK){
        $upload_dir = 'uploads/';
        $upload_file = $upload_dir . basename($file['name']);

        if(move_uploaded_file($file['tmp_name'], $upload_file)){
            echo "<script>alert('파일과 게시글이 업로드 되었습니다!'); window.location.href='view_post.php?id=$post_id';</script>";
        } 
        
        else{
            echo "파일 업로드 실패.<br>";
        }
    } 
    
    else{
        echo "파일 업로드 에러 코드: " . ($file['error'] ?? 'No file uploaded') . "<br>";
    }

    if($title && $writer && $content){
        $stmt = $conn->prepare("INSERT INTO posts (title, writer, content, file_path) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $title, $writer, $content, $upload_file);

        if($stmt->execute()){
            $post_id = $stmt->insert_id;
            echo "<script>alert('파일과 게시글이 업로드 되었습니다!'); window.location.href='main.php?id=$post_id';</script>";
        } 
        
        else{
            echo "게시물 저장 실패: " . $stmt->error . "<br>";
        }
        $stmt->close();
    } 
    
    else{
        echo "제목, 작성자, 내용을 입력해주세요.<br>";
    }
}
?>

