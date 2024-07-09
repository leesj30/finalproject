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

// 파일의 MIME 타입과 확장자 확인
function validate_file($file) {
    $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt'];
    $allowed_mime_types = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain'];
    
    // 파일 크기 2MB로 제한
    $max_file_size = 2 * 1024 * 1024; // 2MB
    $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $file_mime_type = mime_content_type($file['tmp_name']);
    $file_size = $file['size'];
    if (in_array($file_extension, $allowed_extensions) && in_array($file_mime_type, $allowed_mime_types) && $file_size <= $max_file_size) {
        return true;
    } else {
        return false;
    }
}

// 파일명 검증
function validate_filename($filename) {
    // 허용되는 문자 패턴
    $pattern = '/^[a-zA-Z0-9_\-\.]+$/';
    
    // 파일명에서 확장자 제거
    $name_without_ext = pathinfo($filename, PATHINFO_FILENAME);
    
    if (preg_match($pattern, $name_without_ext)) {
        return true;
    } else {
        return false;
    }
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $title = mysqli_real_escape_string($conn, $_POST['title'] ?? '');
    $writer = mysqli_real_escape_string($conn, $_POST['writer'] ?? '');
    $content = mysqli_real_escape_string($conn, $_POST['content'] ?? '');
    $file = $_FILES['file'] ?? null;
    $upload_file = '';

    if ($file && $file['error'] == UPLOAD_ERR_OK) {
        if (validate_file($file) && validate_filename($file['name'])) {
            $upload_dir = 'uploads/';
            $new_file_name = uniqid() . '.' . strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            $upload_file = $upload_dir . $new_file_name;
            if (move_uploaded_file($file['tmp_name'], $upload_file)) {
                echo "<script>alert('파일과 게시글이 업로드 되었습니다!');</script>";
            } else {
                echo "파일 업로드 실패.<br>";
            }
        } else {
            if (!validate_file($file)) {
                echo "허용되지 않는 파일 형식이거나 파일 크기가 2MB를 초과했습니다.<br>";
            }
            if (!validate_filename($file['name'])) {
                echo "안전하지 않은 파일명입니다. 파일명에는 영문자, 숫자, 밑줄(_), 하이픈(-), 점(.)만 사용할 수 있습니다.<br>";
            }
        }
    } elseif ($file) {
        echo "파일 업로드 에러 코드: " . $file['error'] . "<br>";
    }

    if ($title && $writer && $content) {
        $sql = "INSERT INTO posts (title, writer, content, file_path) VALUES (?, ?, ?, ?)";
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, 'ssss', $title, $writer, $content, $upload_file);
        if (mysqli_stmt_execute($stmt)) {
            $post_id = mysqli_insert_id($conn);
            echo "<script>alert('파일과 게시글이 업로드 되었습니다!'); window.location.href='main.php?id=$post_id';</script>";
        } else {
            echo "게시물 저장 실패: " . mysqli_error($conn) . "<br>";
        }
        mysqli_stmt_close($stmt);
    } else {
        echo "제목, 작성자, 내용을 입력해주세요.<br>";
    }
}
?>