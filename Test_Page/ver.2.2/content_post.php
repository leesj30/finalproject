<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>게시물 내용</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 20px;
        }
        button {
            padding: 10px 20px;
            background-color: #3498db;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
        }
        button:hover {
            opacity: 0.8;
        }
        .file-section {
            margin-top: 20px;
        }
        .file-section h3 {
            margin-bottom: 10px;
        }
        .file-section a {
            color: #3498db;
            text-decoration: none;
        }
        .file-section a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>게시물 내용</h1>
        <?php
        include "db_conn.php";

        if(isset($_GET['id'])) {
            $post_id = $_GET['id'];

            $sql = "SELECT * FROM Posts WHERE id = $post_id";
            $result = $conn->query($sql);

            if($result && $result->num_rows > 0) {
                $post = $result->fetch_assoc();
                $title = $post['title'];
                $content = $post['content'];
                $writer = $post['writer'];
                $created_date = $post['created_date'];
                $file_path = $post['file_path'];

                echo "<h2>$title</h2>";
                echo "<hr>";
                echo "<h4>작성자</h4>";
                echo "<p>$writer</p>";
                echo "<hr>";
                echo "<h4>작성일</h4>";
                echo "<p>$created_date</p>";
                echo "<hr>";
                echo "<h4>내용</h4>";
                echo "<p>$content</p>";

                if ($file_path) {
                    echo "<div class='file-section'>";
                    echo "<h3>파일</h3>";
                    echo "<p><a href='download_handler.php?file=$file_path'>".basename($file_path)."</a></p>";
                    echo "</div>";
                }
            } else {
                echo "<p>해당하는 게시물이 없습니다.</p>";
            }
        } else {
            echo "<p>게시물을 찾을 수 없습니다.</p>";
        }
        ?>
        <button onclick="location.href='main.php'">이전</button>
    </div>
</body>
</html>
