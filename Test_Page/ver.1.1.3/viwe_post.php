<?php
include 'db_conn.php';

$post_id = $_GET['id'] ?? null;
if ($post_id) {
    $sql = "SELECT * FROM posts WHERE id = $post_id";
    $result = mysqli_query($conn, $sql);

    if ($result) {
        $post = mysqli_fetch_assoc($result);
        if ($post) {
            echo "<h1>{$post['title']}</h1>";
            echo "<p>작성자: {$post['writer']}</p>";
            echo "<p>작성일: {$post['created_at']}</p>";
            echo "<p>{$post['content']}</p>";
            if ($post['file_path']) {
                echo "<p>첨부 파일: <a href='download_handler.php?file={$post['file_path']}'>".basename($post['file_path'])."</a></p>";
            }
        } else {
            echo "게시물을 찾을 수 없습니다.";
        }
    } else {
        echo "데이터베이스 조회 실패: " . mysqli_error($conn);
    }
} else {
    echo "잘못된 요청입니다.";
}
?>
<input type="button" value="이전" onclick="window.history.back()">
