<?php
include "db_conn.php";

try{
    $sql = "SELECT id, title, writer, created_date FROM Posts";
    $result = $conn->query($sql);

    if ($result && $result->num_rows > 0) {
        $rows = array();
        while ($row = $result->fetch_assoc()) {
            $rows[] = $row;
        }
        include "main.php";
    } else {
        echo "게시물이 없습니다.";
    }
} catch (Exception $e) {
    echo "게시물을 불러오는 중에 오류가 발생했습니다.";
}
?>