<?php
if (isset($_GET['file']) && isset($_GET['newname'])) {
    $file = $_GET['file'];
    $newName = $_GET['newname'];

    // 파일 경로 설정(경로 조작 허용)
    $filePath = $file;

    // 파일 존재 여부 확인
    if (file_exists($filePath)) {
        // 파일 다운로드 또는 열기 선택
        if (isset($_GET['action']) && $_GET['action'] == 'open') {
            // 파일 열기
            header('Content-Type: ' . mime_content_type($filePath));
            readfile($filePath);
        } else {
            // 파일 다운로드
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename=' . basename($newName));
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . filesize($filePath));
            readfile($filePath);
        }
        exit;
    } else {
        echo "File not found.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>File Download</title>
</head>
<body>

<!-- 파일 다운로드 및 열기 폼 -->
<form action="download.php" method="GET">
    File to download: <input type="text" name="file" />
    New filename: <input type="text" name="newname" />
    <input type="submit" value="Download File" />
    <br>
    <label>
        <input type="radio" name="action" value="open" /> Open
    </label>
    <label>
        <input type="radio" name="action" value="download" checked /> Download
    </label>
</form>

</body>
</html>
