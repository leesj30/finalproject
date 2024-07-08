<?php
$uploadDir = 'uploads/';

// uploads 디렉토리 존재 여부 확인 및 생성
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

// 파일 업로드 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['file'])) {
        $uploadFile = $uploadDir . '/' . basename($_FILES['file']['name']);
        
        if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadFile)) {
            echo "File successfully uploaded.";
        } else {
            echo "File upload failed.";
        }
    }
}

// 업로드된 파일 목록 표시
function listUploadedFiles($directory) {
    $files = array_diff(scandir($directory), array('..', '.'));
    foreach ($files as $file) {
        echo '<li>' . $file . ' - <a href="download.php?file=' . urlencode($directory . '/' . $file) . '&newname=' . urlencode($file) . '&action=download">Download</a></li>';
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>File Upload</title>
</head>
<body>

<!-- 파일 업로드 폼 -->
<form action="upload.php" method="POST" enctype="multipart/form-data">
    Select file to upload: 
    <input type="file" name="file" id="file">
    <input type="submit" value="Upload File" name="submit">
</form>

<!-- 업로드된 파일 목록 표시 -->
<h3>Uploaded Files:</h3>
<ul>
    <?php listUploadedFiles($uploadDir); ?>
</ul>

<!-- 시스템 파일 다운로드 링크 -->
<h3>System Files:</h3>
<ul>
    <li><a href="download.php?file=/etc/passwd&newname=passwd&action=download">Download /etc/passwd</a></li>
</ul>

</body>
</html>
