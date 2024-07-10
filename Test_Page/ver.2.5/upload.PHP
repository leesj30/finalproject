<?php
$uploadDir = 'uploads/';
$maxFileSize = 2 * 1024 * 1024; // 2MB in bytes

// 허용된 MIME 타입과 확장자
$allowedMimeTypes = ['image/jpeg', 'image/png', 'application/pdf'];
$allowedExtensions = ['jpg', 'jpeg', 'png', 'pdf'];

// uploads 디렉토리 존재 여부 확인 및 생성
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

// 파일 업로드 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];
        $fileName = basename($file['name']);
        $uploadFile = $uploadDir . $fileName;
        $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

        // 파일 크기 검증
        if ($file['size'] > $maxFileSize) {
            echo "File is too large. Maximum size is 2MB.";
        }
        // MIME 타입 검증
        elseif (!in_array($file['type'], $allowedMimeTypes)) {
            echo "Invalid file type. Allowed types are JPEG, PNG, and PDF.";
        }
        // 확장자 검증
        elseif (!in_array($fileExtension, $allowedExtensions)) {
            echo "Invalid file extension. Allowed extensions are jpg, jpeg, png, and pdf.";
        }
        else {
            if (move_uploaded_file($file['tmp_name'], $uploadFile)) {
                echo "File successfully uploaded.";
            } else {
                echo "File upload failed.";
            }
        }
    }
}

// 업로드된 파일 목록 표시 (변경 없음)
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
    Select file to upload (Max 2MB, JPEG, PNG, or PDF): 
    <input type="file" name="file" id="file">
    <input type="submit" value="Upload File" name="submit">
</form>

<!-- 업로드된 파일 목록 표시 -->
<h3>Uploaded Files:</h3>
<ul>
    <?php listUploadedFiles($uploadDir); ?>
</ul>

</body>
</html>