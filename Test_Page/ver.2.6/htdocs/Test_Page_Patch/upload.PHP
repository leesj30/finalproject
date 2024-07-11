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

// 랜덤 파일 이름 생성 함수
function generateRandomFileName($extension) {
    return uniqid() . '.' . $extension;
}

// 파일 이름 정규화 함수
function normalizeFileName($fileName) {
    return preg_replace('/[^a-zA-Z0-9_\.-]/', '_', $fileName);
}

// MIME 타입 검증 함수
function getMimeType($filePath) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $filePath);
    finfo_close($finfo);
    return $mimeType;
}

// 파일 업로드 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];
        $fileName = normalizeFileName(basename($file['name']));
        $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        $uploadFile = $uploadDir . generateRandomFileName($fileExtension);

        // 파일 크기 검증
        if ($file['size'] > $maxFileSize) {
            echo "File is too large. Maximum size is 2MB.";
        }
        // 확장자 검증
        elseif (!in_array($fileExtension, $allowedExtensions)) {
            echo "Invalid file extension. Allowed extensions are jpg, jpeg, png, and pdf.";
        }
        // .php 확장자 차단
        elseif ($fileExtension === 'php') {
            echo "PHP files are not allowed.";
        }
        else {
            // MIME 타입 검증
            $tmpFilePath = $file['tmp_name'];
            $mimeType = getMimeType($tmpFilePath);
            if (!in_array($mimeType, $allowedMimeTypes)) {
                echo "Invalid file type. Allowed types are JPEG, PNG, and PDF.";
            }
            else {
                if (move_uploaded_file($tmpFilePath, $uploadFile)) {
                    // 업로드된 파일의 실행 권한 제거
                    chmod($uploadFile, 0644);
                    echo "File successfully uploaded.";
                } else {
                    echo "File upload failed.";
                }
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
    <script>
        function validateFile() {
            const fileInput = document.getElementById('file');
            const filePath = fileInput.value;
            const allowedExtensions = /(\.jpg|\.jpeg|\.png|\.pdf)$/i;
            
            if (!allowedExtensions.exec(filePath)) {
                alert('Invalid file type. Allowed types are JPEG, PNG, and PDF.');
                fileInput.value = '';
                return false;
            }
            return true;
        }
    </script>
</head>
<body>

<!-- 파일 업로드 폼 -->
<form action="upload.php" method="POST" enctype="multipart/form-data" onsubmit="return validateFile()">
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
