<?php
$file_path = $_GET['file'] ?? '';

if ($file_path && file_exists($file_path)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file_path).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file_path));
    flush();
    readfile($file_path);
    exit;
} else {
    echo "파일을 찾을 수 없습니다.";
}
?>
