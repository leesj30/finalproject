<?php
// 허용된 다운로드 디렉토리 설정
$allowed_dir = 'uploads/';

// GET 파라미터에서 파일 경로 가져오기
$file_path = $_GET['file'] ?? '';

// 파일명 검증 함수
function is_safe_filename($filename) {
    // 허용되는 문자: 영문자, 숫자, 밑줄, 하이픈, 점
    return preg_match('/^[a-zA-Z0-9_\-\.]+$/', $filename);
}

// 파일 경로에서 파일명 추출
$requested_filename = basename($file_path);

// 요청된 파일의 전체 경로
$full_path = $allowed_dir . $requested_filename;

if ($file_path && file_exists($full_path) && is_file($full_path) && is_safe_filename($requested_filename)) {
    // 실제 파일명 확인
    $actual_filename = basename(realpath($full_path));
    
    // 실제 파일명과 요청된 파일명 비교
    if ($actual_filename === $requested_filename) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $full_path);
        finfo_close($finfo);

        header('Content-Description: File Transfer');
        header('Content-Type: ' . $mime_type);
        header('Content-Disposition: attachment; filename="'.$actual_filename.'"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($full_path));
        flush();
        readfile($full_path);
        exit;
    } else {
        echo "요청한 파일명이 실제 파일명과 일치하지 않습니다.";
    }
} else {
    if (!file_exists($full_path)) {
        echo "파일을 찾을 수 없습니다.";
    } elseif (!is_safe_filename($requested_filename)) {
        echo "안전하지 않은 파일명입니다. 다운로드가 제한됩니다.";
    } else {
        echo "파일 다운로드 중 오류가 발생했습니다.";
    }
}
?>