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
        input[type="text"] {
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
    <h1>파일 다운로드</h1>
    <div class="notice" name="notice">다운로드할 파일의 경로를 입력해주세요</div>
    <div class="container">
        <form action="download_handler.php" method="get">
            <div class="form-group">
                <label for="file">파일 경로</label>
                <input id="file" name="file" type="text" required>
            </div>
            <div class="button">
                <input type="submit" value="다운로드">
            </div>
        </form>
    </div>
</body>
</html>
