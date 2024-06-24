<!DOCTYPE html>
<html>
<head>
    <title>Bank Transfer</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f8f8f8;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            flex-direction: column; /* 세로 정렬 추가 */
        }
        .container {
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
            margin: 0 20px;
            box-sizing: border-box;
        }
        h2 {
            text-align: center;
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="number"] {
            width: calc(100% - 16px);
            padding: 8px;
            margin-bottom: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
        }
        input[type="submit"] {
            width: 100%;
            padding: 10px;
            background-color: #3498db;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        input[type="submit"]:hover {
            background-color: #2980b9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        table, th, td {
            border: 1px solid #ccc;
        }
        th, td {
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }

        .link {
            text-align: center;
        }

        .btn a {
            text-decoration: none;
            color: #3498db;
        }

        .btn a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Bank Transfer</h2>
        <form method="POST" action="transfer.php">
            <label for="from_account">From Account:</label>
            <input type="text" id="from_account" name="from_account" required>
            <label for="to_account">To Account:</label>
            <input type="text" id="to_account" name="to_account" required>
            <label for="amount">Amount:</label>
            <input type="number" id="amount" name="amount" step="0.01" required>
            <input type="submit" value="Transfer">
        </form>
        <div class="link">
            <p class="btn">메인 페이지로 <a href="index.php">Main page</a></p>
        </div>
    </div>
    <div class="container">
        <?php include 'transfer.php'; ?>
    </div>
</body>
</html>