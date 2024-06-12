<?php
// 데이터베이스 연결 설정
$servername = "localhost";
$username = "username";
$password = "password";
$dbname = "database";

// 데이터베이스 연결 생성
$conn = new mysqli($servername, $username, $password, $dbname);

// 연결 확인
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// 폼 데이터 받기
$from_account = $_POST['from_account'];
$to_account = $_POST['to_account'];
$amount = $_POST['amount'];

// 거래 기록 삽입
$sql = "INSERT INTO transactions (from_account, to_account, amount) VALUES ('$from_account', '$to_account', '$amount')";
if ($conn->query($sql) === TRUE) {
    echo "Transfer successful";
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}

// 거래 내역 조회
$sql = "SELECT id, from_account, to_account, amount, transaction_date FROM transactions ORDER BY transaction_date DESC";
$result = $conn->query($sql);

// 거래 내역 표시
if ($result->num_rows > 0) {
    echo "<h2>Transaction History</h2>";
    echo "<table border='1'>
            <tr>
                <th>ID</th>
                <th>From Account</th>
                <th>To Account</th>
                <th>Amount</th>
                <th>Date</th>
            </tr>";
    while($row = $result->fetch_assoc()) {
        echo "<tr>
                <td>".$row['id']."</td>
                <td>".$row['from_account']."</td>
                <td>".$row['to_account']."</td>
                <td>".$row['amount']."</td>
                <td>".$row['transaction_date']."</td>
              </tr>";
    }
    echo "</table>";
} else {
    echo "No transactions found";
}

$conn->close();
?>