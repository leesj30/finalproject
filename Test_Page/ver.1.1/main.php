<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
        }

        .container {
            max-width: 1300px;
            width: 100%;
            margin: 100px auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }

        h1 {
            text-align: center;
            color: #333;
        }

        .button {
            text-align: center;
            margin-bottom: 20px;
        }

        .input {
            display: inline-block;
            margin-left: 10px;
        }

        .input input[type="text"] {
            padding: 8px;
            margin-right: 5px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }

        .input button {
            padding: 8px 16px;
            background-color: #3498db;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        .input button:hover {
            background-color: #2980b9;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }

        table th, table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }

        table th {
            background-color: #f2f2f2;
            font-weight: bold;
        }

        .button input[type="submit"] {
            padding: 8px 16px;
            background-color: #3498db;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        .button input[type="submit"]:hover {
            background-color: #2980b9;
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
        <h1>게시판</h1>
        <div class="button">
            <input type="submit" value="게시글 작성" name="post" onclick="location.href='write_post.php'">
            <div class="input">
                <input type="text" id="find_title" name="find_title" placeholder="게시물 찾기">
                <button onclick="find()">검색</button>
            </div>
        </div>
        <br>
        <table>
            <tr>
                <th>No.</th>
                <th>제목</th>
                <th>작성자</th>
                <th>작성일</th>
            </tr>
            
            <?php
            include "db_conn.php";
            
            if(isset($_GET['find_title'])) {
                $find_title = $_GET['find_title'];
                $sql = "SELECT id, title, writer, created_date FROM Posts WHERE title LIKE '%$find_title%'";
            } else { 
                $sql = "SELECT id, title, writer, created_date FROM Posts";
            }
            
            $result = $conn->query($sql);
            
            if($result && $result->num_rows > 0) {
                while ($row = $result->fetch_assoc()) {
                    echo "<tr onclick='goBoard({$row['id']})'>";
                    echo "<td>{$row['id']}</td>";
                    echo "<td>{$row['title']}</td>";
                    echo "<td>{$row['writer']}</td>";
                    echo "<td>{$row['created_date']}</td>";
                    echo "</tr>";
                }
            } 
            else{
                echo "<tr><td colspan='4'>게시물이 없습니다.</td></tr>";
            }
            ?>
        </table>
        <script>
            function goBoard(postid){
                location.href = 'content_post.php?id=' + postid;
            }

            function find(){
                var find_title = document.getElementById('find_title').value;
                location.href = 'board.php?find_title=' + find_title;
            }
        </script>
        <div class="link">
            <p class="btn">메인 페이지로 <a href="index.php">Main page</a></p>
        </div>
    </div>
</body>