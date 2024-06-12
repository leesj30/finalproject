CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    from_account VARCHAR(50),
    to_account VARCHAR(50),
    amount DECIMAL(10, 2),
    transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);