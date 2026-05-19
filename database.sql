CREATE DATABASE file_analysis;

USE file_analysis;

CREATE TABLE reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_name VARCHAR(255),
    file_path TEXT,
    file_size BIGINT,
    hash_value TEXT,
    status VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);