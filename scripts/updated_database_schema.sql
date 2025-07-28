-- Updated database schema with monthly summaries
CREATE DATABASE IF NOT EXISTS expense_tracker;
USE expense_tracker;

-- Users table
CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Remove the old expense table (we're not using expenses anymore)
DROP TABLE IF EXISTS expense;

-- Income table
CREATE TABLE income (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    month INT NOT NULL CHECK (month >= 1 AND month <= 12),
    year INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_month_year (user_id, month, year)
);

-- Monthly limits table
CREATE TABLE monthly_limit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    limit_amount DECIMAL(10, 2) NOT NULL,
    month INT NOT NULL CHECK (month >= 1 AND month <= 12),
    year INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_limit_month_year (user_id, month, year)
);

-- NEW: Monthly summaries table for history tracking
CREATE TABLE monthly_summary (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    month INT NOT NULL CHECK (month >= 1 AND month <= 12),
    year INT NOT NULL,
    income DECIMAL(10, 2) NOT NULL DEFAULT 0,
    total_spent DECIMAL(10, 2) NOT NULL DEFAULT 0,
    savings DECIMAL(10, 2) NOT NULL DEFAULT 0,
    budget_limit DECIMAL(10, 2) NOT NULL DEFAULT 0,
    exceeded_amount DECIMAL(10, 2) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_summary_month_year (user_id, month, year)
);

-- Indexes for better performance
CREATE INDEX idx_income_user_month_year ON income(user_id, month, year);
CREATE INDEX idx_monthly_limit_user_month_year ON monthly_limit(user_id, month, year);
CREATE INDEX idx_monthly_summary_user_month_year ON monthly_summary(user_id, month, year);
CREATE INDEX idx_monthly_summary_date ON monthly_summary(year, month);
