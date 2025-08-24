
-- ddl.sql: MySQL 8.x schema
CREATE DATABASE IF NOT EXISTS otp_service;
USE otp_service;

CREATE TABLE IF NOT EXISTS otps (
  id BINARY(16) PRIMARY KEY,
  user_id VARCHAR(128) NOT NULL,
  purpose VARCHAR(64) NOT NULL,
  code_hash CHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  wrong_attempts INT NOT NULL DEFAULT 0,
  used_at TIMESTAMP NULL DEFAULT NULL,
  UNIQUE KEY uq_user_purpose_active (user_id, purpose, is_active),
  INDEX idx_user_purpose (user_id, purpose),
  INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS verification_locks (
  user_id VARCHAR(128) NOT NULL,
  purpose VARCHAR(64) NOT NULL,
  lock_until TIMESTAMP NOT NULL,
  PRIMARY KEY (user_id, purpose),
  INDEX idx_lock_until (lock_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS request_logs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(128) NULL,
  ip VARBINARY(16) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_req_user_time (user_id, created_at),
  INDEX idx_req_ip_time (ip, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS idempotency_keys (
  idempotency_key VARCHAR(128) PRIMARY KEY,
  user_id VARCHAR(128) NOT NULL,
  purpose VARCHAR(64) NOT NULL,
  otp_id BINARY(16) NULL,
  response_json JSON NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  INDEX idx_ide_user (user_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
