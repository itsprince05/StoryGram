<?php
// =======================================================
// Database Connection & Config
// Database: u563285099_StoryGram
// =======================================================

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-KEY, x-api-key');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

define('DB_HOST', 'localhost');
define('DB_NAME', 'u563285099_StoryGram');
define('DB_USER', 'u563285099_storygram');
define('DB_PASS', 'Story@#Gram#@1488');
define('API_SECRET_KEY', 'StoryGramSecretKey_9874981488');
define('ADMIN_PASSWORD', 'Story@#Gram#@1488');

function ensureDatabaseSchema($pdo) {
    try {
        // 1. Create users table if not exists
        $pdo->exec("CREATE TABLE IF NOT EXISTS `users` (
          `id` INT AUTO_INCREMENT PRIMARY KEY,
          `user_id` VARCHAR(255) DEFAULT NULL,
          `email` VARCHAR(255) NOT NULL UNIQUE,
          `name` VARCHAR(255) DEFAULT 'User',
          `photo_url` TEXT DEFAULT NULL,
          `device_id` VARCHAR(255) DEFAULT NULL,
          `status` ENUM('pending', 'allowed', 'blocked') NOT NULL DEFAULT 'pending',
          `allowed_until` DATETIME DEFAULT NULL,
          `last_ip` VARCHAR(64) DEFAULT NULL,
          `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          `last_login` DATETIME DEFAULT NULL,
          INDEX `idx_user_id` (`user_id`),
          INDEX `idx_email` (`email`),
          INDEX `idx_device_id` (`device_id`),
          INDEX `idx_status` (`status`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // 2. Create access_logs table if not exists
        $pdo->exec("CREATE TABLE IF NOT EXISTS `access_logs` (
          `id` INT AUTO_INCREMENT PRIMARY KEY,
          `user_id` INT DEFAULT NULL,
          `email` VARCHAR(255) NOT NULL,
          `device_id` VARCHAR(255) DEFAULT NULL,
          `ip_address` VARCHAR(64) DEFAULT NULL,
          `action` VARCHAR(50) NOT NULL,
          `details` TEXT DEFAULT NULL,
          `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          INDEX `idx_user_email` (`email`),
          INDEX `idx_created_at` (`created_at`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // 3. Ensure user_id column exists if table was created previously without it
        $columns = $pdo->query("SHOW COLUMNS FROM `users` LIKE 'user_id'")->fetchAll();
        if (empty($columns)) {
            $pdo->exec("ALTER TABLE `users` ADD COLUMN `user_id` VARCHAR(255) DEFAULT NULL AFTER `id`, ADD INDEX `idx_user_id` (`user_id`)");
        }
    } catch (Exception $e) {
        error_log("Schema auto-ensure notice: " . $e->getMessage());
    }
}

function getDBConnection() {
    static $pdo = null;
    if ($pdo === null) {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ];
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
            ensureDatabaseSchema($pdo);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => 'Database connection failed: ' . $e->getMessage()
            ]);
            exit;
        }
    }
    return $pdo;
}

function sendJsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function verifyApiSecretKey() {
    $providedKey = '';
    
    // 1. Check HTTP Headers
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        if (is_array($headers)) {
            foreach ($headers as $k => $v) {
                if (strtolower($k) === 'x-api-key' || strtolower($k) === 'x_api_key' || strtolower($k) === 'api-key') {
                    $providedKey = trim($v);
                    break;
                }
            }
        }
    }
    
    // 2. Check Server Variables
    if (empty($providedKey)) {
        if (isset($_SERVER['HTTP_X_API_KEY'])) {
            $providedKey = trim($_SERVER['HTTP_X_API_KEY']);
        } elseif (isset($_SERVER['HTTP_X_APIKEY'])) {
            $providedKey = trim($_SERVER['HTTP_X_APIKEY']);
        } elseif (isset($_SERVER['X_API_KEY'])) {
            $providedKey = trim($_SERVER['X_API_KEY']);
        } elseif (isset($_POST['api_key'])) {
            $providedKey = trim($_POST['api_key']);
        } elseif (isset($_GET['api_key'])) {
            $providedKey = trim($_GET['api_key']);
        }
    }

    // 3. Check JSON Payload
    if (empty($providedKey)) {
        $raw = file_get_contents('php://input');
        if ($raw) {
            $json = json_decode($raw, true);
            if (isset($json['api_key'])) {
                $providedKey = trim($json['api_key']);
            } elseif (isset($json['x_api_key'])) {
                $providedKey = trim($json['x_api_key']);
            }
        }
    }

    if ($providedKey !== API_SECRET_KEY) {
        sendJsonResponse([
            'success' => false,
            'error' => 'Unauthorized API request'
        ], 401);
    }
}
