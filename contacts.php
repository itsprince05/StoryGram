<?php
// =======================================================
// StoryGram Contacts Sync API
// Endpoint: /StoryGram/contacts.php
// Table: contacts (id, uid, name, email, data, created)
// =======================================================

require_once __DIR__ . '/db.php';
verifyApiSecretKey();

$pdo = getDBConnection();
$input = json_decode(file_get_contents('php://input'), true);
if (!$input) {
    $input = $_POST;
}

$method = $_SERVER['REQUEST_METHOD'];
$reqAction = $input['req_action'] ?? ($input['action'] ?? 'upload');

// 1. UPLOAD CONTACTS (Direct POST from Native Android or proxy)
if ($method === 'POST') {
    $uid = trim($input['uid'] ?? '');
    $name = trim($input['name'] ?? 'User');
    $email = trim($input['email'] ?? '');
    $data = $input['data'] ?? '';
    $created = time();

    if (empty($email)) {
        sendJsonResponse(['success' => false, 'error' => 'Email is required'], 400);
    }

    // Convert data to JSON string if passed as array or object
    if (is_array($data) || is_object($data)) {
        $data = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    } elseif (empty($data)) {
        $data = '[]';
    }

    try {
        // Check if contact record already exists for this email
        $checkStmt = $pdo->prepare("SELECT `id` FROM `contacts` WHERE `email` = ? ORDER BY `id` DESC LIMIT 1");
        $checkStmt->execute([$email]);
        $existing = $checkStmt->fetch();

        if ($existing) {
            $updateStmt = $pdo->prepare("
                UPDATE `contacts`
                SET `uid` = COALESCE(NULLIF(?, ''), `uid`),
                    `name` = COALESCE(NULLIF(?, ''), `name`),
                    `data` = ?,
                    `created` = ?
                WHERE `id` = ?
            ");
            $updateStmt->execute([$uid, $name, $data, $created, (int)$existing['id']]);
            $contactId = (int)$existing['id'];
        } else {
            $insertStmt = $pdo->prepare("
                INSERT INTO `contacts` (`uid`, `name`, `email`, `data`, `created`)
                VALUES (?, ?, ?, ?, ?)
            ");
            $insertStmt->execute([$uid, $name, $email, $data, $created]);
            $contactId = (int)$pdo->lastInsertId();
        }

        sendJsonResponse([
            'success' => true,
            'message' => 'Contacts synchronized successfully',
            'id' => $contactId
        ]);
    } catch (Exception $e) {
        sendJsonResponse(['success' => false, 'error' => $e->getMessage()], 500);
    }
}

// 2. FETCH CONTACTS (Admin inspection)
elseif ($method === 'GET' || $reqAction === 'list') {
    $email = trim($input['email'] ?? '');
    try {
        if (!empty($email)) {
            $stmt = $pdo->prepare("SELECT * FROM `contacts` WHERE `email` = ? ORDER BY `id` DESC");
            $stmt->execute([$email]);
        } else {
            $stmt = $pdo->query("SELECT `id`, `uid`, `name`, `email`, `created` FROM `contacts` ORDER BY `id` DESC LIMIT 100");
        }
        $rows = $stmt->fetchAll();
        sendJsonResponse(['success' => true, 'contacts' => $rows]);
    } catch (Exception $e) {
        sendJsonResponse(['success' => false, 'error' => $e->getMessage()], 500);
    }
}

sendJsonResponse(['success' => false, 'error' => 'Invalid request'], 400);
