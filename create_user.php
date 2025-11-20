<?php
require 'vendor/autoload.php';

use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

try {
    $dsn = "sqlite:{$_ENV['DB_DATABASE']}";
    $pdo = new PDO($dsn, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    $username = 'testuser';
    $password = 'securepassword';

    $hashedPassword = password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 1<<17,    // 128 MB
        'time_cost'   => 4,        // Number of iterations
        'threads'     => 2         // Parallelism (CPU cores)
    ]);

    $stmt = $pdo->prepare('INSERT INTO users (username, password) VALUES (:username, :password)');
    $stmt->execute([
        ':username' => $username,
        ':password' => $hashedPassword,
    ]);

    echo "User '$username' created successfully.";

} catch (PDOException $e) {
    echo 'Database error: ' . $e->getMessage();
} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage();
}