<?php
/**
 * Verifica uma Checkout Session pelo id (usado por deu-certo.html).
 * Devolve apenas status e valor — nada de dados pessoais.
 *
 * GET ?session_id=cs_...
 */
header('Content-Type: application/json');

$config = require __DIR__ . '/config.php';
$secretKey = $config['secret_key'] ?? '';

$sessionId = $_GET['session_id'] ?? '';

// Aceita só ids de Checkout Session, para não virar um proxy genérico da API.
if (!$secretKey || strpos($sessionId, 'cs_') !== 0 || !preg_match('/^cs_[A-Za-z0-9_]+$/', $sessionId)) {
    http_response_code(400);
    echo json_encode(['error' => 'Sessão inválida']);
    exit;
}

$ch = curl_init('https://api.stripe.com/v1/checkout/sessions/' . urlencode($sessionId));
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_USERPWD        => $secretKey . ':',
    CURLOPT_TIMEOUT        => 20,
]);
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$data = json_decode($response, true);

if ($httpCode >= 400 || !isset($data['id'])) {
    http_response_code(404);
    echo json_encode(['error' => 'Sessão não encontrada']);
    exit;
}

echo json_encode([
    'status'         => $data['status'] ?? '',          // open | complete | expired
    'payment_status' => $data['payment_status'] ?? '',  // paid | unpaid | no_payment_required
    'amount_total'   => $data['amount_total'] ?? 0,      // centavos
    'currency'       => $data['currency'] ?? 'brl',
]);
