<?php
/**
 * Webhook da Stripe — confirmação oficial do pagamento.
 *
 * O Payment Element confirma o pagamento direto no navegador, mas o sinal
 * CONFIÁVEL de que a compra deu certo (e que deve disparar o pós-venda) vem
 * por aqui. Configure este endpoint no Dashboard:
 *   Desenvolvedores > Webhooks > Adicionar endpoint
 *   URL:  https://programas.amuri.com.br/stripe/webhook.php
 *   Evento: payment_intent.succeeded
 *
 * Copie o "Signing secret" (whsec_...) para config.php > webhook_secret.
 */

$config = require __DIR__ . '/config.php';
$webhookSecret = $config['webhook_secret'] ?? '';

$payload   = file_get_contents('php://input');
$sigHeader = $_SERVER['HTTP_STRIPE_SIGNATURE'] ?? '';

/**
 * Valida a assinatura do webhook sem depender do SDK.
 * Formato do header: t=timestamp,v1=assinatura[,v1=...]
 */
function stripeSignatureValida($payload, $sigHeader, $secret, $tolerancia = 300) {
    if (!$secret || !$sigHeader) {
        return false;
    }

    $timestamp = null;
    $assinaturas = [];
    foreach (explode(',', $sigHeader) as $parte) {
        $kv = explode('=', $parte, 2);
        if (count($kv) !== 2) {
            continue;
        }
        if ($kv[0] === 't') {
            $timestamp = $kv[1];
        } elseif ($kv[0] === 'v1') {
            $assinaturas[] = $kv[1];
        }
    }

    if (!$timestamp) {
        return false;
    }

    // Proteção contra replay: rejeita eventos muito antigos.
    if (abs(time() - (int)$timestamp) > $tolerancia) {
        return false;
    }

    $esperada = hash_hmac('sha256', $timestamp . '.' . $payload, $secret);
    foreach ($assinaturas as $assinatura) {
        if (hash_equals($esperada, $assinatura)) {
            return true;
        }
    }
    return false;
}

if (!stripeSignatureValida($payload, $sigHeader, $webhookSecret)) {
    http_response_code(400);
    echo 'Assinatura inválida';
    exit;
}

$evento = json_decode($payload, true);
$tipo = $evento['type'] ?? '';

if ($tipo === 'payment_intent.succeeded') {
    $pi = $evento['data']['object'] ?? [];

    $registro = [
        'data'         => date('c'),
        'payment_intent' => $pi['id'] ?? '',
        'valor'        => ($pi['amount'] ?? 0) / 100,
        'produto'      => $pi['metadata']['produto'] ?? '',
        'cpf'          => $pi['metadata']['cpf'] ?? '',
        'email'        => $pi['receipt_email'] ?? ($pi['shipping']['name'] ?? ''),
        'entrega'      => $pi['shipping'] ?? null,
        // UTMs e demais rastreios (tudo da metadata, menos os campos fixos).
        'utm'          => array_diff_key($pi['metadata'] ?? [], array_flip(['produto', 'cpf', 'origem'])),
    ];

    // Registro simples em arquivo. Substitua/adicione aqui o seu pós-venda:
    // enviar e-mail de confirmação, gravar o pedido, avisar a logística, etc.
    file_put_contents(
        __DIR__ . '/pedidos.log',
        json_encode($registro, JSON_UNESCAPED_UNICODE) . "\n",
        FILE_APPEND | LOCK_EX
    );
}

// Sempre responda 200 rapidamente para a Stripe não reenviar o evento.
http_response_code(200);
echo 'ok';
