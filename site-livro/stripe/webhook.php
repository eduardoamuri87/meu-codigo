<?php
/**
 * Webhook da Stripe — confirmação oficial do pagamento (Checkout Session).
 *
 * O Checkout embedded confirma o pagamento no navegador, mas o sinal CONFIÁVEL
 * de que a compra deu certo (e que deve disparar o pós-venda) vem por aqui.
 *
 * Configure no Dashboard (Desenvolvedores > Webhooks > endpoint):
 *   URL: https://programas.amuri.com.br/stripe/webhook.php
 *   Eventos:
 *     - checkout.session.completed            (cartão e PIX pago na hora)
 *     - checkout.session.async_payment_succeeded  (PIX confirmado com atraso)
 *     - checkout.session.async_payment_failed      (PIX expirou/falhou)
 *   (pode remover o antigo payment_intent.succeeded — não é mais usado.)
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

/**
 * Registra o pedido a partir de uma Checkout Session paga.
 * Idempotente: ignora se a sessão já foi registrada (retentativas da Stripe,
 * ou o evento completed + um async_succeeded para a mesma sessão).
 */
function registrarPedido($session) {
    $logFile = __DIR__ . '/pedidos.log';
    $sid = $session['id'] ?? '';

    if ($sid && is_file($logFile)) {
        $existente = @file_get_contents($logFile);
        if ($existente !== false && strpos($existente, '"checkout_session":"' . $sid . '"') !== false) {
            return; // já registrado
        }
    }

    $cd = $session['customer_details'] ?? [];

    // CPF/CNPJ coletado via tax_id_collection (customer_details.tax_ids[]).
    $cpf = '';
    foreach (($cd['tax_ids'] ?? []) as $t) {
        if (!empty($t['value'])) { $cpf = $t['value']; break; }
    }

    // Endereço de entrega — o nome do campo varia por versão da API.
    $entrega = $session['collected_information']['shipping_details']
            ?? $session['shipping_details']
            ?? $session['shipping']
            ?? null;

    // PaymentIntent pode vir como id (string) ou objeto expandido.
    $pi = $session['payment_intent'] ?? '';
    if (is_array($pi)) { $pi = $pi['id'] ?? ''; }

    $meta = $session['metadata'] ?? [];

    $registro = [
        'data'             => date('c'),
        'checkout_session' => $sid,
        'payment_intent'   => $pi,
        'valor'            => ($session['amount_total'] ?? 0) / 100,
        'produto'          => $meta['produto'] ?? '',
        'cpf'              => $cpf,
        'email'            => $cd['email'] ?? '',
        'nome'             => $cd['name'] ?? '',
        'entrega'          => $entrega,
        // UTMs e demais rastreios (metadata, menos os campos fixos).
        'utm'              => array_diff_key($meta, array_flip(['produto', 'origem'])),
    ];

    // Registro simples em arquivo. Substitua/adicione aqui o seu pós-venda:
    // enviar e-mail de confirmação, gravar o pedido, avisar a logística, etc.
    file_put_contents(
        $logFile,
        json_encode($registro, JSON_UNESCAPED_UNICODE) . "\n",
        FILE_APPEND | LOCK_EX
    );
}

if (!stripeSignatureValida($payload, $sigHeader, $webhookSecret)) {
    http_response_code(400);
    echo 'Assinatura inválida';
    exit;
}

$evento = json_decode($payload, true);
$tipo   = $evento['type'] ?? '';
$obj    = $evento['data']['object'] ?? [];

if ($tipo === 'checkout.session.completed') {
    // Síncrono (cartão; PIX pago na hora): payment_status = 'paid' → registra.
    // Assíncrono pendente (PIX aguardando confirmação): 'unpaid' → NÃO registra
    // ainda; o async_payment_succeeded chega depois.
    if (($obj['payment_status'] ?? '') === 'paid') {
        registrarPedido($obj);
    }
} elseif ($tipo === 'checkout.session.async_payment_succeeded') {
    // PIX confirmado depois (rede de segurança).
    registrarPedido($obj);
} elseif ($tipo === 'checkout.session.async_payment_failed') {
    // PIX expirou/falhou — registra um marcador para acompanhamento.
    @file_put_contents(
        __DIR__ . '/pedidos.log',
        json_encode(['data' => date('c'), 'falha_sessao' => $obj['id'] ?? ''], JSON_UNESCAPED_UNICODE) . "\n",
        FILE_APPEND | LOCK_EX
    );
}

// Sempre responda 200 rapidamente para a Stripe não reenviar o evento.
http_response_code(200);
echo 'ok';
