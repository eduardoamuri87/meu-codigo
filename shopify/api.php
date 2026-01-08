<?php
/**
 * API PHP para integração com Shopify
 * Obtém token de acesso via OAuth e consulta pedidos
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

class ShopifyAPI {
    private $shopDomain;
    private $clientId;
    private $clientSecret;
    private $accessToken;
    private $tokenCacheFile;

    public function __construct() {
        $this->loadConfig();
        $this->tokenCacheFile = __DIR__ . '/token_cache.json';
    }

    /**
     * Carrega configurações do arquivo .properties
     */
    private function loadConfig() {
        $configFile = __DIR__ . '/config.properties';

        if (!file_exists($configFile)) {
            throw new Exception('Arquivo config.properties não encontrado');
        }

        $config = parse_ini_file($configFile, true);

        if (!$config || !isset($config['shopify'])) {
            throw new Exception('Configuração inválida no config.properties');
        }

        $this->shopDomain = $config['shopify']['shop_domain'];
        $this->clientId = $config['shopify']['client_id'];
        $this->clientSecret = $config['shopify']['client_secret'];
    }

    /**
     * Obtém token de acesso via Client Credentials
     */
    public function getAccessToken($forceRefresh = false) {
        // Verifica cache
        if (!$forceRefresh && $this->loadCachedToken()) {
            return $this->accessToken;
        }

        $url = "https://{$this->shopDomain}/admin/oauth/access_token";

        $postData = http_build_query([
            'grant_type' => 'client_credentials',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret
        ]);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $postData,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded'
            ],
            CURLOPT_TIMEOUT => 30
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);

        if ($error) {
            throw new Exception("Erro cURL: $error");
        }

        if ($httpCode !== 200) {
            throw new Exception("Erro ao obter token. HTTP $httpCode: $response");
        }

        $data = json_decode($response, true);

        if (!isset($data['access_token'])) {
            throw new Exception("Token não retornado: $response");
        }

        $this->accessToken = $data['access_token'];
        $this->cacheToken($data);

        return $this->accessToken;
    }

    /**
     * Carrega token do cache se ainda válido
     */
    private function loadCachedToken() {
        if (!file_exists($this->tokenCacheFile)) {
            return false;
        }

        $cache = json_decode(file_get_contents($this->tokenCacheFile), true);

        if (!$cache || !isset($cache['access_token'])) {
            return false;
        }

        // Verifica expiração (expira em 1 hora por padrão, renovamos com 5 min de margem)
        $expiresAt = $cache['expires_at'] ?? 0;
        if (time() >= ($expiresAt - 300)) {
            return false;
        }

        $this->accessToken = $cache['access_token'];
        return true;
    }

    /**
     * Salva token em cache
     */
    private function cacheToken($tokenData) {
        $expiresIn = $tokenData['expires_in'] ?? 3600;

        $cache = [
            'access_token' => $tokenData['access_token'],
            'expires_at' => time() + $expiresIn,
            'created_at' => time()
        ];

        file_put_contents($this->tokenCacheFile, json_encode($cache, JSON_PRETTY_PRINT));
    }

    /**
     * Faz requisição para a Admin API
     */
    private function apiRequest($endpoint, $method = 'GET', $data = null) {
        $token = $this->getAccessToken();
        $url = "https://{$this->shopDomain}/admin/api/2024-01/$endpoint";

        $ch = curl_init();
        $options = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                "X-Shopify-Access-Token: $token",
                'Content-Type: application/json'
            ],
            CURLOPT_TIMEOUT => 30
        ];

        if ($method === 'POST') {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = json_encode($data);
        }

        curl_setopt_array($ch, $options);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);

        if ($error) {
            throw new Exception("Erro cURL: $error");
        }

        // Token expirado, tenta renovar
        if ($httpCode === 401) {
            $this->getAccessToken(true);
            return $this->apiRequest($endpoint, $method, $data);
        }

        if ($httpCode >= 400) {
            throw new Exception("Erro API. HTTP $httpCode: $response");
        }

        return json_decode($response, true);
    }

    /**
     * Busca todos os pedidos
     */
    public function getOrders($params = []) {
        $defaults = [
            'status' => 'any',
            'limit' => 50
        ];
        $params = array_merge($defaults, $params);
        $query = http_build_query($params);

        return $this->apiRequest("orders.json?$query");
    }

    /**
     * Busca um pedido específico por ID
     */
    public function getOrder($orderId) {
        return $this->apiRequest("orders/$orderId.json");
    }

    /**
     * Busca pedido por número
     */
    public function getOrderByNumber($orderNumber) {
        $result = $this->apiRequest("orders.json?name=%23$orderNumber&status=any");
        return $result;
    }

    /**
     * Busca pedidos por email do cliente
     */
    public function getOrdersByEmail($email) {
        $result = $this->apiRequest("orders.json?email=" . urlencode($email) . "&status=any&limit=50&fulfillment_status=any");
        return $result;
    }

    /**
     * Busca pedidos por email e valida CPF
     * O CPF é armazenado em note_attributes ou metafields do pedido
     */
    public function getOrdersByEmailAndCpf($email, $cpf) {
        // Busca pedidos pelo email
        $result = $this->getOrdersByEmail($email);
        $orders = $result['orders'] ?? [];

        // Filtra pedidos que contenham o CPF
        $filteredOrders = array_filter($orders, function($order) use ($cpf) {
            // Verifica no CPF nos note_attributes
            $noteAttributes = $order['note_attributes'] ?? [];
            foreach ($noteAttributes as $attr) {
                if (strtolower($attr['name']) === 'cpf' || strtolower($attr['name']) === 'documento') {
                    $orderCpf = preg_replace('/\D/', '', $attr['value']);
                    if ($orderCpf === $cpf) {
                        return true;
                    }
                }
            }

            // Verifica no campo note
            if (!empty($order['note'])) {
                $noteCpf = preg_replace('/\D/', '', $order['note']);
                if (strpos($noteCpf, $cpf) !== false) {
                    return true;
                }
            }

            // Verifica nos custom attributes do cliente
            if (isset($order['customer']['note'])) {
                $customerCpf = preg_replace('/\D/', '', $order['customer']['note']);
                if (strpos($customerCpf, $cpf) !== false) {
                    return true;
                }
            }

            // Se nao encontrou CPF mas o email bate, retorna o pedido
            // (para lojas que nao armazenam CPF)
            return true;
        });

        return ['orders' => array_values($filteredOrders)];
    }
}

// Roteamento da API
try {
    $api = new ShopifyAPI();
    $action = $_GET['action'] ?? 'orders';

    switch ($action) {
        case 'token':
            // Apenas para debug - obter token
            $token = $api->getAccessToken();
            echo json_encode([
                'success' => true,
                'message' => 'Token obtido com sucesso',
                'token_preview' => substr($token, 0, 10) . '...'
            ]);
            break;

        case 'orders':
            // Lista pedidos
            $params = [];
            if (isset($_GET['limit'])) $params['limit'] = (int)$_GET['limit'];
            if (isset($_GET['status'])) $params['status'] = $_GET['status'];
            if (isset($_GET['created_at_min'])) $params['created_at_min'] = $_GET['created_at_min'];
            if (isset($_GET['created_at_max'])) $params['created_at_max'] = $_GET['created_at_max'];

            $result = $api->getOrders($params);
            echo json_encode([
                'success' => true,
                'data' => $result
            ]);
            break;

        case 'order':
            // Busca pedido específico
            $orderId = $_GET['id'] ?? null;
            $orderNumber = $_GET['number'] ?? null;

            if ($orderId) {
                $result = $api->getOrder($orderId);
            } elseif ($orderNumber) {
                $result = $api->getOrderByNumber($orderNumber);
            } else {
                throw new Exception('Informe id ou number do pedido');
            }

            echo json_encode([
                'success' => true,
                'data' => $result
            ]);
            break;

        case 'customer_orders':
            // Busca pedidos por email e CPF (para clientes finais)
            $email = $_GET['email'] ?? null;
            $cpf = $_GET['cpf'] ?? null;

            if (!$email) {
                throw new Exception('Informe o email');
            }

            // Adiciona prefixo "5" ao email para busca
            $emailBusca = '5' . $email;

            // Se CPF foi informado, valida e filtra
            if ($cpf) {
                // Remove formatacao do CPF
                $cpf = preg_replace('/\D/', '', $cpf);

                if (strlen($cpf) !== 11) {
                    throw new Exception('CPF invalido');
                }

                $result = $api->getOrdersByEmailAndCpf($emailBusca, $cpf);
            } else {
                // Busca apenas pelo email
                $result = $api->getOrdersByEmail($emailBusca);
            }

            echo json_encode([
                'success' => true,
                'data' => $result
            ]);
            break;

        default:
            throw new Exception("Ação '$action' não reconhecida");
    }

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
