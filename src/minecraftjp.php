<?php
/**
 * Minecraft.jp PHP SDK
 *
 * @copyright Copyright (c) 2014 Japan Minecraft Network All rights Reserved.
 * @license MIT License
 */
class MinecraftJP {
    const VERSION = '1.0.0';
    protected static $URL_TABLE = array(
        'oauth' => 'https://minecraft.jp/oauth/',
        'api' => 'https://api.minecraft.jp/',
    );

    /**
     * Client ID
     * @var string
     */
    protected $clientId;

    /**
     * Client Secret
     * @var string
     */
    protected $clientSecret;

    /**
     * Session storage
     * @var SessionStorageInterface
     */
    protected $sessionStorage;

    /**
     * Access token
     * @var string
     */
    protected $accessToken;

    /**
     * User object
     * @var mixed
     */
    protected $user;

    public function __construct($config) {
        $this->setClientId($config['clientId']);
        $this->setClientSecret($config['clientSecret']);

        if (!empty($config['sessionStorage']) && $config['sessionStorage'] instanceof SessionStorageInterafce) {
            $this->sessionStorage = $config['sessionStorage'];
        } else {
            $this->sessionStorage = new PHPSessionStorage('minecraftjpsdk_' . $this->getClientId() . '_');
        }
    }

    /**
     * Get User object
     *
     * @return mixed
     */
    public function getUser() {
        $this->user = $this->sessionStorage->read('user');
        if (!empty($this->user)) {
            return $this->user;
        }

        $this->exchangeToken();

        return $this->user;
    }

    /**
     * Get Access token.
     *
     * @return mixed
     */
    public function getAccessToken() {
        $this->accessToken = $this->sessionStorage->read('access_token');
        if (!empty($this->accessToken)) {
            return $this->accessToken;
        }

        $this->exchangeToken();

        return $this->accessToken;
    }

    /**
     * Get login url for redirect.
     *
     * @param array $options
     * @return string
     */
    public function getLoginUrl($options = array()) {
        $options = array_merge(array(
            'scope' => 'openid profile',
        ), $options);

        if (isset($options['scope']) && is_array($options['scope'])) {
            $options['scope'] = join(' ', $options['scope']);
        }

        // Generate nonce
        if (function_exists('openssl_random_pseudo_bytes')) {
            $nonce = sha1(openssl_random_pseudo_bytes(24));
        } else {
            $nonce = sha1(uniqid(mt_rand(), true));
        }
        $this->sessionStorage->write('nonce', $nonce);

        return $this->getUrl('oauth', 'authorize', array(
            'client_id' => $this->getClientId(),
            'response_type' => 'code',
            'scope' => $options['scope'],
            'redirect_uri' => isset($options['redirect_uri']) ? $options['redirect_uri'] : $this->getCurrentUrl(),
            'nonce' => $nonce,
        ));
    }

    /**
     * Do logout
     */
    public function logout() {
        $this->sessionStorage->remove('access_token');
        $this->sessionStorage->remove('user');
    }

    /**
     * Exchange code to access_token
     */
    protected function exchangeToken() {
        $result = $this->requestAccessToken();
        if ($result && !empty($result['access_token'])) {
            $this->accessToken = $result['access_token'];
            $this->sessionStorage->write('access_token', $result['access_token']);
            if (!empty($result['id_token'])) {
                $this->validateIdToken($result['id_token']);

                $this->user = $this->requestUserInfo();
                if ($this->user) {
                    $this->sessionStorage->write('user', $this->user);
                }
            }
        }
    }

    /**
     * Request User Info
     *
     * @return mixed
     */
    protected  function requestUserInfo() {
        $result = $this->sendRequest('GET', $this->getUrl('oauth', 'userinfo'), array(), array(
            'Authorization' => 'Bearer ' . $this->sessionStorage->read('access_token'),
        ));

        return json_decode($result, true);
    }

    /**
     * Request Access Token
     *
     * @return mixed|null
     * @throws Exception
     */
    protected  function requestAccessToken() {
        if (!empty($_REQUEST['code'])) {
            $result = $this->sendRequest('POST', $this->getUrl('oauth', 'token'), array(
                'code' => $_REQUEST['code'],
                'client_id' => $this->getClientId(),
                'client_secret' => $this->getClientSecret(),
                'grant_type' => 'authorization_code',
                'redirect_uri' => $this->getCurrentUrl(),
            ));
            if ($result && $result = json_decode($result, true)) {
                if (!empty($result['error'])) {
                    throw new Exception($result['error_description']);
                }

                return $result;
            }
        }
        return null;
    }

    /**
     * Build API Url
     *
     * @param $type
     * @param $path
     * @param array $params
     * @return string
     */
    protected function getUrl($type, $path, $params = array()) {
        $url = self::$URL_TABLE[$type] . $path;
        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }
        return $url;
    }

    /**
     * Send HTTP Request
     *
     * @param $method
     * @param $url
     * @param array $data
     * @param array $headers
     * @return string
     */
    protected function sendRequest($method, $url, $data = array(), $headers = array()) {
        $contextOptions = array(
            'http' => array(
                'method' => $method,
                'user_agent' => 'MinecraftJP-PHP-SDK/' . self::VERSION,
                'ignore_errors' => true,
            ),
        );

        if ($method == 'POST' && is_array($data)) {
            $formEncoded = http_build_query($data);
            $headers['Content-Type'] = 'application/x-www-form-urlencoded';
            $headers['Content-Length'] = strlen($formEncoded);
            $contextOptions['http']['content'] = $formEncoded;
        }

        $contextOptions['http']['header'] = '';
        foreach ($headers as $k => $v) {
            $contextOptions['http']['header'] .= $k . ': ' . $v . "\r\n";
        }
        $context = stream_context_create($contextOptions);

        return file_get_contents($url, false, $context);
    }

    /**
     * Get Current Url
     *
     * @return string
     */
    protected function getCurrentUrl() {
        if ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')) {
            $schema = 'https://';
        } else {
            $schema = 'http://';
        }

        $host = $_SERVER['HTTP_HOST'];

        if (preg_match('#:(\d+)$#', $host, $match)) {
            $port = ':' . $match[1];
        } else {
            $port = '';
        }
        $urls = parse_url($_SERVER['REQUEST_URI']);

        $path = $urls['path'];
        $query = '';

        return $schema . $host . $port . $path . $query;
    }

    /**
     * Get Public Key
     *
     * @param $kid
     * @return resource|void
     * @throws Exception
     */
    protected function getPublicKey($kid) {
        $publicKeyFile = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'minecraftjp.crt';
        if (file_exists($publicKeyFile)) {
            return openssl_pkey_get_public('file://' . $publicKeyFile);
        }

        if (empty($kid)) {
            throw new Exception('No such public key.');
        }

        $result = $this->sendRequest('GET', $this->getUrl('oauth', 'jwks'));
        if ($result && $result = json_decode($result, true)) {
            $len = count($result['keys']);
            for ($i = 0; $i < $len; $i++) {
                $key = $result['keys'][$i];
                if (!isset($key['kid']) || $key['kid'] != $kid) continue;

                // もうちょっとスマートにやりたい所
                // 2048bit MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
                // 4096bit MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
                $data = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A' . 'MIIBCgKCAQEA' . $key['n'] . 'ID' . $key['e'];
                $data = "-----BEGIN PUBLIC KEY----- \n" . wordwrap($data, 64, "\n", true) . "\n-----END PUBLIC KEY----- \n";

                $publicKey = openssl_pkey_get_public($data);
                if (!$publicKey) throw new Exception('Unable to fetch public key.');
                return $publicKey;
            }
        }
        throw new Exception('No such public key.');
    }

    /**
     * Validate ID Token
     *
     * @param $idToken
     * @return mixed
     * @throws Exception
     */
    protected function validateIdToken($idToken) {
        $segments = explode('.', $idToken);
        if (count($segments) != 3) {
            throw new InvalidIdTokenException('Invalid Token');
        }
        $header = json_decode($this->decodeBase64Url($segments[0]), true);
        if (empty($header)) {
            throw new InvalidIdTokenException('Invalid Token');
        }
        $payload = json_decode($this->decodeBase64Url($segments[1]), true);
        if (empty($payload)) {
            throw new InvalidIdTokenException('Invalid Token');
        }
        $signature = $this->decodeBase64Url($segments[2]);

        $signingInput = implode('.', array($segments[0], $segments[1]));
        $kid = isset($header['kid']) ? $header['kid'] : null;
        switch ($header['alg']) {
            case 'RS256':
            case 'RS384':
            case 'RS512':
                // 署名検証用に公開鍵を取得する
                $publicKey = $this->getPublicKey($kid);

                $algo = 'sha' . substr($header['alg'], 2);
                if (openssl_verify($signingInput, $signature, $publicKey, $algo) != 1) {
                    openssl_free_key($publicKey);
                    throw new InvalidIdTokenException('Signature Mismatch');
                }
                openssl_free_key($publicKey);
                break;
            default:
                throw new InvalidIdTokenException('Unsupported Algorithm: ' . $header['alg']);
        }

        // Check Issuer
        if ($payload['iss'] != 'minecraft.jp') {
            throw new InvalidIdTokenException('Invalid Issuer.');
        }

        // Check Client Id
        if ($payload['aud'] != $this->getClientId()) {
            throw new InvalidIdTokenException('Client ID Mismatch.');
        }

        // Check expired
        $now = time();
        if ($payload['exp'] < $now || $payload['iat'] < $now - 600) {
            throw new InvalidIdTokenException('ID Token expired.');
        }

        // Check nonce
        if ($payload['nonce'] != $this->sessionStorage->read('nonce')) {
            throw new InvalidIdTokenException('Nonce Mismatch.');
        }

        $this->sessionStorage->remove('nonce');

        return $payload;
    }

    /**
     * Decode Base64URL
     *
     * @param $base64url
     * @return string
     */
    protected function decodeBase64Url($base64url) {
        $base64 = strtr($base64url, '-_', '+/');
        return base64_decode($base64);
    }

    /**
     * @param string $clientId
     */
    public function setClientId($clientId) {
        if (empty($clientId)) {
            throw new InvalidArgumentException('clientId must not be null');
        }
        $this->clientId = $clientId;
    }

    /**
     * @return string
     */
    public function getClientId() {
        return $this->clientId;
    }

    /**
     * @param string $clientSecret
     */
    public function setClientSecret($clientSecret) {
        if (empty($clientSecret)) {
            throw new InvalidArgumentException('clientSecret must not be null');
        }
        $this->clientSecret = $clientSecret;
    }

    /**
     * @return string
     */
    public function getClientSecret() {
        return $this->clientSecret;
    }
}

class InvalidIdTokenException extends Exception {
    function __construct($message, $code = 0, Exception $previous = null) {
        parent::__construct($message, $code, $previous);
    }
}

interface SessionStorageInterafce {
    /**
     * Read from session
     *
     * @param $key string
     * @return mixed
     */
    public function read($key);

    /**
     * Write to session
     *
     * @param $key string
     * @param $value mixed
     * @return void
     */
    public function write($key, $value);

    /**
     * Remove session data
     * @param $key string
     * @return void
     */
    public function remove($key);
}

class PHPSessionStorage implements SessionStorageInterafce {
    protected $prefix;
    /**
     * Constructor
     */
    function __construct($prefix) {
        $this->prefix = $prefix;
        if (!session_id()) {
            session_start();
        }
    }

    /**
     * Read from session
     *
     * @param $key string
     * @return mixed
     */
    public function read($key) {
        return isset($_SESSION[$this->prefix . $key]) ? $_SESSION[$this->prefix . $key] : null;
    }

    /**
     * Write to session
     *
     * @param $key string
     * @param $value mixed
     * @return void
     */
    public function write($key, $value) {
        $_SESSION[$this->prefix . $key] = $value;
    }

    /**
     * Remove session data
     * @param $key string
     * @return void
     */
    public function remove($key) {
        unset($_SESSION[$this->prefix . $key]);
    }
}