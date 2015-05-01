<?php
/**
 * Minecraft.jp PHP SDK
 *
 * @copyright Copyright (c) 2014 Japan Minecraft Network All rights Reserved.
 * @license MIT License
 */
class MinecraftJP {
    const VERSION = '1.1.1';
    protected static $URL_TABLE = array(
        'oauth' => 'https://minecraft.jp/oauth/',
        'api-1.0' => 'https://api.minecraft.jp/1.0/',
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
     * Redirect URI
     * @var string
     */
    protected $redirectUri;

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
     * Refresh token
     * @var string
     */
    protected $refreshToken;

    /**
     * User object
     * @var mixed
     */
    protected $user;

    public function __construct($config) {
        $this->setClientId($config['clientId']);
        $this->setClientSecret($config['clientSecret']);
        $this->setRedirectUri($config['redirectUri']);

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
     * Get Refresh token.
     *
     * @return mixed
     */
    public function getRefreshToken() {
        if (empty($this->refreshToken)) {
            $this->refreshToken = $this->sessionStorage->read('refresh_token');
            return $this->refreshToken;
        }
        return $this->refreshToken;
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
            'redirect_uri' => isset($options['redirect_uri']) ? $options['redirect_uri'] : $this->redirectUri,
            'nonce' => $nonce,
        ));
    }

    /**
     * Do logout
     */
    public function logout() {
        $this->sessionStorage->remove('access_token');
        $this->sessionStorage->remove('refresh_token');
        $this->sessionStorage->remove('user');
    }

    public function request($method, $url, $data = array(), $headers = array(), $options = array()) {
        $options = array_merge(array(
            'refresh_token' => true,
        ), $options);

        $headers = array_merge(array(
            'Authorization' => 'Bearer ' . $this->getAccessToken(),
        ), $headers);

        $res = $this->sendRequest($method, $url, $data, $headers);
        if ($res->getStatusCode() == 401 && preg_match('#^Bearer\s(.*)$#i', $res->getHeader('WWW-Authenticate'), $match)) {
            if (preg_match('#error="(.*?)"#', $match[1], $match)) {
                $error = $match[1];
                // trying refresh
                if ($error == 'invalid_token' && $options['refresh_token']) {
                    $this->refreshToken();
                    $options['refresh_token'] = false;
                    $headers['Authorization'] = 'Bearer ' . $this->getAccessToken();
                    return $this->request($method, $url, $data, $headers, $options);
                }
            }
        }
        return $res;
    }

    /**
     * Exchange code to access_token
     */
    protected function exchangeToken() {
        $result = $this->requestAccessToken();
        if ($result && !empty($result['access_token'])) {
            $this->accessToken = $result['access_token'];
            $this->sessionStorage->write('access_token', $result['access_token']);
            if (!empty($result['refresh_token'])) {
                $this->refreshToken = $result['refresh_token'];
                $this->sessionStorage->write('refresh_token', $result['refresh_token']);
            }
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
     * Refresh token
     */
    public function refreshToken() {
        $refreshToken = $this->getRefreshToken();
        if (empty($refreshToken)) {
            throw new InvalidTokenException('refresh token not available.');
        }
        $res = $this->sendRequest('POST', $this->getUrl('oauth', 'token'), array(
            'refresh_token' => $refreshToken,
            'client_id' => $this->getClientId(),
            'client_secret' => $this->getClientSecret(),
            'grant_type' => 'refresh_token',
        ));
        $result = $res->getBody();
        if ($result && $result = json_decode($result, true)) {
            if (!empty($result['error'])) {
                throw new Exception($result['error_description']);
            } else if (!empty($result['access_token'])) {
                $this->accessToken = $result['access_token'];
                $this->sessionStorage->write('access_token', $result['access_token']);
                return true;
            }
        }
        throw new Exception('failed to refreshing token.');
    }

    /**
     * Request User Info
     *
     * @return mixed
     */
    protected  function requestUserInfo() {
        $res = $this->sendRequest('GET', $this->getUrl('oauth', 'userinfo'), array(), array(
            'Authorization' => 'Bearer ' . $this->sessionStorage->read('access_token'),
        ));
        $result = $res->getBody();

        return json_decode($result, true);
    }

    /**
     * Request Access Token
     *
     * @return mixed|null
     * @throws Exception
     */
    protected function requestAccessToken() {
        $code = $this->getRequestVar('code');
        if (!empty($code)) {
            $res = $this->sendRequest('POST', $this->getUrl('oauth', 'token'), array(
                'code' => $code,
                'client_id' => $this->getClientId(),
                'client_secret' => $this->getClientSecret(),
                'grant_type' => 'authorization_code',
                'redirect_uri' => $this->redirectUri,
            ));
            $result = $res->getBody();
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
    public function getUrl($type, $path, $params = array()) {
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

        $body = file_get_contents($url, false, $context);
        return new HttpResponse($http_response_header, $body);
    }

    /**
     * Get Current Url
     *
     * @return string
     */
    protected function getCurrentUrl() {
        $isHttps = $this->getServerVar('HTTPS');
        $forwardedProto = $this->getServerVar('HTTP_X_FORWARDED_PROTO');
        if ($isHttps == 'on' || $forwardedProto === 'https') {
            $schema = 'https://';
        } else {
            $schema = 'http://';
        }

        $host = $this->getServerVar('HOST');

        if (preg_match('#:(\d+)$#', $host, $match)) {
            $port = ':' . $match[1];
        } else {
            $port = '';
        }
        $urls = parse_url($this->getServerVar('REQUEST_URI'));

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
        $publicKeyFile = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'MinecraftJP.crt';
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

    protected function getRequestVar($name) {
        if (function_exists('request_var')) {
            return request_var($name, '');
        } else {
            return $_REQUEST[$name];
        }
    }

    protected function getServerVar($name) {
        if (function_exists('request_var')) {
            return request_var($name, '');
        } else {
            return $_SERVER[$name];
        }
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

    /**
     * @param $redirectUri
     */
    public function setRedirectUri($redirectUri) {
        if (empty($redirectUri)) {
            $redirectUri = $this->getCurrentUrl();
        }
        $this->redirectUri = $redirectUri;
    }

    /**
     * @return string
     */
    public function getRedirectUri() {
        return $this->redirectUri;
    }
}

class InvalidTokenException extends Exception {
    function __construct($message, $code = 0, Exception $previous = null) {
        parent::__construct($message, $code, $previous);
    }
}

class InvalidIdTokenException extends Exception {
    function __construct($message, $code = 0, Exception $previous = null) {
        parent::__construct($message, $code, $previous);
    }
}

class HttpResponse {
    private $version;
    private $statusCode;
    private $reasonPhrase;
    private $headers = array();
    private $body;

    public function __construct($headers, $body) {
        $parts = explode(' ', $headers[0]);
        $this->version = str_replace('HTTP/', '', $parts[0]);
        $this->statusCode = intval($parts[1]);
        $this->reasonPhrase = $parts[2];
        for ($i = 1; $i < count($headers); $i++) {
            $parts = explode(': ', $headers[$i], 2);
            $this->headers[strtolower($parts[0])] = $parts[1];
        }
        $this->body = $body;
    }

    public function getVersion() {
        return $this->version;
    }

    public function getStatusCode() {
        return $this->statusCode;
    }

    public function getReasonPhrase() {
        return $this->reasonPhrase;
    }

    public function getHeader($key = null) {
        if (is_null($key)) {
            return $this->headers;
        } else {
            $key = strtolower($key);
            return isset($this->headers[$key]) ? $this->headers[$key] : null;
        }
    }

    public function isOk() {
        return in_array($this->statusCode, array(200, 201, 202, 203, 204, 205, 206));
    }

    public function getBody() {
        return $this->body;
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
