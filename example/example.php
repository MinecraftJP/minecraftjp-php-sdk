<?php
require('../src/MinecraftJP.php');

$minecraftjp = new MinecraftJP(array(
    'clientId' => 'YOUR_CLIENT_ID',
    'clientSecret' => 'YOUR_CLIENT_SECRET',
));

if (isset($_GET['action']) && $_GET['action'] == 'logout') {
    $minecraftjp->logout();
}

try {
    $user = $minecraftjp->getUser();
} catch (Exception $e) {
    $error = $e->getMessage();
}

$loginUrl = $minecraftjp->getLoginUrl(array(
    'scope' => array('openid', 'profile', 'email', 'offline_access'),
));

?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>SDK Example</title>
</head>
<body>
    <h1>SDK Example</h1>

    <?php if (isset($error)): ?>
    <span style="color: red;"><?php echo $error; ?></span>
    <?php endif; ?>

    <?php if (!empty($user)): ?>
        <a href="?action=logout">Logout</a>
    <?php else: ?>
        <a href="<?php echo $loginUrl; ?>">Login with minecraft.jp</a>
    <?php endif; ?>

<?php
$token = $minecraftjp->getAccessToken();
if (!empty($token)) {
    echo '<h2>Access Token</h2><pre>' . $token . '</pre>';
}

$refreshToken = $minecraftjp->getRefreshToken();
if (!empty($refreshToken)) {
    echo '<h2>Refresh Token</h2><pre>' . $refreshToken . '</pre>';
}

?>

    <h2>User</h2>
    <pre><?php if (!empty($user)) echo json_encode($user, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT); ?></pre>

<?php
function formatHeaderName($name) {
    return str_replace(' ', '-', ucwords(str_replace('-', ' ', $name)));
}

$token = $minecraftjp->getAccessToken();
if (!empty($token)) {
    echo '<h2>My Servers</h2><pre>';

    $url = $minecraftjp->getUrl('api-1.0', 'servers/my.json');
    $urls = parse_url($url);

    echo "GET " . $urls['path'] . " HTTP/1.0\nHost: " . $urls['host'] . "\nAuthorization: Bearer {$token}\n\n";

    $res = $minecraftjp->request('GET', $url);

    echo 'HTTP/' . $res->getVersion() . ' ' . $res->getStatusCode() . ' ' . $res->getReasonPhrase() . "\n" ;
    foreach ($res->getHeader() as $k => $v) {
        echo formatHeaderName($k) . ': ' . $v . "\n";
    }
    echo "\n";

    $servers = json_decode($res->getBody());
    echo json_encode($servers, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    echo '</pre>';


}
?>
</body>
</html>
