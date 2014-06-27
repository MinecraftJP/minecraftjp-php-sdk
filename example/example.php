<?php
require('../src/minecraftjp.php');

$minecraftjp = new MinecraftJP(array(
    'clientId' => 'd95119dcd37b33ccb7c8',
    'clientSecret' => 'd8e552e9c35152c2771eaaa271e7acaa5603b503',
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
    'scope' => array('openid', 'profile', 'email'),
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

    <h2>User</h2>
    <pre><?php if (!empty($user)) echo json_encode($user, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT); ?></pre>

</body>
</html>
