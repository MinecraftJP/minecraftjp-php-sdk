minecraft.jp PHP SDK

Usage
-----
```php
require('minecraftjp-php-sdk/src/MinecraftJP.php');

$minecraftjp = new MinecraftJP(array(
    'clientId' => 'YOUR_CLIENT_ID',
    'clientSecret' => 'YOUR_CLIENT_SECRET',
));

// Get User
$user = $minecraftjp->getUser();

// Get Access Token
$accessToken = $minecraftjp->getAccessToken();

// Get login url for redirect
$loginUrl = $minecraftjp->getLoginUrl();
echo '<a href="' . $loginUrl . '">Login with minecraft.jp</a>';

```
