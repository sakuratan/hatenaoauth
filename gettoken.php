<?php

require_once 'hatenaoauth.php';

// Enter your Hatena OAuth consumer token and secret.
$CONSUMER_TOKEN = 'ENTER YOUR CONSUMER TOKEN';
$CONSUMER_SECRET = 'ENTER YOUR CONSUMER SECRET';

// Enter OAuth callback URL. You cannot ommit this URL.
$CALLBACK_URL = "http://{$_SERVER['HTTP_HOST']}{$_SERVER['PHP_SELF']}";

// Setup accessing scope.
$SCOPE = 'read_public,write_public';

// Create an instance.
$h = new HatenaOAuth($CONSUMER_TOKEN, $CONSUMER_SECRET);

// Using session to keep request token.
session_start();

if (isset($_GET['oauth_token']) && isset($_GET['oauth_verifier']) &&
    $_GET['oauth_token'] == $_SESSION['token']['oauth_token']) {
    // User accept the OAuth permissions to your application.
    $h->token = new OAuthToken($_SESSION['token']['oauth_token'],
                               $_SESSION['token']['oauth_token_secret']);
    $t = $h->getAccessToken($_GET['oauth_verifier']);

    echo "Your Hatena id is {$t['url_name']}.<br />";
    echo "Copy the following code to bookmark.php.<br />";
    echo "\$OAUTH_TOKEN = '{$t['oauth_token']}';<br />";
    echo "\$OAUTH_TOKEN_SECRET = '{$t['oauth_token_secret']}';<br />";

    session_destroy();

} else {
    // Get request token.
    $_SESSION['token'] = $h->getRequestToken($CALLBACK_URL, $SCOPE);

    // Direct OAuth permissions submittion page URL.
    $url = $h->getAuthorizeURL($_SESSION['token']);
    echo '<a href="' . $url . '">Click here to get access token</a>';
}

// vim:sw=4:et:
