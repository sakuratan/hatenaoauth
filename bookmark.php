<?php

require_once 'hatenaoauth.php';

// Enter your Hatena OAuth consumer token and secret.
$CONSUMER_TOKEN = 'ENTER YOUR CONSUMER TOKEN';
$CONSUMER_SECRET = 'ENTER YOUR CONSUMER SECRET';

// Copy and paste your OAuth token from gettoken.php.
$OAUTH_TOKEN = 'ENTER YOUR OAUTH TOKEN';
$OAUTH_TOKEN_SECRET = 'ENTER YOUR OAUTH SECRET';

// Create an instance.
$h = new HatenaOAuth($CONSUMER_TOKEN, $CONSUMER_SECRET,
                     $OAUTH_TOKEN, $OAUTH_TOKEN_SECRET);

// Don't forget to set valid API format.
$h->format = 'xml';

// Try to call Hatena Bookmark API.
$url = 'http://hatena.ne.jp/';
$message = '';
$xml =<<<__XML__
<entry xmlns="http://purl.org/atom/ns#">
<title>dummy</title>
<link rel="related" type="text/html" href="{$url}" />
<summary type="text/plain">{$message}</summary>
</entry>
__XML__;

$data = $h->post('http://b.hatena.ne.jp/atom/post', $xml);
var_dump($data);

// vim:sw=4:et:
