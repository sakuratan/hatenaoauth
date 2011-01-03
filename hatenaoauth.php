<?php

/*
The MIT License

Copyright (c) 2011 sakuratan.biz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

require_once 'OAuth.php';

/**
 * Hatena OAuth API helper.
 * This class requires abraham's twitteroauth library. You can find
 * the library from https://github.com/abraham/twitteroauth.
 */
class HatenaOAuth
{
    /**
     * Request token URL.
     */
    public static $REQUEST_TOKEN_URL = 'https://www.hatena.com/oauth/initiate';

    /**
     * Authorize URL for smart phones.
     */
    public static $AUTHORIZE_TOUCH_URL = 'https://www.hatena.ne.jp/touch/oauth/authorize';

    /**
     * Authorize URL for cellar.
     */
    public static $AUTHORIZE_MOBILE_URL = 'http://www.hatena.ne.jp/mobile/oauth/authorize';

    /**
     * Authorize URL for PC.
     */
    public static $AUTHORIZE_URL = 'https://www.hatena.ne.jp/oauth/authorize';

    /**
     * Access token URL.
     */
    public static $ACCESS_TOKEN_URL = 'https://www.hatena.com/oauth/token';

    /**
     * Contains the last HTTP status code returned.
     */
    public $http_code;

    /**
     * Contains the last API call.
     */
    public $last_api_call;

    /**
     * Set timeout default.
     */
    public $timeout = 30;

    /**
     * Set connect timeout.
     */
    public $connecttimeout = 30;

    /**
     * Verify SSL Cert.
     */
    public $ssl_verifypeer = FALSE;

    /**
     * Respons format. xml, json or others.
     */
    public $format = 'xml';

    /**
     * Decode returned json data.
     */
    public $decode_json = TRUE;

    /**
     * OAuth token.
     */
    public $token = NULL;

    /**
     * Enable debugging.
     */
    public $debug = FALSE;

    private $sha1_method;
    private $consumer;

    /**
     * The constructor.
     * @param $consumer_key       Hatena OAuth Consomer token
     * @param $consumer_secret    Hatena OAuth Consomer secret
     * @param $oauth_token        Hatena OAuth token
     * @param $oauth_token_secret Hatena OAuth secret
     */
    function __construct($consumer_key, $consumer_secret, $oauth_token=NULL,
                         $oauth_token_secret=NULL)
    {
        $this->sha1_method = new OAuthSignatureMethod_HMAC_SHA1();
        $this->consumer = new OAuthConsumer($consumer_key, $consumer_secret);
        if ($oauth_token && $oauth_token_secret) {
            $this->token = new OAuthConsumer($oauth_token, $oauth_token_secret);
        }
    }

    // Create a cURL instance.
    private function curlInit()
    {
        $ci = curl_init();
        curl_setopt($ci, CURLOPT_CONNECTTIMEOUT, $this->connecttimeout);
        curl_setopt($ci, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ci, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ci, CURLOPT_SSL_VERIFYPEER, $this->ssl_verifypeer);
        if ($this->debug) {
            curl_setopt($ci, CURLOPT_VERBOSE, TRUE);
        }
        return $ci;
    }

    // Execute and close a cURL session.
    private function curlExecClose($ci, $url)
    {
        curl_setopt($ci, CURLOPT_URL, $url);
        $response = curl_exec($ci);
        $this->http_code = curl_getinfo($ci, CURLINFO_HTTP_CODE);
        $this->last_api_call = $url;
        curl_close($ci);
        return $response;
    }

    /**
     * Get a request token from Hatena.
     * @param $oauth_callback OAuth callback URL
     * @param $scope          OAuth scope
     * @return An OAuthConsumer object that contains request token
     */
    function getRequestToken($oauth_callback=NULL,
                             $scope='read_public,write_public')
    {
        $parameters = array();
        if ($oauth_callback) {
            $parameters['oauth_callback'] = $oauth_callback;
        }
        if ($scope) {
            $parameters['scope'] = $scope;
        }

        $request = OAuthRequest::from_consumer_and_token(
            $this->consumer, $this->token, 'POST',
            HatenaOAuth::$REQUEST_TOKEN_URL, $parameters);
        $request->sign_request($this->sha1_method, $this->consumer,
                               $this->token);

        $ci = $this->curlInit();
        curl_setopt($ci, CURLOPT_POST, TRUE);
        curl_setopt($ci, CURLOPT_HTTPHEADER, array($request->to_header()));
        curl_setopt($ci, CURLOPT_POSTFIELDS, array('scope' => $scope));
        $response = $this->curlExecClose($ci,
                                         $request->get_normalized_http_url());

        $token = OAuthUtil::parse_parameters($response);
        $this->token = new OAuthConsumer($token['oauth_token'],
                                         $token['oauth_token_secret']);
        return $token;
    }

    /**
     * Get the authorize URL for device.
     * @param $token OAuth token
     * @param $device 'pc' or 'touch' or 'mobile'
     * @return An authorize URL string
     */
    function getAuthorizeURL($token, $device='pc')
    {
        if (is_array($token)) {
            $token = $token['oauth_token'];
        }
        switch ($device) {
        case 'touch':
        case 'smartphone':
        case 'smart-phone':
            $url = HatenaOAuth::$AUTHORIZE_TOUCH_URL;
            break;
        case 'ktai':
        case 'k-tai':
        case 'mobile':
            $url = HatenaOAuth::$AUTHORIZE_MOBILE_URL;
            break;
        case 'pc':
        default:
            $url = HatenaOAuth::$AUTHORIZE_URL;
            break;
        }
        return "{$url}?oauth_token=" . urlencode($token);
    }

    /**
     * Exchange request token and secret for an access token and
     * secret, to sign API calls.
     * @param $oauth_verifier oauth_verifer that returned from Hatena
     * @return An OAuthConsumer object that contains access token
     */
    function getAccessToken($oauth_verifier=FALSE)
    {
        $parameters = array();
        if ($oauth_verifier) {
            $parameters['oauth_verifier'] = $oauth_verifier;
        }

        $request = OAuthRequest::from_consumer_and_token(
            $this->consumer, $this->token, 'POST',
            HatenaOAuth::$ACCESS_TOKEN_URL, $parameters);
        $request->sign_request($this->sha1_method, $this->consumer,
                               $this->token);

        $ci = $this->curlInit();
        curl_setopt($ci, CURLOPT_POST, TRUE);
        curl_setopt($ci, CURLOPT_HTTPHEADER, array($request->to_header()));
        $response = $this->curlExecClose($ci,
                                         $request->get_normalized_http_url());

        $token = OAuthUtil::parse_parameters($response);
        $this->token = new OAuthConsumer(
            $token['oauth_token'], $token['oauth_token_secret']);
        return $token;
    }

    /**
     * Format and sign an OAuth / API request.
     * @param $url         API end point URL
     * @param $method     'GET', 'POST', 'PUT' or 'DELETE'
     * @param $parameters parameters for API
     * @return API results
     */
    function oAuthRequest($url, $method, $parameters=array())
    {
        if ($method == 'GET') {
            $request = OAuthRequest::from_consumer_and_token(
                $this->consumer, $this->token, $method, $url, $parameters);
        } else {
            $request = OAuthRequest::from_consumer_and_token(
                $this->consumer, $this->token, $method, $url);
        }
        $request->sign_request($this->sha1_method, $this->consumer,
                               $this->token);

        $ci = $this->curlInit();
        $headers = array($request->to_header());
        if ($this->format == 'xml') {
            $headers[] = 'Content-Type: text/xml';
        }
        curl_setopt($ci, CURLOPT_HTTPHEADER, $headers);
        switch ($method) {
        case 'GET':
            $url = $request->get_normalized_http_url();
            if ($parameters) {
                $url .= '?' . OAuthUtil::build_http_query($parameters);
            }
            break;
        default:
            $url = $request->get_normalized_http_url();
            if ($method == 'POST') {
                curl_setopt($ci, CURLOPT_POST, TRUE);
            } else {
                curl_setopt($ci, CURLOPT_CUSTOMREQUEST, $method);
            }
            if ($parameters) {
                curl_setopt($ci, CURLOPT_POSTFIELDS, $parameters);
            }
            break;
        }

        return $this->curlExecClose($ci, $url);
    }

    /**
     * GET wrapper for oAuthRequest.
     * @param $url         API end point URL
     * @param $parameters parameters for API
     * @return API results
     */
    function get($url, $parameters=array())
    {
        $response = $this->oAuthRequest($url, 'GET', $parameters);
        if ($this->format === 'json' && $this->decode_json) {
            return json_decode($response);
        }
        return $response;
    }

    /**
     * POST wrapper for oAuthRequest.
     * @param $url         API end point URL
     * @param $parameters parameters for API
     * @return API results
     */
    function post($url, $parameters=array())
    {
        $response = $this->oAuthRequest($url, 'POST', $parameters);
        if ($this->format === 'json' && $this->decode_json) {
            return json_decode($response);
        }
        return $response;
    }

    /**
     * PUT wrapper for oAuthRequest.
     * @param $url         API end point URL
     * @param $parameters parameters for API
     * @return API results
     */
    function put($url, $parameters='')
    {
        $response = $this->oAuthRequest($url, 'PUT', $parameters);
        if ($this->format === 'json' && $this->decode_json) {
            return json_decode($response);
        }
        return $response;
    }

    /**
     * DELETE wrapper for oAuthRequest.
     * @param $url         API end point URL
     * @param $parameters parameters for API
     * @return API results
     */
    function delete($url, $parameters='')
    {
        $response = $this->oAuthRequest($url, 'DELETE', $parameters);
        if ($this->format === 'json' && $this->decode_json) {
            return json_decode($response);
        }
        return $response;
    }
}

// vim:sw=4:et:
