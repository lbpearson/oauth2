<?php
namespace LBPearson\OAuth2;

use \Firebase\JWT\JWT;

class Azure
{
  public $client_id;
  public $state;
  public $logout_url;
  private $client_secret;
  private $tenant;
  private $redirect_uri;
  private $policy;
  private $policy_qs = "";
  private $key_url;
  private $authorize_url;
  private $token_url;
  private $RSA;
  private $JWT;
  
  function __construct() {
    $this->client_id = getenv('AZURE_AD_CLIENT_ID');
    $this->client_secret = getenv('AZURE_AD_CLIENT_SECRET');
    $this->tenant = getenv('AZURE_AD_TENANT_ID');
    $this->redirect_uri = getenv('AZURE_AD_REDIRECT_URI');

    $this->key_url = "https://login.microsoftonline.com/" . $this->tenant . "/discovery/v2.0/keys";
    $this->authorize_url = "https://login.microsoftonline.com/" . $this->tenant . "/oauth2/v2.0/authorize";
    $this->token_url = "https://login.microsoftonline.com/" . $this->tenant . "/oauth2/v2.0/token";
    $this->logout_url = "https://login.microsoftonline.com/" . $this->tenant . "/oauth2/v2.0/logout";
  }

  public function getAuthorizeUrl() {
    $authorize_params = array(
      'client_id' => $this->client_id,
      'response_type' => 'id_token',
      'redirect_uri' => $this->redirect_uri,
      'response_mode' => 'form_post',
      'scope' => 'openid',
      'state' => base64_encode(uniqid()),
      'nonce' => '678910'
    );
    
    $authorize_querystring = http_build_query($authorize_params);
    $authorize_url = $this->authorize_url . "?" . $authorize_querystring;
    return $authorize_url;
  }

  public function validateIDToken($id_token) {
    $used_key = $this->getUsedKey($id_token);
    
    $public_key = $this->getPublicKey($used_key);

    $decoded = JWT::decode($id_token, $public_key, ['RS256']);
    
    return $decoded;
  }
  
  public function getLogoutUrl($redirect_to=false) {
    if (empty($redirect_to)) {
      return false;
    }
    $logout_params = array(
      "post_logout_redirect_uri" => $redirect_to
    );
   
    $logout_params_qs = "?" . http_build_query($logout_params);
    return $this->logout_url . $logout_params_qs;
  }
 
  private function getUsedKey($id_token) {
    $token_parts = $this->splitIDToken($id_token);
    $header = json_decode(base64_decode($token_parts['header']));

    $available_keys = $this->getAvailableKeys();

    foreach ($available_keys as $available_key) {
      if ($available_key->kid == $header->kid) {
        return $available_key;
      }
    }

    return false;
  }

  public function getPayload($id_token) {
    $token_parts = $this->splitIDToken($id_token);
    $payload = json_decode(base64_decode($token_parts['payload']));

    return $payload;
  }

  public function getPublicKey($key_info)
  {
    $public_key = '';

    if (isset($key_info->x5c) && is_array($key_info->x5c)) {
      foreach ($key_info->x5c as $encodedkey) {
        $cert =
            '-----BEGIN CERTIFICATE-----' . PHP_EOL
            . chunk_split($encodedkey, 64,  PHP_EOL)
            . '-----END CERTIFICATE-----' . PHP_EOL;
        $cert_object = openssl_x509_read($cert);
        if ($cert_object === false) {
          throw new \RuntimeException('An attempt to read ' . $encodedkey . ' as a certificate failed.');
        }
        $pkey_object = openssl_pkey_get_public($cert_object);
        if ($pkey_object === false) {
          throw new \RuntimeException('An attempt to read a public key from a ' . $encodedkey . ' certificate failed.');
        }
        $pkey_array = openssl_pkey_get_details($pkey_object);
        if ($pkey_array === false) {
          throw new \RuntimeException('An attempt to get a public key as an array from a ' . $encodedkey . ' certificate failed.');
        }
        $public_key = $pkey_array['key'];
      }
    }

    return $public_key;
  }

  private function splitIDToken($id_token) {
    $token_parts = explode(".", $id_token);
    $return['header'] = $token_parts[0];
    $return['payload'] = $token_parts[1];
    $return['signature'] = $token_parts[2];
    return $return;
  }

  
  private function getAvailableKeys() {
    $azure_keys = json_decode(file_get_contents($this->key_url));
    return $azure_keys->keys;
  }
}
