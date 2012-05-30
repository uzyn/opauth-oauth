<?php
/**
 * OAuth
 * 
 * Generic Opauth strategy implementing OAuth
 * More information on Opauth: http://opauth.org
 * 
 * @copyright    Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.OAuthStrategy
 * @license      MIT License
 */

class OAuthStrategy extends OpauthStrategy{
	
	/**
	 * Compulsory configuration options
	 */
	public $expects = array(
		'consumer_key', 		
		'consumer_secret',
		'request_token_url',
		'access_token_url'
	);
	
	/**
	 * Compulsory configuration options
	 */
	public $defaults = array(
		'method' => 'POST', 		// The HTTP method being used. e.g. POST, GET, HEAD etc 
		'oauth_callback' => '{complete_url_to_strategy}oauth_callback',
		
		// From tmhOAuth
		// Refer to Vendor/tmhOAuth/tmhOAuth.php for details on these
		'user_token'					=> '',
		'user_secret'					=> '',
		'use_ssl'						=> true,
		'debug'							=> false,
		'force_nonce'					=> false,
		'nonce'							=> false, // used for checking signatures. leave as false for auto
		'force_timestamp'				=> false,
		'timestamp'						=> false, // used for checking signatures. leave as false for auto
		'oauth_version'					=> '1.0',
		'curl_connecttimeout'			=> 30,
		'curl_timeout'					=> 10,
		'curl_ssl_verifypeer'			=> false,
		'curl_followlocation'			=> false, // whether to follow redirects or not
		'curl_proxy'					=> false, // really you don't want to use this if you are using streaming
		'curl_proxyuserpwd'				=> false, // format username:password for proxy, if required
		'is_streaming'					=> false,
		'streaming_eol'					=> "\r\n",
		'streaming_metrics_interval'	=> 60,
		'as_header'				  		=> true,
	);
	
	/**
	 * tmhOAuth instance
	 */
	private $tmhOAuth;
	
	public function __construct($strategy, $env){
		parent::__construct($strategy, $env);
		
		$this->strategy['consumer_key'] = $this->strategy['consumer_key'];
		$this->strategy['consumer_secret'] = $this->strategy['consumer_secret'];
		
		require dirname(__FILE__).'/Vendor/tmhOAuth/tmhOAuth.php';
		$this->tmhOAuth = new tmhOAuth($this->strategy);
	}
	
	/**
	 * Auth request
	 */
	public function request(){
		$params = array(
			'oauth_callback' => $this->strategy['oauth_callback']
		);

		$results =  $this->_request('POST', $this->strategy['request_token_url'], $params);
		
		if ($results !== false && !empty($results['oauth_token']) && !empty($results['oauth_token_secret'])){
			session_start();
			$_SESSION['_opauth_oauth'] = $results;
			$this->_authorize($results['oauth_token']);
		}
		else{
			$error = array(
				'provider' => 'OAuth',
				'code' => 'request_token_error',
				'raw' => $results
			);

			$this->errorCallback($error);
		}
	}

	/**
	 * Receives oauth_verifier, requests for access_token and redirect to callback
	 */
	public function oauth_callback(){
		session_start();
		$session = $_SESSION['_opauth_oauth'];
		unset($_SESSION['_opauth_oauth']);
		
		$this->tmhOAuth->config['user_token'] = $session['oauth_token'];
		$this->tmhOAuth->config['user_secret'] = $session['oauth_token_secret'];

		$results =  $this->_request('POST', $this->strategy['access_token_url']);
		
		$this->auth = array(
			'provider' => 'oauth',
			'uid' => null,
			'credentials' => array(
				'token' => $results['oauth_token'],
				'secret' => $results['oauth_token_secret']
			),
		);
		
		$this->callback();
	}
	
	/**
	 * Sends user to provider's site for authentication
	 * calls back to oauth_callback() when done
	 */
	private function _authorize($oauth_token){
		// Sends to provider's site
		
		// Simulate calls to callback
		// For actual scenario, this should be done at the provider's site and not here
		$this->redirect($this->strategy['oauth_callback']);
	}
	
	
	/**
	 * Wrapper of tmhOAuth's request() with Opauth's error handling.
	 * 
	 * request():
	 * Make an HTTP request using this library. This method doesn't return anything.
	 * Instead the response should be inspected directly.
	 *
	 * @param string $method the HTTP method being used. e.g. POST, GET, HEAD etc
	 * @param string $url the request URL without query string parameters
	 * @param array $params the request parameters as an array of key=value pairs
	 * @param string $useauth whether to use authentication when making the request. Default true.
	 * @param string $multipart whether this request contains multipart data. Default false
	 */	
	private function _request($method, $url, $params = array(), $useauth = true, $multipart = false){
		$code = $this->tmhOAuth->request($method, $url, $params, $useauth, $multipart);

		if ($code == 200){
			$response = $this->tmhOAuth->extract_params($this->tmhOAuth->response['response']);
			return $response;		
		}
		else {
			$error = array(
				'provider' => 'OAuth',
				'code' => $code,
				'raw' => $this->tmhOAuth->response['response']
			);

			$this->errorCallback($error);
			
			return false;
		}
		
		
	}
	
}