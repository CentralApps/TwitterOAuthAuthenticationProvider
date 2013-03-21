<?php
namespace CentralApps\Authentication\Providers;

class TwitterProvider implements OAuthProviderInterface
{
	protected $request;
	protected $userFactory;
	protected $userGateway;
	protected $get = array();
	protected $session = array();
	protected $externalId;
	protected $callbacks = array();
	protected $consumerKey;
	protected $consumerSecret;
	protected $callbackPage;
	
	public function __construct(array $request, \CentralApps\Authentication\UserFactoryInterface $user_factory, \CentralApps\Authentication\UserGateway $user_gateway)
	{
		$this->request = $request;
		$this->userFactory = $user_factory;
		$this->userGateway = $user_gateway;
		
		if(is_array($request) && array_key_exists('get') && is_array($request['get'])) {
			$this->get = $request['get'];
		}
		if(is_array($request) && array_key_exists('session') && is_array($request['session'])) {
			$this->session = $request['session'];
		}
	}
	
	public function registerAttachCallback($callback)
	{
		$this->callbacks['attach'] = $callback;
	}
	
	public function registerRegisterCallback($callback)
	{
		$this->callbacks['register'] = $callback;
	}
	
	public function hasAttemptedToLoginWithProvider()
	{
		if(isset($this->get['oauth_verifier']) && isset($this->get['state']) && $this->get['state'] == 'twitter-login' && isset($this->session['oauth_token']) && isset($this->session['oauth_token_secret'])) {
			return true;
		}
		return false;
	}
	
	public function processLoginAttempt()
	{
		$connection = $this->getTwitterAPIConnection();
		$token_credentials = $connection->getAccessToken($this->get['oauth_verifier']);
		$content = $connection->get('account/verify_credentials');
		if($connection->http_code != 200) {
			return null;
		}
		$this->externalId = $content['id'];
		try {
 			 return $this->userFactory->getFromProvider($this);
		} catch (\Exception $e) {
			return null;
		}
		return null;
	}
	
	public function logout()
	{
		return true;
	}
	
	public function userWantsToBeRemembered()
	{
		return false;
	}
	
	public function shouldPersist()
	{
		return true;
	}
	public function getProviderName()
	{
		return 'twitter';	
	}
	
	public function getTokens()
	{
		return array();
	}
	
	public function getExternalId()
	{
		return $this->externalId;
	}
	
	protected function getTwitterAPIConnection()
	{
		if(isset($this->session['oauth_token']) && isset($this->session['oauth_token_secret'])) {
			$connection = new TwitterOAuth($this->consumerKey, $this->consumerSecret, $this->session['oauth_token'], $this->session['oauth_token_secret']);
		} else {
			$connection = new TwitterOAuth($this->consumerKey, $this->consumerSecret);
		}
		$connection->host = "https://api.twitter.com/1.1/";
		return $connection;
	}
	
	public function getLoginUrl()
	{
		return $this->buildRedirectUrl() . "state=twitter-login";	
	}
	
	public function getRegisterUrl()
	{
		return $this->buildRedirectUrl() . "state=twitter-register";	
	}
	
	public function getAttachUrl()
	{
		return $this->buildRedirectUrl() . "state=twitter-attach";	
	}
	
	protected function buildRedirectUrl()
	{
		$connection = $this->getTwitterAPIConnection();
		$callback = $this->callbackPage . parse_url($this->callbackPage, PHP_URL_QUERY) ? "?" : "";
		$temporary_credentials = $connection->getRequestToken($callback);
		$redirect_url = $connection->getAuthorizeURL($temporary_credentials);
		$glue = parse_url($this->callbackPage, PHP_URL_QUERY) ? "?" : "&";
		return $redirect_url . $glue;
	}

}
