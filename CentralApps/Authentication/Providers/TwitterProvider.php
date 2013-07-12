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
	protected $consumerKey;
	protected $consumerSecret;
	protected $callbackPage;
	protected $oAuthToken;
	protected $oAuthTokenSecret;
	protected $persistantTokensLookedUp = false;
    protected $externalUsername = null;
    protected $externalDisplayName = null;
	
	public function __construct(array $request, \CentralApps\Authentication\UserFactoryInterface $user_factory, \CentralApps\Authentication\UserGateway $user_gateway)
	{
		$this->request = $request;
		$this->userFactory = $user_factory;
		$this->userGateway = $user_gateway;
		
		if(is_array($request) && array_key_exists('get', $request) && is_array($request['get'])) {
			$this->get = $request['get'];
		}
		if(is_array($request) && array_key_exists('session', $request) && is_array($request['session'])) {
			$this->session = $request['session'];
		}
		
		$this->lookupPersistantOAuthTokenDetails();
	}
	
	protected function lookupPersistantOAuthTokenDetails()
	{
		if(!$this->persistantTokensLookedUp) {
			$this->oAuthToken = (isset($this->session['oauth_token'])) ? $this->session['oauth_token'] : null;
			$this->oAuthTokenSecret = (isset($this->session['oauth_token_secret'])) ? $this->session['oauth_token_secret'] : null;
		}
		$this->persistantTokensLookedUp = true;
	}
    
    public function getExternalDisplayName()
    {
        return $this->externalDisplayName;
    }
	
	protected function persistOAuthToken($token)
	{
		$_SESSION['oauth_token'] = $token;
	}
	
	protected function clearPersistedTokens()
	{
		unset($_SESSION['oauth_token']);
		unset($_SESSION['oauth_token_secret']);
	}
	
	protected function persistOAuthTokenSecret($secret)
	{
		$_SESSION['oauth_token_secret'] = $secret;
	}
	
	public function hasAttemptedToLoginWithProvider()
	{
		return $this->hasAttemptedToPerformActionWithState('twitter-login');
	}
	
	public function isAttemptingToAttach()
	{
		return $this->hasAttemptedToPerformActionWithState('twitter-attach');
	}
	
	public function isAttemptingToRegister()
	{
		return $this->hasAttemptedToPerformActionWithState('twitter-register');
	}
	
	protected function hasAttemptedToPerformActionWithState($state)
	{
		$this->lookupPersistantOAuthTokenDetails();
		if(isset($this->get['oauth_verifier']) && isset($this->get['state']) && $this->get['state'] == $state && !is_null($this->oAuthToken) && ! is_null($this->oAuthTokenSecret)) {
			return true;
		}
		return false;
	}
    
    // TODO: use this to remove the repetition from below
    public function verifyTokens()
    {
        $connection = $this->getTwitterAPIConnection();
        $content = $connection->get('account/verify_credentials');
        if($connection->http_code != 200) {
            return false;
        } else {
            $this->externalId = $content->id;
            $this->externalUsername = $content->screen_name;
            $this->externalDisplayName = $content->name;
            return $content;
        }
    }
    
    public function setOAuthToken($token)
    {
        $this->oAuthToken = $token;
    }
    
    public function setOAuthTokenSecret($secret)
    {
        $this->oAuthTokenSecret = $secret;
    }
    
    public function getExternalUsername()
    {
        return $this->externalUsername;
    }
    
    public function handleAttach()
    {
        if(!is_null($this->userGateway->user)) {
            $connection = $this->getTwitterAPIConnection();
            $this->clearPersistedTokens();
            $token_credentials = $connection->getAccessToken($this->get['oauth_verifier']);
            $this->oAuthToken = $token_credentials['oauth_token'];
            $this->oAuthTokenSecret = $token_credentials['oauth_token_secret'];
            $connection = $this->getTwitterAPIConnection();
            $content = $connection->get('account/verify_credentials');
            if($connection->http_code != 200) {
                return false;
            }
            $this->externalId = $content->id;
            $this->externalUsername = $content->screen_name;
            $this->externalDisplayName = $content->name;
            try {
                 $this->userGateway->attachTokensFromProvider($this);
                 return true;
            } catch (\Exception $e) {
                return false;
            }
            return false;
        } else {
            // exception?
            return false;
        }
        
    }
    
    public function handleRegister()
    {
        if(!is_null($this->userGateway->user)) {
            return false; // cant't oauth register when user is logged in!
        } else {
            $connection = $this->getTwitterAPIConnection();
            $this->clearPersistedTokens();
            $token_credentials = $connection->getAccessToken($this->get['oauth_verifier']);
            $this->oAuthToken = $token_credentials['oauth_token'];
            $this->oAuthTokenSecret = $token_credentials['oauth_token_secret'];
            $connection = $this->getTwitterAPIConnection();
            $content = $connection->get('account/verify_credentials');
            if($connection->http_code != 200) {
                return false;
            }

            $this->externalId = $content->id;
            $this->externalUsername = $content->screen_name;
            $this->externalDisplayName = $content->name;
            try {
                 $this->userGateway->registerUserFromProvider($this);
                 return true;
            } catch (\Exception $e) {
                return false;
            }
            return false;
        }
    }
	
	public function processLoginAttempt()
	{	    
		$connection = $this->getTwitterAPIConnection();
		$this->clearPersistedTokens();
		$token_credentials = $connection->getAccessToken($this->get['oauth_verifier']);
		$this->oAuthToken = $token_credentials['oauth_token'];
		$this->oAuthTokenSecret = $token_credentials['oauth_token_secret'];
        $connection = $this->getTwitterAPIConnection();
		$content = $connection->get('account/verify_credentials');
		if($connection->http_code != 200) {
			return null;
		}
		$this->externalId = $content->id;
        $this->externalUsername = $content->screen_name;
        $this->externalDisplayName = $content->name;
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
		return array('oauth_token' => $this->oAuthToken, 'oauth_token_secret' => $this->oAuthTokenSecret);
	}
	
	public function getExternalId()
	{
		return $this->externalId;
	}
	
	protected function getTwitterAPIConnection($ignore_set_tokens=false)
	{
		if(!is_null($this->oAuthToken) && !is_null($this->oAuthTokenSecret) && ! $ignore_set_tokens) {
			$connection = new \TwitterOAuth($this->consumerKey, $this->consumerSecret, $this->oAuthToken, $this->oAuthTokenSecret);
		} else {
			$connection = new \TwitterOAuth($this->consumerKey, $this->consumerSecret);
		}
		$connection->host = "https://api.twitter.com/1.1/";
		return $connection;
	}
	
	public function getLoginUrl()
	{
		return $this->buildRedirectUrl('state=twitter-login');	
	}
	
	public function getRegisterUrl()
	{
		return $this->buildRedirectUrl('state=twitter-register');	
	}
	
	public function getAttachUrl()
	{
		return $this->buildRedirectUrl('state=twitter-attach');	
	}
	
	protected function buildRedirectUrl($state)
	{
		$connection = $this->getTwitterAPIConnection($ignore_set_tokens=true);
		$callback = $this->callbackPage . (is_null(parse_url($this->callbackPage, PHP_URL_QUERY)) ? "?" : "&") . $state;
		$request_token = $connection->getRequestToken($callback);
		$this->persistOAuthToken($request_token['oauth_token']);
		$this->persistOAuthTokenSecret($request_token['oauth_token_secret']);
		$redirect_url = $connection->getAuthorizeURL($request_token);
		$glue = (is_null(parse_url($redirect_url, PHP_URL_QUERY)) ? "?" : "&") . $state;
		return $redirect_url . $glue;
	}
    
    public function setConsumerKey($consumer_key)
    {
        $this->consumerKey = $consumer_key;
    }
    
    public function setConsumerSecret($consumer_secret)
    {
        $this->consumerSecret = $consumer_secret;
    }
    
    public function setCallbackPage($callback_page)
    {
        $this->callbackPage = $callback_page;
    }

}
