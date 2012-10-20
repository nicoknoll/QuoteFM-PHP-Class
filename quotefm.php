<?php
/**
* Quotefm class
*
* This file can be used to communicate with QuoteFM (http://quote.fm)
*
* This class is based on the Twitter class by Tijs Verkoyen (http://verkoyen.eu).
*
* License
* Copyright (c) 2012, Nico Knoll. All rights reserved.
*
* Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* 3. The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.
*
* This software is provided by the author "as is" and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the author be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.
*
* @author		Nico Knoll <mail@nico.is>
* @version		0.1.0
*
* @copyright	Copyright (c) 2012, Nico Knoll. All rights reserved.
* @license		BSD License
*/

class Quotefm
{
	// internal constant to enable/disable debugging
	const DEBUG = false;

	// url for the quotefm-api
	const MAIN_URL = 'https://quote.fm/';
	const API_URL = 'https://quote.fm/api';
	const SECURE_API_URL = 'https://quote.fm/api';

	// port for the quotefm-api
	const API_PORT = 443;
	const SECURE_API_PORT = 443;

	// current version
	const VERSION = '0.1.0';


	/**
	 * A cURL instance
	 */
	private $curl;


	/**
	 * The consumer key
	 */
	private $consumerKey;


	/**
	 * The consumer secret
	 */
	private $consumerSecret;


	/**
	 * The access-token
	 */
	private $accessToken = '';


	/**
	 * The timeout
	 */
	private $timeOut = 60;


	/**
	 * The user agent
	 */
	private $userAgent;


// class methods
	/**
	 * Default constructor
	 *
	 * @return	void
	 * @param	string $consumerKey		The consumer key to use.
	 * @param	string $consumerSecret	The consumer secret to use.
	 */
	public function __construct($consumerKey, $consumerSecret)
	{
		$this->setConsumerKey($consumerKey);
		$this->setConsumerSecret($consumerSecret);
	}


	/**
	 * Default destructor
	 *
	 * @return	void
	 */
	public function __destruct()
	{
		if($this->curl != null) curl_close($this->curl);
	}


	/**
	 * Format the parameters as a querystring
	 *
	 * @return	string
	 * @param	array $parameters	The parameters.
	 */
	private function buildQuery(array $parameters)
	{
		// no parameters?
		if(empty($parameters)) return '';

		// encode the keys
		$keys = self::urlencode_rfc3986(array_keys($parameters));

		// encode the values
		$values = self::urlencode_rfc3986(array_values($parameters));

		// reset the parameters
		$parameters = array_combine($keys, $values);

		// sort parameters by key
		uksort($parameters, 'strcmp');

		// loop parameters
		foreach($parameters as $key => $value)
		{
			// sort by value
			if(is_array($value)) $parameters[$key] = natsort($value);
		}

		// process parameters
		foreach($parameters as $key => $value) $chunks[] = $key . '=' . str_replace('%25', '%', $value);

		// return
		return implode('&', $chunks);
	}


	/**
	 * All OAuth 1.0 requests use the same basic algorithm for creating a signature base string and a signature.
	 * The signature base string is composed of the HTTP method being used, followed by an ampersand ("&") and then the URL-encoded base URL being accessed,
	 * complete with path (but not query parameters), followed by an ampersand ("&").
	 * Then, you take all query parameters and POST body parameters (when the POST body is of the URL-encoded type, otherwise the POST body is ignored),
	 * including the OAuth parameters necessary for negotiation with the request at hand, and sort them in lexicographical order by first parameter name and
	 * then parameter value (for duplicate parameters), all the while ensuring that both the key and the value for each parameter are URL encoded in isolation.
	 * Instead of using the equals ("=") sign to mark the key/value relationship, you use the URL-encoded form of "%3D". Each parameter is then joined by the
	 * URL-escaped ampersand sign, "%26".
	 *
	 * @return	string
	 * @param	string $url			The URL.
	 * @param	string $method		The method to use.
	 * @param	array $parameters	The parameters.
	 */
	private function calculateBaseString($url, $method, array $parameters)
	{
		// redefine
		$url = (string) $url;
		$parameters = (array) $parameters;

		// init var
		$pairs = array();
		$chunks = array();

		// sort parameters by key
		uksort($parameters, 'strcmp');

		// loop parameters
		foreach($parameters as $key => $value)
		{
			// sort by value
			if(is_array($value)) $parameters[$key] = natsort($value);
		}

		// process queries
		foreach($parameters as $key => $value)
		{
			// only add if not already in the url
			if(substr_count($url, $key . '=' . $value) == 0) $chunks[] = self::urlencode_rfc3986($key) . '%3D' . self::urlencode_rfc3986($value);
		}

		// buils base
		$base = $method . '&';
		$base .= urlencode($url);
		$base .= (substr_count($url, '?')) ? '%26' : '&';
		$base .= implode('%26', $chunks);
		$base = str_replace('%3F', '&', $base);

		// return
		return $base;
	}


	/**
	 * Build the Authorization header
	 *
	 * @return	string
	 * @param	array $parameters	The parameters.
	 * @param	string $url			The URL.
	 */
	private function calculateHeader(array $parameters, $url)
	{
		// redefine
		$url = (string) $url;

		// divide into parts
		$parts = parse_url($url);

		// init var
		$chunks = array();

		// process queries
		foreach($parameters as $key => $value) $chunks[] = str_replace('%25', '%', self::urlencode_rfc3986($key) . '="' . self::urlencode_rfc3986($value) . '"');

		// build return
		
		$return = 'Authorization: Bearer '.$this->getAccessToken();
		$return .= implode(',', $chunks);

		// prepend name and OAuth part
		return $return;
	}


	/**
	 * Make an call to the oAuth
	 *
	 * @return	array
	 * @param	string $method					The method.
	 * @param	array[optional] $parameters		The parameters.
	 */
	private function doOAuthCall($method, array $parameters = null)
	{
		// redefine
		$method = (string) $method;

		// set additional parameters
		$parameters['client_id'] = $this->getConsumerKey() ;
		$parameters['client_secret'] = $this->getConsumerSecret() ;
		$parameters['grant_type'] = 'authorization_code';

		// calculate the base string
		$base = $this->calculateBaseString(self::SECURE_API_URL . '/oauth/' . $method, 'POST', $parameters);

		// set options
		$options[CURLOPT_URL] = self::SECURE_API_URL . '/oauth/' . $method;
		$options[CURLOPT_PORT] = self::SECURE_API_PORT;
		$options[CURLOPT_USERAGENT] = $this->getUserAgent();
		if(ini_get('open_basedir') == '' && ini_get('safe_mode' == 'Off')) $options[CURLOPT_FOLLOWLOCATION] = true;
		$options[CURLOPT_RETURNTRANSFER] = true;
		$options[CURLOPT_TIMEOUT] = (int) $this->getTimeOut();
		$options[CURLOPT_SSL_VERIFYPEER] = false;
		$options[CURLOPT_SSL_VERIFYHOST] = false;
		$options[CURLOPT_HTTPHEADER] = array('Expect:');
		$options[CURLOPT_POST] = true;
		$options[CURLOPT_POSTFIELDS] = $this->buildQuery($parameters);

		// init
		$this->curl = curl_init();

		// set options
		curl_setopt_array($this->curl, $options);

		// execute
		$response = curl_exec($this->curl);
		$headers = curl_getinfo($this->curl);

		// fetch errors
		$errorNumber = curl_errno($this->curl);
		$errorMessage = curl_error($this->curl);

		// error?
		if($errorNumber != '') throw new QuotefmException($errorMessage, $errorNumber);

		// init var
		$return = json_decode($response, true);

		// return
		return $return;
	}


	/**
	 * Make the call
	 *
	 * @return	string
	 * @param	string $url						The url to call.
	 * @param	array[optional] $parameters		Optional parameters.
	 * @param	bool[optional] $authenticate	Should we authenticate.
	 * @param	bool[optional] $method			The method to use. Possible values are GET, POST.
	 * @param	bool[optional] $expectJSON		Do we expect JSON.
	 * @param	bool[optional] $returnHeaders	Should the headers be returned?
	 */
	private function doCall($url, array $parameters = null, $authenticate = false, $method = 'GET', $expectJSON = true, $returnHeaders = false)
	{
		// allowed methods
		$allowedMethods = array('GET', 'POST');

		// redefine
		$url = (string) $url;
		$parameters = (array) $parameters;
		$authenticate = (bool) $authenticate;
		$method = (string) $method;
		$expectJSON = (bool) $expectJSON;
		
		$oauth = array();

		// validate method
		if(!in_array($method, $allowedMethods)) throw new QuotefmException('Unknown method (' . $method . '). Allowed methods are: ' . implode(', ', $allowedMethods));

		// set data
		if(!empty($parameters)) $data = $parameters;

		// calculate the base string
		$base = $this->calculateBaseString(self::API_URL . '/' . $url, $method, $data);

		// based on the method, we should handle the parameters in a different way
		if($method == 'POST')
		{
			$options[CURLOPT_POSTFIELDS] = $this->buildQuery($parameters);

			// enable post
			$options[CURLOPT_POST] = true;
		}

		else
		{
			// add the parameters into the querystring
			if(!empty($parameters)) $url .= '?' . $this->buildQuery($parameters);

			$options[CURLOPT_POST] = false;
		}

		// generate headers
		$headers[] = $this->calculateHeader($oauth, self::API_URL . '/' . $url);
		$headers[] = 'Expect:';

		// set options
		$options[CURLOPT_URL] = self::API_URL . '/' . $url;
		$options[CURLOPT_PORT] = self::API_PORT;
		$options[CURLOPT_USERAGENT] = $this->getUserAgent();
		if(ini_get('open_basedir') == '' && ini_get('safe_mode' == 'Off')) $options[CURLOPT_FOLLOWLOCATION] = true;
		$options[CURLOPT_RETURNTRANSFER] = true;
		$options[CURLOPT_TIMEOUT] = (int) $this->getTimeOut();
		$options[CURLOPT_SSL_VERIFYPEER] = false;
		$options[CURLOPT_SSL_VERIFYHOST] = false;
		$options[CURLOPT_HTTP_VERSION] = CURL_HTTP_VERSION_1_1;
		$options[CURLOPT_HTTPHEADER] = $headers;

		// init
		if($this->curl == null) $this->curl = curl_init();

		// set options
		curl_setopt_array($this->curl, $options);

		// execute
		$response = curl_exec($this->curl);
		$headers = curl_getinfo($this->curl);

		// fetch errors
		$errorNumber = curl_errno($this->curl);
		$errorMessage = curl_error($this->curl);

		// return the headers
		if($returnHeaders) return $headers;

		// we don't expext JSON, return the response
		if(!$expectJSON) return $response;

		// replace ids with their string values, added because of some PHP-version can't handle these large values
		$response = preg_replace('/id":(\d+)/', 'id":"\1"', $response);

		// we expect JSON, so decode it
		$json = @json_decode($response, true);

		// validate JSON
		if($json === null)
		{
			// should we provide debug information
			if(self::DEBUG)
			{
				// make it output proper
				echo '<pre>';

				// dump the header-information
				var_dump($headers);

				// dump the error
				var_dump($errorMessage);

				// dump the raw response
				var_dump($response);

				// end proper format
				echo '</pre>';
			}

			// throw exception
			throw new QuotefmException('Invalid response.');
		}


		// any errors
		if(isset($json['errors']))
		{
			// should we provide debug information
			if(self::DEBUG)
			{
				// make it output proper
				echo '<pre>';

				// dump the header-information
				var_dump($headers);

				// dump the error
				var_dump($errorMessage);

				// dump the raw response
				var_dump($response);

				// end proper format
				echo '</pre>';
			}

			// throw exception
			if(isset($json['errors'][0]['message'])) throw new QuotefmException($json['errors'][0]['message']);
			elseif(isset($json['errors']) && is_string($json['errors'])) throw new QuotefmException($json['errors']);
			else throw new QuotefmException('Invalid response.');
		}


		// any error
		if(isset($json['error']))
		{
			// should we provide debug information
			if(self::DEBUG)
			{
				// make it output proper
				echo '<pre>';

				// dump the header-information
				var_dump($headers);

				// dump the raw response
				var_dump($response);

				// end proper format
				echo '</pre>';
			}

			// throw exception
			throw new QuotefmException($json['error']);
		}

		// return
		return $json;
	}

	/**
	 * Get the consumer key
	 *
	 * @return	string
	 */
	private function getConsumerKey()
	{
		return $this->consumerKey;
	}


	/**
	 * Get the consumer secret
	 *
	 * @return	string
	 */
	private function getConsumerSecret()
	{
		return $this->consumerSecret;
	}


	/**
	 * Get the oAuth-token
	 *
	 * @return	string
	 */
	private function getAccessToken()
	{
		return $this->accessToken;
	}


	/**
	 * Get the timeout
	 *
	 * @return	int
	 */
	public function getTimeOut()
	{
		return (int) $this->timeOut;
	}


	/**
	 * Get the useragent that will be used. Our version will be prepended to yours.
	 * It will look like: "PHP Quotefm/<version> <your-user-agent>"
	 *
	 * @return	string
	 */
	public function getUserAgent()
	{
		return (string) 'PHP Quotefm/' . self::VERSION . ' ' . $this->userAgent;
	}


	/**
	 * Set the consumer key
	 *
	 * @return	void
	 * @param	string $key		The consumer key to use.
	 */
	private function setConsumerKey($key)
	{
		$this->consumerKey = (string) $key;
	}


	/**
	 * Set the consumer secret
	 *
	 * @return	void
	 * @param	string $secret	The consumer secret to use.
	 */
	private function setConsumerSecret($secret)
	{
		$this->consumerSecret = (string) $secret;
	}


	/**
	 * Set the access-token
	 *
	 * @return	void
	 * @param	string $token	The token to use.
	 */
	public function setAccessToken($token)
	{
		$this->accessToken = (string) $token;
	}

	/**
	 * Set the timeout
	 *
	 * @return	void
	 * @param	int $seconds	The timeout in seconds.
	 */
	public function setTimeOut($seconds)
	{
		$this->timeOut = (int) $seconds;
	}


	/**
	 * Get the useragent that will be used. Our version will be prepended to yours.
	 * It will look like: "PHP Quotefm/<version> <your-user-agent>"
	 *
	 * @return	void
	 * @param	string $userAgent	Your user-agent, it should look like <app-name>/<app-version>.
	 */
	public function setUserAgent($userAgent)
	{
		$this->userAgent = (string) $userAgent;
	}


	/**
	 * Build the signature for the data
	 *
	 * @return	string
	 * @param	string $key		The key to use for signing.
	 * @param	string $data	The data that has to be signed.
	 */
	private function hmacsha1($key, $data)
	{
		return base64_encode(hash_hmac('SHA1', $data, $key, true));
	}


	/**
	 * URL-encode method for internal use
	 *
	 * @return	string
	 * @param	mixed $value	The value to encode.
	 */
	private static function urlencode_rfc3986($value)
	{
		if(is_array($value)) return array_map(array('Quotefm', 'urlencode_rfc3986'), $value);
		else
		{
			$search = array('+', ' ', '%7E', '%');
			$replace = array('%20', '%20', '~', '%25');

			return str_replace($search, $replace, urlencode($value));
		}
	}




// Recommendation resources

	/**
	* Deletes the recommendation given by its id. The authenticated user can only delete own recommendations.
	*
	* @return	array
	* @param 	$id					The ID of the recommendation.
	*/
	public function recommendationDelete($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('recommendation/recite', $parameters, true, 'POST');
	}


	/**
	* Posts a new recommendation. Please be sure to comply with the terms of service when posting recommendations. This method returns the posted recommendation. 
	*
	* @return	array
	* @param 	$text					The quote. It will be shortened after 600 characters.
	* @param 	$source					The URL to the article the quote is from.
	* @param 	$categoryId (optional)	The category the recommendation is assigned to.
	* @param 	$comment (optional)		The comment by the user who posts the recommendation.
	*/
	public function recommendationPost($text, $source, $categoryId = null, $comment = null)
	{
		// validate
		if($text == '' || $source == '') throw new QuotefmException('A text and a source are required.');
	
		// build parameters
		$parameters = null;
		$parameters['text'] = $text;
		$parameters['source'] = $source;
		if($categoryId != null) $parameters['category_id'] = (string) $categoryId;
		if($comment != null) $parameters['comment'] = (string) $comment;
		
		// make the call
		return (array) $this->doCall('recommendation/post', $parameters, true, 'POST');
	}


	/**
	* Recites a recommendation. This method returns the posted recommendation.
	*
	* @return	array
	* @param 	$id						The id of the recommendation that should be recited.
	* @param 	$comment (optional)		The comment by the user who posts the recommendation.
	*/
	public function recommendationRecite($id, $comment = null)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		if($comment != null) $parameters['comment'] = (string) $comment;
		
		// make the call
		return (array) $this->doCall('recommendation/recite', $parameters, true, 'POST');
	}


	/**
	* Returns the recommendation specified by its unique id. The returned array also includes the associated article and page entities, the user who posted the recommendation and a list of comments.
	*
	* @return	array
	* @param 	$id						The id of the recommendation that should be recited.
	*/
	public function recommendationGet($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('recommendation/get', $parameters, true, 'GET');
	}


	/**
	* Returns a list of recommendations associated to an article specified by its unique id or URL. One of the both parameters is required. The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* @return	array
	* @param 	$id						The id of the recommendation that should be recited.
	* @param 	$url (optional)			The URL of the article.
	* @param 	$scope (optional)		Determines the order of the returned entities. Use time for newest first or popular for most popular first.
	* @param 	$pageSize (optional)	Determines the maximum count of entities to be returned on one page. Maximum of 100.
	* @param 	$page (optional)		The page index (zero based).
	*/
	public function recommendationListByArticle($id = null, $url = null, $scope = null, $pageSize = null, $page = null)
	{
		// validate
		if($id == '' && $url == '') throw new QuotefmException('An ID or a URL is required.');
	
		// build parameters
		$parameters = null;
		if($id != null) $parameters['id'] = (string) $id;
		if($url != null) $parameters['url'] = (string) $url;
		if($scope != null) $parameters['scope'] = (string) $scope;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('recommendation/listByArticle', $parameters, true, 'GET');
	}


	/**
	* Returns a list of recommendations posted by a user specified by its username. The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* @return	array
	* @param 	$username					The users username.
	* @param 	$scope (optional)			Determines the order of the returned entities. Use time for newest first or popular for most popular first.
	* @param 	$pageSize (optional)		Determines the maximum count of entities to be returned on one page. Maximum of 100.
	* @param 	$page (optional)			The page index (zero based).
	*/
	public function recommendationListByUser($username, $scope = null, $pageSize = null, $page = null)
	{
		// validate
		if($username == '') throw new QuotefmException('An username is required.');
	
		// build parameters
		$parameters = null;
		$parameters['username'] = $username;
		if($scope != null) $parameters['scope'] = (string) $scope;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('recommendation/listByUser', $parameters, true, 'GET');
	}
	
	
	/**
	* Returns all recommendations by users and pages the currently authenticated user follows. The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* @return	array
	* @param 	$pageSize (optional)		Determines the maximum count of entities to be returned on one page. Maximum of 100.
	* @param 	$page (optional)			The page index (zero based).
	*/
	public function recommendationListByFollowings($pageSize = null, $page = null)
	{
		// build parameters
		$parameters = null;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('recommendation/listByFollowings', $parameters, true, 'GET');
	}



// Article resources
	/**
	* Returns a list of articles that match the given search term. The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* @return	array
	* @param 	$term						The search term.
	* @param 	$pageSize (optional)		Determines the maximum count of entities to be returned on one page. Maximum of 100.
	* @param 	$page (optional)			The page index (zero based).
	*/
	public function articleSearch($term, $pageSize = null, $page = null)
	{
		// validate
		if($term == '') throw new QuotefmException('A term is required.');
		
		// build parameters
		$parameters = null;
		$parameters['term'] = $term;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('article/search', $parameters, true, 'GET');
	}


	/**
	* Returns the article specified by its unique id or url, Only one of the parameters is needed.
	*
	* The returned title and the language are guessed from the article content and may not be accurate.
	* 
	* The length is calculated from the article content and represents the length of the article in words. Using the length the estimated reading time ert is calculated.
	* 
	* The included topquote is the most popular recommendation of the article.
	*
	* @return	array
	* @param 	$id							The ID of the article to get
	* @param 	$url						The url of the article.
	*/
	public function articleGet($id, $url = null)
	{
		// validate
		if($id == '' && $url == '') throw new QuotefmException('An ID or a URL is required.');
		
		// build parameters
		$parameters = null;
		if($id != null) $parameters['id'] = (string) $id;
		if($url != null) $parameters['url'] = (string) $url;
		
		// make the call
		return (array) $this->doCall('article/get', $parameters, true, 'GET');
	}


	/**
	* Returns a list of articles associated to a page specified by its unique id.
	* 
	* The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	* 
	* The scope parameter controls if the articles are returned based on their popularity or based on their creation time. scope can be either 'popular' or 'time'.
	*
	* @return	array
	* @param 	$id						The id of the recommendation that should be recited.
	* @param 	$scope (optional)		Determines the order of the returned entities. Use time for newest first or popular for most popular first.
	* @param 	$pageSize (optional)	Determines the maximum count of entities to be returned on one page. Maximum of 100.
	* @param 	$page (optional)		The page index (zero based).
	*/
	public function articleListByPage($id, $scope = null, $pageSize = null, $page = null)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		if($scope != null) $parameters['scope'] = (string) $scope;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('article/listByPage', $parameters, true, 'GET');
	}
	

	/**
	* Returns a list of articles associated to the categories specified by their ids.
	* 
	* The ids parameter should be a comma separated list of category ids. To get the ids see category/list.
	* 
	* The language parameter controls the language of the articles returned. Please note that the language detection is not completely reliable. language can be either 'de' or 'en', default is 'any'.
	*
	* The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* The scope parameter controls if the articles are returned based on their popularity or based on their creation time. scope can be either 'popular' or 'time'.
	*
	* @return	array
	* @param 	$id						The id of the recommendation that should be recited.
	* @param 	$scope (optional)		Determines the order of the returned entities. Use time for newest first or popular for most popular first.
	* @param 	$pageSize (optional)	Determines the maximum count of entities to be returned on one page. Maximum of 100.
	* @param 	$page (optional)		The page index (zero based).
	*/
	public function articleListByCategories($ids, $scope = null, $pageSize = null, $page = null)
	{
		// validate
		if($id == '') throw new QuotefmException('IDs are required.');
	
		// build parameters
		$parameters = null;
		$parameters['ids'] = $ids;
		if($scope != null) $parameters['scope'] = (string) $scope;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('article/listByCategories', $parameters, true, 'GET');
	}







// Page resources
	/**
	* Lets the currently authenticated user follow the page given by its id.
	*
	* @return	array
	* @param 	$id						The id of the recommendation that should be recited.
	*/
	public function pageFollow($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('page/follow', $parameters, true, 'POST');
	}


	/**
	* Lets the currently authenticated user unfollow the page given by its id.
	*
	* @return	array
	* @param 	$id						The id of the recommendation that should be recited.
	*/
	public function pageUnfollow($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('page/unfollow', $parameters, true, 'POST');
	}


	/**
	* Lets the currently authenticated user block the page given by its id.
	*
	* @return	array
	* @param 	$id						The id of the recommendation that should be recited.
	*/
	public function pageBlock($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('page/block', $parameters, true, 'POST');
	}
	
	
	/**
	* Lets the currently authenticated user unblock the page given by its id.
	*
	* @return	array
	* @param 	$id						The id of the recommendation that should be recited.
	*/	
	public function pageUnblock($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('page/unblock', $parameters, true, 'POST');
	}


	/**
	* Returns the page specified by its unique id or domain name. Only one of the parameters is needed.
	*
	* The returned page entity contains the unique id, the domain name that is used internally and a description. The description is derived from the pages meta tags and therefore may also be empty or inaccurate.
	*
	* @return	array
	* @param 	$id						The id of the recommendation that should be recited.
	* @param 	$domain (optional)		The domain name of the page to get.
	*/	
	public function pageGet($id, $domain = null)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		if($domain != null) $parameters['domain'] = (string) $domain;
		
		// make the call
		return (array) $this->doCall('page/get', $parameters, true, 'GET');
	}


	/**
	* Returns a list of all pages. For more information about the page entity see page/get.
	*
	* The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* @return	array
	* @param 	$pageSize (optional)	Determines the maximum count of entities to be returned on one page. Maximum of 100.
	* @param 	$page (optional)		The page index (zero based).
	*/
	public function pageList($id, $pageSize = null, $page = null)
	{
		// build parameters
		$parameters = null;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('page/list', $parameters, true, 'GET');
	}
	



// User resources
	/**
	* Returns a list of users matching the search term.
	*
	* The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* @return	array
	* @param 	$term					The term to search for.
	* @param 	$pageSize (optional)	Determines the maximum count of entities to be returned on one page. Maximum of 100.
	* @param 	$page (optional)		The page index (zero based).
	*/
	public function userSearch($term, $pageSize = null, $page = null)
	{
		// validate
		if($term == '') throw new QuotefmException('A term is required.');
		
		// build parameters
		$parameters = null;
		$parameters['term'] = $term;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('user/search', $parameters, true, 'GET');
	}


	/**
	* Lets the currently authenticated user follow the user given by its id.
	*
	* @return	array
	* @param 	$id						The ID of the user.
	*/
	public function userFollow($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('user/follow', $parameters, true, 'POST');
	}
	
	
	/**
	* Lets the currently authenticated user unfollow the user given by its id.
	*
	* @return	array
	* @param 	$id						The ID of the user.
	*/
	public function userUnfollow($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('user/unfollow', $parameters, true, 'POST');
	}
	
	
	/**
	* Lets the currently authenticated user block the user given by its id.
	*
	* @return	array
	* @param 	$id						The ID of the user.
	*/
	public function userBlock($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('user/block', $parameters, true, 'POST');
	}
	
	
	/**
	* Lets the currently authenticated user unblock the user given by its id.
	*
	* @return	array
	* @param 	$id						The ID of the user.
	*/
	public function userUnblock($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('user/unblock', $parameters, true, 'POST');
	}


	/**
	* Returns the user specified by its username or id. Only one of the parameters is needed.
	*
	* Please note that the fullname may be the same as the username if the user has not activated the "Use full name as display name"-flag. To get the users followers and followings use user/listFollowers and user/listFollowings.
	*
	* @return	array
	* @param 	$username				The username of the user to get.
	* @param 	$id						The ID of the user.
	*/
	public function userGet($id = null, $username = null)
	{
		// validate
		if($id == '' && $username == '') throw new QuotefmException('An ID or a username is required.');
	
		// build parameters
		$parameters = null;
		if($id != null) $parameters['id'] = (string) $id;
		if($username != null) $parameters['id'] = (string) $username;
		
		// make the call
		return (array) $this->doCall('user/get', $parameters, true, 'GET');
	}
	
	
	/**
	* Returns a list of users following the user specified by its username or id. Only one of the parameters is needed.
	* 
	* The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* @return	array
	* @param 	$id						The ID of the user.
	* @param 	$username				The username of the user to get.
	* @param 	$pageSize (optional)	Determines the maximum count of entities to be returned on one page. Maximum of 100.
	* @param 	$page (optional)		The page index (zero based).
	*/
	public function userListFollowers($id = null, $username = null, $pageSize = null, $page = null)
	{
		// validate
		if($id == '' && $username == '') throw new QuotefmException('An ID or a username is required.');
	
		// build parameters
		$parameters = null;
		if($id != null) $parameters['id'] = (string) $id;
		if($username != null) $parameters['id'] = (string) $username;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('user/listFollowers', $parameters, true, 'GET');
	}


	/**
	* Returns a list of users the user specified by its username or id is following. Only one of the parameters is needed.
	*
	* The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* @return	array
	* @param 	$id						The ID of the user.
	* @param 	$username				The username of the user to get.
	* @param 	$pageSize (optional)	Determines the maximum count of entities to be returned on one page. Maximum of 100.
	* @param 	$page (optional)		The page index (zero based).
	*/
	public function userListFollowings($id = null, $username = null, $pageSize = null, $page = null)
	{
		// validate
		if($id == '' && $username == '') throw new QuotefmException('An ID or a username is required.');
	
		// build parameters
		$parameters = null;
		if($id != null) $parameters['id'] = (string) $id;
		if($username != null) $parameters['id'] = (string) $username;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('user/listFollowings', $parameters, true, 'GET');
	}



// Category resources
	/**
	* Returns the list of categories for discover.
	*
	* The returned name is the internally used english representation of the category. In the future localized versions may be included.
	* 
	* Please note that the curator field is always null since curators have been deprecated.
	*
	* The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* @return	array
	* @param 	$pageSize (optional)	Determines the maximum count of entities to be returned on one page. Maximum of 100.
	* @param 	$page (optional)		The page index (zero based).
	*/
	public function categoryList($pageSize = null, $page = null)
	{
		// build parameters
		$parameters = null;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('category/list', $parameters, true, 'GET');
	}



// Comment resources
	/**
	* Returns the list of categories for discover.
	*
	* The returned name is the internally used english representation of the category. In the future localized versions may be included.
	* 
	* Please note that the curator field is always null since curators have been deprecated.
	*
	* The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* @return	array
	* @param 	$recommendationId		The ID of the recommendation.
	* @param 	$text					The comment text.
	*/
	public function commentPost($recommendationId, $text)
	{
		// validate
		if($text == '' || $source == '') throw new QuotefmException('A text and a recommendation ID are required.');
	
		// build parameters
		$parameters = null;
		$parameters['text'] = $text;
		$parameters['recommendation_id'] = $recommendationId;
		
		// make the call
		return (array) $this->doCall('comment/post', $parameters, true, 'POST');
	}
	
	
	/**
	* Deletes a comment given by its unique id.
	*
	* The authenticated user can only delete own comments or comments posted under own recommendations.
	*
	* @return	array
	* @param 	$id						The ID of the comment.
	*/
	public function commentDelete($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('comment/delete', $parameters, true, 'POST');
	}


	/**
	* Marks the comment given by its unique id as liked by the currently authenticated user.
	*
	* Returns the comment entity (see comment/get).
	*
	* @return	array
	* @param 	$id						The ID of the comment.
	*/
	public function commentLike($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('comment/like', $parameters, true, 'POST');
	}


	/**
	* Marks the comment given by its unique id as not liked by the currently authenticated user.
	*
	* Returns the comment entity (see comment/get).
	*
	* @return	array
	* @param 	$id						The ID of the comment.
	*/
	public function commentUnlike($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('comment/unlike', $parameters, true, 'POST');
	}


	/**
	* Returns the comment specified by its unique id.
	*
	* If replace_mentions is set to true all mentions of users will be replaced with hyperlinks. If set to false they will be included in the format "@userid@". For example: "Hello, @1@!"
	*
	* @return	array
	* @param 	$id								The ID of the comment to get.
	* @param 	$replaceMentions (optional)		Replace mentions with hyperlinks. (true/false)
	*/
	public function commentGet($id, $replaceMentions = false)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		if($replaceMentions != false) $parameters['replace_mentions'] = (bool) $replaceMentions;
		
		// make the call
		return (array) $this->doCall('comment/get', $parameters, true, 'POST');
	}




	
// Read resources
	/**
	* Lets the currently authenticated user mark the given readlater entity as favorite.
	*
	* @return	array
	* @param 	$id						The ID of the readlater entity.
	*/
	public function readStar($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('read/star', $parameters, true, 'POST');
	}


	/**
	* Lets the currently authenticated user unmark the given readlater entity.
	*
	* @return	array
	* @param 	$id						The ID of the readlater entity.
	*/
	public function readUnstar($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('read/unstar', $parameters, true, 'POST');
	}
	
	
	/**
	* Lets the currently authenticated user move the given readlater entity to the archive.
	*
	* @return	array
	* @param 	$id						The ID of the readlater entity.
	*/
	public function readArchive($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('read/archive', $parameters, true, 'POST');
	}


	/**
	* Lets the currently authenticated user remove the given readlater entity from the archive. The entity will be moved back to the inbox.
	*
	* @return	array
	* @param 	$id						The ID of the readlater entity.
	*/
	public function readUnarchive($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('read/unarchive', $parameters, true, 'POST');
	}
	
	
	/**
	* Lets the currently authenticated user remove the given readlater entity. The entity will be completly removed.
	*
	* @return	array
	* @param 	$id						The ID of the readlater entity.
	*/
	public function readDelete($id)
	{
		// validate
		if($id == '') throw new QuotefmException('An ID is required.');
	
		// build parameters
		$parameters = null;
		$parameters['id'] = $id;
		
		// make the call
		return (array) $this->doCall('read/delete', $parameters, true, 'POST');
	}
	
	
	/**
	* Lets the currently authenticated user add an article to his read later inbox. The required recommendation_id should point to the recommendation the user viewed when he decided to add the article.
	*
	* To add articles without a associated recommendation use read/saveUrl.
	*
	* @return	array
	* @param 	$articleId					The ID of the article.
	* @param 	$recommendationId			The ID of the recommendation.
	*/
	public function readSave($articleId, $recommendationId)
	{
		// validate
		if($articleId == '' || $recommendationId == '') throw new QuotefmException('An article ID and a recommendation ID are required.');
	
		// build parameters
		$parameters = null;
		$parameters['article_id'] = $articleId;
		$parameters['recommendation_id'] = $recommendationId;
		
		// make the call
		return (array) $this->doCall('read/save', $parameters, true, 'POST');
	}
	
	
	/**
	* Lets the currently authenticated user add an article to his read later inbox.
	*
	* To add articles found via QUOTE.fm please use read/save
	*
	* @return	array
	* @param 	$url						The URL of the article.
	*/
	public function readSaveUrl($url)
	{
		// validate
		if($url == '') throw new QuotefmException('A URL is required.');
	
		// build parameters
		$parameters = null;
		$parameters['url'] = $url;
		
		// make the call
		return (array) $this->doCall('read/saveUrl', $parameters, true, 'POST');
	}
	

	/**
	* Returns a list of read later entities saved by the authenticated user.
	*
	* Available list types are default, starred (favorites) and archive.
	*
	* It's also possible to filter the lists by category ids, see category/list for more information.
	*
	* The response is split into several pages with a default page size of 100 items per page. To control the output use the pageSize and page parameters.
	*
	* @return	array
	* @param 	$type (optional)				The list type.
	* @param 	$categoryIds (optional)			Comma-separated list of category ids to filter.
	* @param 	$pageSize (optional)			Determines the maximum count of entities to be returned on one page. Maximum of 100..
	* @param 	$page (optional)				The page index (zero based).
	*/
	public function readList($type = null, $categoryIds = null, $pageSize = null, $page = null)
	{
		// build parameters
		$parameters = null;
		if($type != null) $parameters['type'] = (string) $type;
		if($categoryIds != null) $parameters['category_ids'] = (string) $categoryIds;
		if($pageSize != null) $parameters['pageSize'] = (string) $pageSize;
		if($page != null) $parameters['page'] = (string) $page;
		
		// make the call
		return (array) $this->doCall('category/list', $parameters, true, 'GET');
	}





// OAuth resources
	/**
	 * Allows a Consumer application to obtain an OAuth Request Token to request user authorization.
	 * This method fulfills Secion 6.1 of the OAuth 1.0 authentication flow.
	 *
	 * @return	array					An array containg the token and the secret
	 * @param	$code					The $_GET['code'] generated by oAuthAuthorize
	 * @param	$callbackURL			The callback URL.
	 */
	public function oAuthRequestToken($code, $callbackURL)
	{
		// init var
		$parameters = null;

		// set code
		$parameters['code'] = (string) $code;
		
		// set callback
		if($callbackURL != null) $parameters['redirect_uri'] = (string) $callbackURL;

		// make the call
		$response = $this->doOAuthCall('token', $parameters);

		// validate
		if(!isset($response['access_token'])) throw new QuotefmException(implode(', ', array_keys($response)));

		// set some properties
		if(isset($response['access_token'])) $this->setAccessToken($response['access_token']);

		// return
		return $response;
	}
	
	
	/**
	* Saves the specified token into a cookie
	*
	* @return	void
	* @param	$expire					Livetime of the cookie.
	* @param	$path					The path of the cookie.
	*/
	public function oAuthSaveTokenAsCookie($expire = null, $path = '/')
	{
		// set cookie with the token
		setcookie('quotefm_token', $this->getAccessToken(), (($expire == null) ? time()+60*60*24*30 : $expire), $path);
	}
	
	
	/**
	* Saves the specified token into a session variable
	*
	* @return	void
	*/
	public function oAuthSaveTokenAsSession()
	{
		// starts session if session doesn't exists
		if(session_id() == '') session_start();
		
		// save token as session var
		$_SESSION['quotefm_token'] = $this->getAccessToken();
	}


	/**
	* Loads the token from a cookie
	*
	* @return	string					The token.
	*/
	public function oAuthLoadTokenFromCookie()
	{
		// get token from the cookie
		return ($_COOKIE['quotefm_token'] != '') ? (string) $_COOKIE['quotefm_token'] : false;
	}
	
	
	/**
	* Loads the token from a session variable
	*
	* @return	string					The token.
	*/
	public function oAuthLoadTokenFromSession()
	{
		// starts session if session doesn't exists
		if(session_id() == '') session_start();
		
		// load token from session var
		return ($_SESSION['quotefm_token'] != '') ? (string) $_SESSION['quotefm_token'] : false;
	}

	/**
	 * Will redirect to the page to authorize the application
	 *
	 * @return	void
	 * @param	$redirectUri		The callback URI.
	 */
	public function oAuthAuthorize($redirectUri)
	{
		$url = self::MAIN_URL.'labs/oauth/authorize';
		$url .= '?response_type=code';
		$url .= '&client_id=' . $this->getConsumerKey();
		$url .= '&redirect_uri='. $redirectUri;
		
		header('Location: ' . $url);
	}
}


/**
 * Quotefm Exception class
 *
 * @author	Nico Knoll <mail@nico.is>
 */
class QuotefmException extends Exception
{
}

?>