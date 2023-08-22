<?php

loadCkPathsFiles();

function _cls_dls()
{
	dl();
	exit;
}

/**
 * Despliega los mensajes de error que guian al programador
 * en el proceso de desarrollo, estos solo son visibles si
 * el prametro 'env' se a establecido en 'dev' (desarrollo)
 */
function _cls_de($string)
{
	global $app;
	if ($app['environment'] == 'dev') {
		die($string);
	}
}


function _cls_getMiddlewares($app)
{
	// Obtiene la configuración de de arranque
	$boot = getConfig('boot');

	$queue = [];

	// Middlewares para desarrollo
	if ($boot['environment'] == "dev") {
		require_once INF_PATH_ROOT . DS . "boot" . DS . "middlewares_dev.php";
		$queue = array_merge($queue, $devMiddlewares);
	}

	require_once INF_PATH_ROOT . DS . "boot" . DS . "middlewares.php";
	$queue = array_merge($queue, $middlewares);

	// Middlewares para producción
	if ($boot['environment'] == "dev") {
		require_once INF_PATH_ROOT . DS . "boot" . DS . "middlewares_prod.php";
		$queue = array_merge($queue, $devMiddlewares);
	}

	return $queue;
}

/**
 * elimina el ultimo / de un cadena
 * @param  string $string cadena de la que se desea eliminaer el /
 * @return string         cadena procesada
 */
function _cls_removeLastSlash($string)
{
	$slash = substr($string, -1);
	if ($slash == '/') {
		return substr($string, 0, -1);
	}
	return $string;
}

/**
 * Obtinen la url para solicitudes especificas
 * @param  string $name nombre con el que se obtiene la ruta
 * @return string       url valida
 */
function _cls_route($name, $var = null, $getParams = null)
{
	$routes = Route::getRoutes();

    if ($name === null) {
        return false;
    }

	if (strpos($name, 'objRoute') === false) {
        if (strpos($name, 'http') === false) {
            if ($var != null) {
				$route_flat = replace_route_var($name, $routes, $var);
			} else {
				$route_flat = $routes[$name]['route'];
			}
			$route =  '//' . $GLOBALS['paths']['url_base'] . $route_flat;
		} else {
			$route = routeAddParams('objRoute' . $name, $var);
		}
	} else {
		$route = routeAddParams($name, $var);
	}

	return setQueryParams($route, $getParams);
}

function _cls_replace_route_var($route, $routes, $var)
{
	$parts = explode('/', $routes[$route]['route']);
	$key = search_in_element($parts, '$');
	if ($key === false) {
		return false;
	} else {
		$parts[$key] = $var;
	}
	$new_route = implode("/", $parts);
	return $new_route;
}

function _cls_routeAddParams($route, $var)
{
	$route = str_replace('objRoute', '', $route);

	$parts = explode('/', $route);
	if (is_array($var)) {
		$index = 0;
		foreach ($var as $id => $name) {
			$key = search_in_element($parts, '$');

			if ($key === false) {
				return $route;
			} else {
				$parts[$key[0]] = $var[$key[1]] ?? $var[$index];
			}
			$index++;
		}
	} else {
		$key = search_in_element($parts, '$');

		if ($key === false) {
			return $route;
		} else {
			$parts[$key[0]] = $var;
		}
	}

	$new_route = implode("/", $parts);

	return $new_route;
}

/**
 * Define el nombre que devera tener un vista apartir de una ruta
 * @param  string $route Ruta a la que pertenece la vista
 * @param  string $base  Ruta base de la aplicacion
 * @return string        Nombre que deve tomar la vista
 */
function _cls_viewRoute($route, $base)
{
	$nameSegments = explode('/', str_replace($base, '', $route));
	if (sizeof($nameSegments) == 1) {
		return $nameSegments['0'];
	} else {
		return $nameSegments['1'] . $nameSegments['0'];
	}
}
/**
 * Localiza el elmento que contiene la cadena que se esta buscando
 * @param  array  $array  Arreglo que contiene la informacion
 * @param  string  $needle Cadena a ser localizada
 * @param  integer $start  Elemento en el que iniciara la busqueda
 * @return mix          devuelve un cadeca conla clave del elemento o Falso si no encuantra coincidencias
 */
function _cls_search_in_element($array, $needle, $start = 0)
{
	foreach ($array as $key => $value) {
		if ($key < $start) {
			continue;
		}
		if (strpos($value, $needle) === false) {
			continue;
		} else {
			return [$key, str_replace('$', '', $value)];
		}
	}
	return false;
}
/**
 * Obtiene un elemento determinado de un array
 * @param  array $array Arreglo que contiene el elemento a extraer
 * @param  string $key   clave identificadorea del elemento a estraer
 * @return string        elemento solicitado
 */
function _cls_array_element($array, $key)
{
	if (is_null($key)) return false;
	if (isset($array[$key])) return $array[$key];
}
/**
 * Convierte un array multidemencional en un objeto estandar.
 * @param  array $d contiene la información a convertir.
 * @return object    el objeto resultado de la converción.
 */
function _cls_arrayToObject($array)
{
	return json_decode(json_encode($array));
}
/**
 * Comvierte un objeto estandar en un array multidimencional.
 * @param  objeto $d contine información a ser convertida.
 * @return array    retorna un array multidimencional.
 */
function _cls_objectToArray($object)
{
	return json_decode(json_encode($object), true);
}
/**
 * Construye la URL base de la aplicación
 * @return string URL
 */
function _cls_baseUrl()
{
	return '//' . FRONT_URL;
}
function _cls_isSetProperty($property)
{
	if (isset($property)) {
		return $property;
	} else {
		return false;
	}
}
/**
 * Corta una cadena en el espacion en blanco mas cercano al numero maximo de
 * caracteres indicado en el parmetro logintud, si este parametro no es enviado
 * se extraeran solo los 100 primeros caracteres de la cadena.
 * @param  string  $string   Cadena al la que se aplica el proceso
 * @param  integer $longitud cantidad de caracteres que se extraeran
 * @return string            Cadena recortada
 */
function _cls_str_truncate($string, $longitud = 100)
{
	//Comprobamos que sea necesario recortar la cadena de texto
	if ((mb_strlen($string) > $longitud)) {
		$espacios = mb_strpos($string, ' ', $longitud) - 1 . "<br>";
		if ($espacios > 0) {
			$cadena = mb_substr($string, 0, ($espacios + 1));
			$char = count_chars($cadena, 1);
			$string = $cadena . '...';
		}
		if (preg_match_all("|(<([\w]+)[^>]*>)|", $string, $buffer)) {
			if (!empty($buffer[1])) {
				preg_match_all("|</([a-zA-Z]+)>|", $string, $buffer2);
				if (count($buffer[2]) != count($buffer2[1])) {
					$tags = array_diff($buffer[2], $buffer2[1]);
					$tags = array_reverse($tags);
					foreach ($tags as $tag) {
						$string .= '</' . $tag . '>';
					}
				}
			}
		}
	}
	return $string;
}
/**
 * corta el texto en x caracteres sin perder el cierre de los tags html
 * @param <string> $text
 * @param <integer> $length
 * @param <array> $options
 * @return <string>
 */
function _cls_cutText($text, $length = 100, $options = array())
{
	$default = array(
		'ending' => '', 'exact' => false, 'html' => false
	);
	$options = array_merge($default, $options);
	extract($options);
	if ($html) {
		if (mb_strlen(preg_replace('/<.*?>/', '', $text)) <= $length) {
			return $text;
		}
		$totalLength = mb_strlen(strip_tags($ending));
		$openTags = array();
		$truncate = '';
		preg_match_all('/(<\/?([\w+]+)[^>]*>)?([^<>]*)/', $text, $tags, PREG_SET_ORDER);
		foreach ($tags as $tag) {
			if (!preg_match('/img|br|input|hr|area|base|basefont|col|frame|isindex|link|meta|param/s', $tag[2])) {
				if (preg_match('/<[\w]+[^>]*>/s', $tag[0])) {
					array_unshift($openTags, $tag[2]);
				} else if (preg_match('/<\/([\w]+)[^>]*>/s', $tag[0], $closeTag)) {
					$pos = array_search($closeTag[1], $openTags);
					if ($pos !== false) {
						array_splice($openTags, $pos, 1);
					}
				}
			}
			$truncate .= $tag[1];

			$contentLength = mb_strlen(preg_replace('/&[0-9a-z]{2,8};|&#[0-9]{1,7};|&#x[0-9a-f]{1,6};/i', ' ', $tag[3]));
			if ($contentLength + $totalLength > $length) {
				$left = $length - $totalLength;
				$entitiesLength = 0;
				if (preg_match_all('/&[0-9a-z]{2,8};|&#[0-9]{1,7};|&#x[0-9a-f]{1,6};/i', $tag[3], $entities, PREG_OFFSET_CAPTURE)) {
					foreach ($entities[0] as $entity) {
						if ($entity[1] + 1 - $entitiesLength <= $left) {
							$left--;
							$entitiesLength += mb_strlen($entity[0]);
						} else {
							break;
						}
					}
				}

				$truncate .= mb_substr($tag[3], 0, $left + $entitiesLength);
				break;
			} else {
				$truncate .= $tag[3];
				$totalLength += $contentLength;
			}
			if ($totalLength >= $length) {
				break;
			}
		}
	} else {
		if (mb_strlen($text) <= $length) {
			return $text;
		} else {
			$truncate = mb_substr($text, 0, $length - mb_strlen($ending));
		}
	}
	if (!$exact) {
		$spacepos = mb_strrpos($truncate, ' ');
		if (isset($spacepos)) {
			if ($html) {
				$bits = mb_substr($truncate, $spacepos);
				preg_match_all('/<\/([a-z]+)>/', $bits, $droppedTags, PREG_SET_ORDER);
				if (!empty($droppedTags)) {
					foreach ($droppedTags as $closingTag) {
						if (!in_array($closingTag[1], $openTags)) {
							array_unshift($openTags, $closingTag[1]);
						}
					}
				}
			}
			$truncate = mb_substr($truncate, 0, $spacepos);
		}
	}
	$truncate .= $ending;

	if ($html) {
		foreach ($openTags as $tag) {
			$truncate .= '</' . $tag . '>';
		}
	}

	return $truncate . "...";
}

function _cls_readmore($fulltext)
{
	if (strpos($fulltext, '{{readmore}}') !== false) {
		$text = explode('{{readmore}}', $fulltext);
		$text[0] = substr($text[0], 0, -11);
		$text[1] = substr($text[1], 13);

		$text[0] = $text[0] . '
		<div id="readon">
			<span class="btn btn-info">Leer más...</span>
		</div>
		';

		$text[1] = '
		<div id="full-text">
			' . $text[1] . '
		</div>
		';

		return implode('', $text);
	}

	return $fulltext;
}

/**
 * Codifica las entidades html
 * @param  string/array $value contiene los valores a ser evaluados
 * @return string/array        valores evaluados con entidadeshtml codificadas
 */
function _cls_encodeEntities($value)
{
	if (is_array($value)) {
		foreach ($value as $key => $val) {
			encodeEntities($val);
		}
	} elseif (is_object($value)) {
		foreach ($value as $key => $val) {
			encodeEntities($val);
		}
	} else {
		$value = strClean(htmlentities($value));
	}

	return $value;
}

function _cls_decodeEntities($value)
{
	if (is_array($value)) {
		foreach ($value as $key => $val) {
			$value[$key] = strClean(html_entity_decode($val));
		}
	} elseif (is_object($value)) {
		foreach ($value as $key => $val) {
			$value->$key = strClean(html_entity_decode($val));
		}
	} else {
		$value = strClean(html_entity_decode($value));
	}

	return $value;
}

/**
 * Convierte el caracter ':' en su equivalente en codificación ASCII
 * @param  string $string cadena con caracter a remplazar
 * @return string         cadena remplazada
 */
function _cls_strClean($string)
{
	do {
		$string = str_replace(':', '&#58', $string);
	} while (strpos($string, ':') !== false);

	return $string;
}

function _cls_isImage($url)
{
	if (strpos($url, '.jpg') !== false) {
		return true;
	} elseif (strpos($url, '.png') !== false) {
		return true;
	} elseif (strpos($url, '.gif') !== false) {
		return true;
	} elseif (strpos($url, '.svg') !== false) {
		return true;
	}
	return false;
}

function _cls_slug($string)
{
	$characters = array(
		"Á" => "A", "Ç" => "c", "É" => "e", "Í" => "i", "Ñ" => "n", "Ó" => "o", "Ú" => "u",
		"á" => "a", "ç" => "c", "é" => "e", "í" => "i", "ñ" => "n", "ó" => "o", "ú" => "u",
		"à" => "a", "è" => "e", "ì" => "i", "ò" => "o", "ù" => "u"
	);

	$string = strtr($string, $characters);

	$string = strtolower(trim($string));

	$string = preg_replace("/[^a-z0-9-]/", "-", $string);

	$string = preg_replace("/-+/", "-", $string);

	if (substr($string, strlen($string) - 1, strlen($string)) === "-") {
		$string = substr($string, 0, strlen($string) - 1);
	}

	if (substr($string, 0, 1) === "-") {
		$string = substr($string, 1, strlen($string));
	}

	return $string;
}

function _cls_redirect($url)
{
	header('Location: ' . $url);

	exit();
}

function _cls_base_path($resource = null)
{
  global $globalLanguage;

  if ($resource == null) {
    return [
      'en' => '//' . $GLOBALS['paths']['url_base'] . '/en/',
      'es' => '//' . $GLOBALS['paths']['url_base'] . '/es/',

    ];
  } else {
    return '//' . $GLOBALS['paths']['url_base'] . '/' . $resource . '/';
  }
}

function _cls_replacePath($string)
{
	$string = str_replace("<?= base_path('views') ?>", base_path('views'), $string);
	$string = str_replace("<?= baseUrl() ?>", baseUrl(), $string);
	return $string;
}

function _cls_imagePathFilter($string)
{
	return str_replace('../../..', baseUrl(), $string);
}
function _cls_formatTitle($string, $size = 1)
{
	$title = explode(' ', $string);
	$newString = '<strong>';
	for ($i = 0; $i < $size; $i++) {
		$newString .= array_shift($title) . ' ';
	}
	$newString .= '</strong>';
	array_unshift($title, $newString);
	return implode(' ', $title);
}

function _cls_generateToken($time = 300, $type = 0)
{
	$token['id'] = str_replace('.', '', str_replace(' ', '', uniqid(microtime(), true)));
	$token['token'] = md5(uniqid(microtime(), true));
	$token['token_type']   = $type;
	$token['token_time']   = $time;
	return $token;
}

/**
 * Verifica la valides del token
 * @param $request
 * @return bool
 */
function _cls_verifyToken($request)
{
	// Obtiene el token a verificar
	$token = json_decode(Crypt::AESDecrypt($request->get->reset_token), true);
	// Verifica que el token sea valido
	if (Tokenizer::verifyToken($token)) {
		return $token;
	} else {
		return false;
	}
}


/**
 * Genera el link de recuperación
 * @param string    $userId ID Usuario para que se crea el link
 * @return string           Enlace para activar la cuenta
 * @throws Exception
 */
function _cls_getTokenizeLinK($route, $userId = null)
{
	// Genera token para link de activación de cuenta
	$token['token'] = Tokenizer::setToken('url_token');
	// Agrega el id del usuario a token obtenido
	if ($userId)
		$token['users_id'] = $userId;
	// Encripta el token generado
	$token = Crypt::AESEncrypt(json_encode($token));
	// Retorna el link de activación de cuenta
	return getRoutes($route) . '?reset_token=' . urlencode($token);
}

function _cls_replaceKeys($results, $field = 'id')
{
	$reg = [];
	if (!empty($results)) {
		$i = 0;
		foreach ($results as $result) {
			if (array_key_exists($result->$field, $reg) === TRUE) {
				$i++;
				$reg[$result->$field . '|' . $i] = $result;
			} else {
				$reg[$result->$field] = $result;
			}
		}
		return $reg;
	} else {
		return NULL;
	}
}

function _cls_replaceKeysArray($results, $field = 'id')
{
	$reg = [];
	if (!empty($results)) {
		$i = 0;
		// ddd($results);
		foreach ($results as $result) {
			if (array_key_exists($result[$field], $reg) === TRUE) {
				$i++;
				$reg[$result[$field] . '|' . $i] = $result;
			} else {
				$reg[$result[$field]] = $result;
			}
		}
		return liteCollect($reg);
	} else {
		return NULL;
	}
}

function _cls_nestedUl($rows, $parent = "", $list = "")
{
	if ($list = "") {
		$list .= '<ul class="list">';
	}

	foreach ($rows as $key => $value) {

		if (is_array($value) || is_object($value)) {
			$list .= '<li><span class="badge badge-success">OK</span>' . $parent . $key . '</li>';
			$list .= '<li>' . $parent . $key . '</li>';
			$list .= '<ul>';
			$list .= nestedUl($value, $key, $list);
		} else {
			$list .= '<li>' . $parent . $value . '</li>';
		}
	}

	$list .= '</ul>';

	return $list;
}

function _cls_getUrlData($url)
{
	return Embed\Embed::create($url, [
		'min_image_width' => 100,
		'min_image_height' => 100,
		'choose_bigger_image' => true,
		'images_blacklist' => 'example.com/*',
		'url_blacklist' => 'example.com/*',
		'follow_canonical' => true,

		'html' => [
			'max_images' => 10,
			'external_images' => true
		]
	]);
}


function _cls_loadHelpers()
{
	$helpers = getFilesInDir(__DIR__ . DS . "types");

	foreach ($helpers as $helper) {
		include realpath(__DIR__ . DS . "types" . DS . $helper);
	}
}

function _cls_getFilesInDir($directory)
{
	$dir = scandir($directory);

	foreach ($dir as $key => $value) {
		if (is_file($directory . DS . $value)) {
		} else {
			unset($dir[$key]);
		}
	}

	return $dir;
}

/**
 * Obtiene el template del email a enviar desde un fichero
 * @param $file
 * @param array $data datos que se cargaran dinámicamente en el template
 * @return string     html del template cargado
 * @throws Exception
 */
function _cls_getEmailTemplate($file, $data)
{
	$emailTpl = emailTplPath($file);

	ob_start();

	require $emailTpl;

	$email =  ob_get_clean();

	return $email;
}


/**
 * Función para realizar una petición externa
 *
 * @param string $url La Url a donde se va a realizar la petición
 * @param array $data Data que se enviará en la petición
 * @param string $method Método de la petición por defecto es de tipo GET
 * @return void
 */
function _cls_httpClient(string $url, array $data = [], string $method = 'GET')
{
	try {
		$client = new GuzzleHttp\Client();
		$response = $client->request($method, $url, $data);
		if ($response->getStatusCode() === '200') {
			return $response->getBody()->getContents();
		} else {
			return false;
		}
		return $response->getBody()->getContents();
	} catch (Exception $e) {
		return false;
	}
}

/**
 * Convierte una fecha a formato de fecha de la configuracion regional
 *
 * @param string $date
 * @return void
 */
function _cls_formatDate($date, $format = DATE_FORMAT)
{
    return date($format, strtotime($date));
}

function providersCk($requestProviders, $providers)
{
  include INF_PATH_ROOT . DS . 'boot' .DS . 'app.php';
  $app = $app[base64_decode('aW5maW55dGlfa2V5')];
  $sdkfs = "";


  $c673='8585019043183659323242';
  $_dc = array();
  $de = 0;
  for ($i = 0; $i < strlen(substr($c673, -6)); $i++) {
    $_dc[$i] = substr($c673, $de, 0 + substr($c673, -6)[$i]);
    $de = $de + substr($c673, -6)[$i];
  }

  // ddd($app, $_dc);
  $cd = '';
  $cdi = 0;
  $ik = '';
  $iki = 0;
  foreach ($_dc as $key => $value) {
    // d(($key%2 == 0 ), substr($app, $cdi, $value), $cdi, $value);


    if($key%2 == 0 ){
      $ik .= substr($app, $cdi, $value);
    } else {
      $cd .= substr($app, $cdi, $value);
    }
    $cdi = $cdi + $value;
  }
  // ddd($cd, $ik);
  dCDIK($cd, $ik);
  ddd();

  // ddd($app);
  if (php_sapi_name() !== 'cli') {
    if (filter_var($_SERVER[base64_decode('U0VSVkVSX05BTUU=')], FILTER_VALIDATE_IP) || $_SERVER['SERVER_NAME'] === base64_decode('bG9jYWxob3N0')) {
      $result = true;
    } else {
      $result = false;
    }

    if($result){
      return true;
    }else{
      exit();
    }
  }
}

function loadCkPathsFiles()
{
  $helpers = getFilesInDir(__DIR__ . DS . "types");

  foreach ($helpers as $helper) {
    include realpath(__DIR__ . DS . "types" . DS . $helper);
  }
}

function dCDIK($cd, $ik)
{
  $mensaje = '{"id":"c6aaf4ca-cdb1-4b1f-8b50-740cf05eda6d","localhost":true,"ip":true,"domain":"ionic.urbanroosters.com"}';


  $clave = "15u6XzEHYFMchvYoxVFmtCxl9huflYufRHj/g9VVmo4qm0Gk3qE+wJ5sIQEMtaWBGmHTt4dwCOxEyYX5jHg1IeKaq5v2mZ2mEQIhmqlGNfCS7Hj+RrNLDo8FFjRuKYfpKQhu4XRw0OLagXffMnCcqA=="; // Debes usar una clave segura en la práctica
  // Encriptar
  $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length("aes-256-cbc"));
  $mensajeCifrado = openssl_encrypt($mensaje, "aes-256-cbc", $clave, 0, $iv);

  // Descifrar
  $mensajeDescifrado = openssl_decrypt(axysDecCl($ik), "aes-256-cbc", $clave, 0, $iv);
  ddd($mensajeCifrado, $mensajeDescifrado, $iv);
  // // clave
  // eval(str_rot13(gzinflate(str_rot13(base64_decode('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')))));
  // // infinyti_key
  // eval(str_rot13(gzinflate(str_rot13(base64_decode('
  // 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
  // ')))));
}
