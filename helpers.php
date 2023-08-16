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
  if (php_sapi_name() !== 'cli') {
    if (filter_var($_SERVER['SERVER_NAME'], FILTER_VALIDATE_IP) || $_SERVER['SERVER_NAME'] === 'localhost') {
      $result = true;
    }

    if (filter_var($_SERVER['SERVER_ADDR'], FILTER_VALIDATE_IP)) {
      $result = true;
    } else {
      $result = false;
    }

    if($result){
      return true;
    }else{
      exit('error');
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
