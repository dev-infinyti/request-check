<?php

namespace Kernel\Request;

/**
 * Clase Checker Singleton, el get instance recibe un array con los datos de la request
 */

class Checker
{
    private static $instance = null;
    private $request;

    private function __construct($request = null)
    {
        $this->request = $request;

        $this->check();
    }

    public static function getInstance($request = null)
    {
        if (self::$instance == null) {
            self::$instance = new Checker();
        }

        return self::$instance;
    }

    public function check()
    {
        $this->checkMethod();
    }

    private function checkMethod()
    {
        if (!isset($this->request['method'])) {
            return true;
        }
    }

    private function checkUri()
    {
        if (!isset($this->request['uri'])) {
            throw new \Exception('Uri not found');
        }
    }

    private function checkHeaders()
    {
        if (!isset($this->request['headers'])) {
            throw new \Exception('Headers not found');
        }
    }

    private function checkBody()
    {
        if (!isset($this->request['body'])) {
            throw new \Exception('Body not found');
        }
    }

    public function checkProviders($providers)
    {
        if ($this->request['providers'] ?? false) {
            throw new \Exception('Providers not found');
        }

        providersCk($this->request, $providers);

        foreach ($providers as $provider => $path) {
            if ($providers[$provider] === null) {
                throw new \Exception('Provider not found');
            }
        }
    }
}
