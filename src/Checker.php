<?php

namespace Kernel\Request;

/**
 * Clase Checker Singleton, el get instance recibe un array con los datos de la request
 */

class Checker
{
    private static $instance = null;
    private $request;

    private function __construct($request)
    {
        $this->request = $request;
    }

    public static function getInstance($request)
    {

        if (self::$instance == null) {
            self::$instance = new Checker($request);
        }
        return self::$instance;
    }

    public function check()
    {
        $this->checkMethod();
        $this->checkUri();
        $this->checkHeaders();
        $this->checkBody();
    }

    private function checkMethod()
    {
        if (!isset($this->request['method'])) {
            throw new \Exception('Method not found');
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
}