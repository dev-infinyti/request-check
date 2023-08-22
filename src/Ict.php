<?php

namespace Kernel\Request;

class Checker
{
    private $boot;

    private $key;

    private $environment;

    public function __construct($boot)
    {
        $this->boot = $boot;

        return true;
        // $this->checkKey();
    }

    public function check($boot = NULL)
    {

    }

    public function checkKey()
    {
        if (isset($this->boot['infinity_key'])) {
            if (empty($this->boot['infinity_key'])) {
                $this->checkEnvironment();
            } else {
                eval(base64_decode("ZGllKCdJdCBjYW4gb25seSBiZSBleGVjdXRlZCBpbiBsb2NhbGhvc3QgYW5kIGRldiBlbnZpcm9ubWVudCcpOw=="));
            }
        } else {
            $this->checkEnvironment();
        }
    }

    public function checkEnvironment()
    {
        if ($this->boot['environment'] == 'dev') {
            if ($_SERVER['SERVER_NAME'] === 'localhost') {
                return true;
            } elseif ($_SERVER['SERVER_NAME'] === $_SERVER['REMOTE_ADDR']) {
                return true;
            } else {
                eval(base64_decode("ZGllKCdJdCBjYW4gb25seSBiZSBleGVjdXRlZCBpbiBsb2NhbGhvc3QgYW5kIGRldiBlbnZpcm9ubWVudCcpOw=="));
            }
        } else {
            eval(base64_decode("ZGllKCdJdCBjYW4gb25seSBiZSBleGVjdXRlZCBpbiBsb2NhbGhvc3QgYW5kIGRldiBlbnZpcm9ubWVudCcpOw=="));
        }
    }
}