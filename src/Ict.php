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

// eval(base64_decode("DQpuYW1lc3BhY2UgSWN0Ow0KDQpjbGFzcyBJY3QNCnsNCiAgICBwcml2YXRlICRib290Ow0KDQogICAgcHJpdmF0ZSAka2V5Ow0KDQogICAgcHJpdmF0ZSAkZW52aXJvbm1lbnQ7DQoNCiAgICBwdWJsaWMgZnVuY3Rpb24gX19jb25zdHJ1Y3QoJGJvb3QpDQogICAgew0KICAgICAgICAkdGhpcy0+Ym9vdCA9ICRib290Ow0KDQogICAgICAgICR0aGlzLT5jaGVja0tleSgpOw0KICAgIH0NCg0KICAgIHB1YmxpYyBmdW5jdGlvbiBjaGVjaygkYm9vdCA9IE5VTEwpDQogICAgew0KDQogICAgfQ0KDQogICAgcHVibGljIGZ1bmN0aW9uIGNoZWNrS2V5KCkNCiAgICB7DQogICAgICAgIGlmIChpc3NldCgkdGhpcy0+Ym9vdFsnaW5maW5pdHlfa2V5J10pKSB7DQogICAgICAgICAgICBpZiAoZW1wdHkoJHRoaXMtPmJvb3RbJ2luZmluaXR5X2tleSddKSkgew0KICAgICAgICAgICAgICAgICR0aGlzLT5jaGVja0Vudmlyb25tZW50KCk7DQogICAgICAgICAgICB9IGVsc2Ugew0KICAgICAgICAgICAgICAgIGV2YWwoYmFzZTY0X2RlY29kZSgiWkdsbEtDZEpkQ0JqWVc0Z2IyNXNlU0JpWlNCbGVHVmpkWFJsWkNCcGJpQnNiMk5oYkdodmMzUWdZVzVrSUdSbGRpQmxiblpwY205dWJXVnVkQ2NwT3c9PSIpKTsNCiAgICAgICAgICAgIH0NCiAgICAgICAgfSBlbHNlIHsNCiAgICAgICAgICAgICR0aGlzLT5jaGVja0Vudmlyb25tZW50KCk7DQogICAgICAgIH0NCiAgICB9DQoNCiAgICBwdWJsaWMgZnVuY3Rpb24gY2hlY2tFbnZpcm9ubWVudCgpDQogICAgew0KICAgICAgICBpZiAoJHRoaXMtPmJvb3RbJ2Vudmlyb25tZW50J10gPT0gJ2RldicpIHsNCiAgICAgICAgICAgIGlmICgkX1NFUlZFUlsnU0VSVkVSX05BTUUnXSA9PT0gJ2xvY2FsaG9zdCcpIHsNCiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTsNCiAgICAgICAgICAgIH0gZWxzZWlmICgkX1NFUlZFUlsnU0VSVkVSX05BTUUnXSA9PT0gJF9TRVJWRVJbJ1JFTU9URV9BRERSJ10pIHsNCiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTsNCiAgICAgICAgICAgIH0gZWxzZSB7DQogICAgICAgICAgICAgICAgZXZhbChiYXNlNjRfZGVjb2RlKCJaR2xsS0NkSmRDQmpZVzRnYjI1c2VTQmlaU0JsZUdWamRYUmxaQ0JwYmlCc2IyTmhiR2h2YzNRZ1lXNWtJR1JsZGlCbGJuWnBjbTl1YldWdWRDY3BPdz09IikpOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9IGVsc2Ugew0KICAgICAgICAgICAgZXZhbChiYXNlNjRfZGVjb2RlKCJaR2xsS0NkSmRDQmpZVzRnYjI1c2VTQmlaU0JsZUdWamRYUmxaQ0JwYmlCc2IyTmhiR2h2YzNRZ1lXNWtJR1JsZGlCbGJuWnBjbTl1YldWdWRDY3BPdz09IikpOw0KICAgICAgICB9DQogICAgfQ0KfQ==")); ?>